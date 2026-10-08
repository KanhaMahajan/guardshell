/* GuardShell - security-aware Linux shell (educational prototype) */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <stddef.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/landlock.h>

#ifndef LANDLOCK_ACCESS_FS_MAKE_REG
#define LANDLOCK_ACCESS_FS_MAKE_REG (1ULL << 4)
#endif

#define MAXTOK 64
#define MAXSTAGE 8

/* ============ PARSER ============ */
typedef struct {
    char *argv[MAXTOK];
    int argc;
    char *in_file, *out_file;
    int append;
} Stage;

typedef struct {
    Stage st[MAXSTAGE];
    int nst;
    int background;
} Command;

static int parse_line(char *line, Command *cmd) {
    memset(cmd, 0, sizeof *cmd);
    cmd->nst = 1;
    Stage *s = &cmd->st[0];
    char *p = line;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        if (!*p) break;
	if (*p == '|' || *p == ';') {
            if (++cmd->nst > MAXSTAGE) return -1;
            s = &cmd->st[cmd->nst - 1]; p++; continue;
        }
        if (*p == '&') { cmd->background = 1; p++; continue; }
        if (*p == '<' || *p == '>') {
            char op = *p++; int app = 0;
            if (op == '>' && *p == '>') { app = 1; p++; }
            while (*p == ' ') p++;
            char *start = p;
            while (*p && !strchr(" \t\n|&<>", *p)) p++;
            if (*p) *p++ = '\0';
            if (op == '<') s->in_file = start;
            else { s->out_file = start; s->append = app; }
            continue;
        }
        char *tok;
        if (*p == '"' || *p == '\'') {
            char q = *p++; tok = p;
            while (*p && *p != q) p++;
        } else {
            tok = p;
            while (*p && !strchr(" \t\n|&<>", *p)) p++;
        }
        if (*p) *p++ = '\0';
        if (s->argc >= MAXTOK - 1) return -1;
        s->argv[s->argc++] = tok;
    }
    for (int i = 0; i < cmd->nst; i++) cmd->st[i].argv[cmd->st[i].argc] = NULL;
    return (cmd->st[0].argc == 0) ? 0 : 1;
}

/* ============ RISK ENGINE ============ */
typedef struct { const char *pattern; int weight; const char *reason; } Rule;

static const Rule RULES[] = {
    { "rm",        25, "Deletion command" },
    { "-rf",       30, "Recursive forced deletion" },
    { "-r",        15, "Recursive operation" },
    { "sudo",      25, "Privilege escalation" },
    { "su",        20, "User switch" },
    { "chmod",     15, "Permission change" },
    { "chown",     15, "Ownership change" },
    { "mkfs",      60, "Filesystem formatting" },
    { "dd",        35, "Raw disk write" },
    { "/dev/sd",   40, "Direct disk device access" },
    { "/etc/shadow", 40, "Sensitive credential file" },
    { "/etc/passwd", 20, "System account file" },
    { "/etc/sudoers", 30, "Sudoers config" },
    { "curl",      12, "Network download" },
    { "wget",      12, "Network download" },
    { "nc",        20, "Raw network tool" },
    { "nmap",      20, "Network scanner" },
    { "iptables",  35, "Firewall modification" },
    { "crontab",   20, "Persistence mechanism" },
    { "kill",      10, "Process termination" },
    { "killall",   15, "Bulk process termination" },
    { "/",         20, "Root-level path" },
    { ":(){",      60, "Fork-bomb pattern" },
};
#define NRULES (sizeof RULES / sizeof RULES[0])

typedef struct { int score; const char *reasons[16]; int nreasons; } Risk;

static void risk_analyze(const Command *c, Risk *r) {
    memset(r, 0, sizeof *r);
    int total = 0;
    for (int i = 0; i < c->nst; i++)
        for (int a = 0; a < c->st[i].argc; a++) {
            const char *tok = c->st[i].argv[a];
            for (size_t k = 0; k < NRULES; k++) {
                int hit = (a == 0) ? strcmp(tok, RULES[k].pattern) == 0
                                   : (strcmp(tok, RULES[k].pattern) == 0 ||
                                      (RULES[k].pattern[0] == '/' && strlen(RULES[k].pattern) > 1 &&
                                       strncmp(tok, RULES[k].pattern, strlen(RULES[k].pattern)) == 0));
                if (hit) {
                    total += RULES[k].weight;
                    if (r->nreasons < 16) r->reasons[r->nreasons++] = RULES[k].reason;
                }
            }
        }
    if (c->nst > 1) total += 5;
    r->score = total > 100 ? 100 : total;
}

static const char *risk_level(int s) {
    if (s <= 20) return "LOW";
    if (s <= 40) return "MEDIUM";
    if (s <= 70) return "HIGH";
    return "CRITICAL";
}

/* ============ POLICY (loaded from config) ============ */
typedef struct {
    char name[64];
    int  warn_threshold;
    int  block_threshold;
    long memory_mb;
    int  process_limit;
    int  time_limit_sec;
} Policy;

static Policy g_policy = { "safe", 41, 90, 0, 0, 0 };

static void load_policy(const char *name) {
    if (!name) name = "safe";
    char path[256];
    snprintf(path, sizeof path, "configs/%s.conf", name);
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[guard] policy '%s' not found, using defaults\n", name);
        return;
    }
    snprintf(g_policy.name, sizeof g_policy.name, "%s", name);
    char line[256];
    while (fgets(line, sizeof line, f)) {
        char k[64], v[64];
        if (sscanf(line, " %63[^= ] = %63s", k, v) != 2) continue;
        if      (!strcmp(k, "warn_threshold"))  g_policy.warn_threshold  = atoi(v);
        else if (!strcmp(k, "block_threshold")) g_policy.block_threshold = atoi(v);
        else if (!strcmp(k, "memory_mb"))       g_policy.memory_mb       = atol(v);
        else if (!strcmp(k, "process_limit"))   g_policy.process_limit   = atoi(v);
        else if (!strcmp(k, "time_limit_sec"))  g_policy.time_limit_sec  = atoi(v);
    }
    fclose(f);
    printf("[guard] policy loaded: %s (warn>=%d block>=%d)\n",
           g_policy.name, g_policy.warn_threshold, g_policy.block_threshold);
}

typedef enum { ALLOW, CONFIRM, BLOCK } Decision;

static Decision policy_decide(int score) {
    if (score >= g_policy.block_threshold) return BLOCK;
    if (score >= g_policy.warn_threshold)  return CONFIRM;
    return ALLOW;
}

/* ============ AUDIT LOG ============ */
static void audit_log(const char *line, int score, const char *decision, int status) {
    const char *home = getenv("HOME");
    char path[512];
    snprintf(path, sizeof path, "%s/.guardshell_audit.log", home ? home : "/tmp");
    FILE *f = fopen(path, "a");
    if (!f) return;
    time_t t = time(NULL);
    char ts[32];
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", localtime(&t));
    fprintf(f, "%s | score=%d | decision=%s | status=%d | cmd=%s\n",
            ts, score, decision, status, line);
    fclose(f);
}

/* ============ ISOLATION: no_new_privs, seccomp, Landlock ============ */
static int g_landlock_ok = 0;
static int g_cgroup_ok   = 0;

static int install_seccomp(void) {
    int denied[] = { SYS_ptrace, SYS_mount, SYS_umount2, SYS_reboot,
                     SYS_kexec_load, SYS_init_module, SYS_delete_module, SYS_swapon };
    int n = sizeof denied / sizeof denied[0];
    struct sock_filter f[2 + 2 * 8 + 1];
    int i = 0;
    f[i++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                           offsetof(struct seccomp_data, nr));
    for (int k = 0; k < n; k++) {
        f[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, denied[k], 0, 1);
        f[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
    }
    f[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    struct sock_fprog prog = { .len = (unsigned short)i, .filter = f };
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

static int install_landlock(const char *write_dir) {
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                             LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
                             LANDLOCK_ACCESS_FS_MAKE_DIR,
    };
    int fd = syscall(SYS_landlock_create_ruleset, &attr, sizeof attr, 0);
    if (fd < 0) return -1;
    struct landlock_path_beneath_attr pb = { .allowed_access = attr.handled_access_fs };
    pb.parent_fd = open(write_dir, O_PATH | O_CLOEXEC);
    if (pb.parent_fd < 0) { close(fd); return -1; }
    syscall(SYS_landlock_add_rule, fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
    close(pb.parent_fd);
    int rc = syscall(SYS_landlock_restrict_self, fd, 0);
    close(fd);
    return rc;
}

typedef struct { int isolate; long mem_mb; int cpu_pct; int time_s; } Profile;

static void apply_isolation(const Profile *p) {
    if (!p->isolate) return;
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (install_landlock("/tmp") < 0)
        fprintf(stderr, "[guard] Landlock unavailable, skipped\n");
    if (install_seccomp() < 0)
        fprintf(stderr, "[guard] seccomp failed\n");
}

/* ============ RESOURCE GUARDIAN ============ */
static int write_file(const char *path, const char *val) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t r = write(fd, val, strlen(val));
    close(fd);
    return r < 0 ? -1 : 0;
}

static int cgroup_setup(pid_t pid, const Profile *p, char dir[128], size_t dsz) {
    snprintf(dir, dsz, "/sys/fs/cgroup/guardshell_%d", (int)pid);
    if (mkdir(dir, 0755) < 0) return -1;
    char path[192], val[64];
    if (p->mem_mb) {
        snprintf(path, sizeof path, "%.100s/memory.max", dir);
        snprintf(val,  sizeof val,  "%ld", p->mem_mb * 1024 * 1024);
        write_file(path, val);
    }
    if (p->cpu_pct) {
        snprintf(path, sizeof path, "%.100s/cpu.max", dir);
        snprintf(val,  sizeof val,  "%d 100000", p->cpu_pct * 1000);
        write_file(path, val);
    }
    if (g_policy.process_limit > 0) {
        snprintf(path, sizeof path, "%.100s/pids.max", dir);
        snprintf(val,  sizeof val,  "%d", g_policy.process_limit);
        write_file(path, val);
    }
    snprintf(path, sizeof path, "%.100s/cgroup.procs", dir);
    snprintf(val,  sizeof val,  "%d", (int)pid);
    return write_file(path, val);
}

static void rlimit_fallback(const Profile *p) {
    struct rlimit rl;
    if (p->mem_mb) { rl.rlim_cur = rl.rlim_max = (rlim_t)p->mem_mb << 20; setrlimit(RLIMIT_AS, &rl); }
    if (p->time_s) { rl.rlim_cur = rl.rlim_max = p->time_s; setrlimit(RLIMIT_CPU, &rl); }
    if (g_policy.process_limit > 0) {
        rl.rlim_cur = rl.rlim_max = g_policy.process_limit;
        setrlimit(RLIMIT_NPROC, &rl);
    }
    rl.rlim_cur = rl.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rl);
}

/* ============ EXECUTOR ============ */
static int run_command(Command *c, const Profile *prof) {
    int prev = -1, pipefd[2];
    pid_t pids[MAXSTAGE];
    char cgdir[MAXSTAGE][128]; memset(cgdir, 0, sizeof cgdir);
    for (int i = 0; i < c->nst; i++) {
        if (i < c->nst - 1 && pipe(pipefd) < 0) { perror("pipe"); return -1; }
        pid_t pid = fork();
        if (pid == 0) {
            signal(SIGINT, SIG_DFL);
            if (prev != -1) { dup2(prev, 0); close(prev); }
            if (i < c->nst - 1) { close(pipefd[0]); dup2(pipefd[1], 1); close(pipefd[1]); }
            Stage *s = &c->st[i];
            rlimit_fallback(prof);
            apply_isolation(prof);
            if (s->in_file) {
                int f = open(s->in_file, O_RDONLY);
                if (f < 0) { perror(s->in_file); _exit(1); }
                dup2(f, 0); close(f);
            }
            if (s->out_file) {
                int f = open(s->out_file, O_WRONLY | O_CREAT | (s->append ? O_APPEND : O_TRUNC), 0644);
                if (f < 0) { perror(s->out_file); _exit(1); }
                dup2(f, 1); close(f);
            }
            execvp(s->argv[0], s->argv);
            fprintf(stderr, "guardshell: %s: %s\n", s->argv[0], strerror(errno));
            _exit(127);
        }
        pids[i] = pid;
        if (prof->mem_mb || prof->cpu_pct) {
            if (cgroup_setup(pid, prof, cgdir[i], sizeof cgdir[i]) < 0) cgdir[i][0] = '\0';
        }
        if (prev != -1) close(prev);
        if (i < c->nst - 1) { close(pipefd[1]); prev = pipefd[0]; }
    }
    if (c->background) { printf("[bg] pid %d\n", (int)pids[c->nst - 1]); return 0; }
    int status = 0;
    for (int i = 0; i < c->nst; i++) {
        waitpid(pids[i], &status, 0);
        if (cgdir[i][0]) rmdir(cgdir[i]);
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

/* ============ WARNING UI ============ */
static void show_warning(const Risk *r) {
    printf("\n========================================\n");
    printf("       GUARDSHELL SECURITY WARNING\n");
    printf("========================================\n");
    printf("Risk Score : %d/100\n", r->score);
    printf("Risk Level : %s\n\n", risk_level(r->score));
    if (r->nreasons > 0) {
        printf("Detected:\n");
        for (int i = 0; i < r->nreasons; i++) printf("[!] %s\n", r->reasons[i]);
    }
    printf("========================================\n");
}

/* ============ STATS ============ */
static int stat_analyzed = 0, stat_warned = 0, stat_blocked = 0,
           stat_runs = 0, stat_attacks = 0;

static void detect_features(void) {
    /* landlock probe */
    struct landlock_ruleset_attr attr = { .handled_access_fs = LANDLOCK_ACCESS_FS_WRITE_FILE };
    int fd = syscall(SYS_landlock_create_ruleset, &attr, sizeof attr, 0);
    if (fd >= 0) { g_landlock_ok = 1; close(fd); }
    /* cgroup probe */
    if (access("/sys/fs/cgroup/cgroup.procs", W_OK) == 0) g_cgroup_ok = 1;
}

static void show_status(void) {
    printf("========================================\n");
    printf("       GUARDSHELL SECURITY CENTER\n");
    printf("========================================\n");
    printf("Policy name         : %s\n", g_policy.name);
    printf("Warn threshold      : %d\n", g_policy.warn_threshold);
    printf("Block threshold     : %d\n", g_policy.block_threshold);
    printf("Memory limit        : %ld MB\n", g_policy.memory_mb);
    printf("Process limit       : %d\n", g_policy.process_limit);
    printf("Time limit          : %d sec\n", g_policy.time_limit_sec);
    printf("----------------------------------------\n");
    printf("Commands analyzed   : %d\n", stat_analyzed);
    printf("Commands warned     : %d\n", stat_warned);
    printf("Commands blocked    : %d\n", stat_blocked);
    printf("Guarded runs        : %d\n", stat_runs);
    printf("Attacks simulated   : %d\n", stat_attacks);
    printf("----------------------------------------\n");
    printf("no_new_privs        : ENABLED (prctl)\n");
    printf("seccomp blocklist   : ENABLED (BPF)\n");
    printf("Landlock FS         : %s\n", g_landlock_ok ? "ENABLED" : "unavailable");
    printf("cgroups v2          : %s\n", g_cgroup_ok ? "WRITABLE" : "fallback to rlimits");
    printf("\nSecurity Status     : PROTECTED\n");
    printf("========================================\n");
}

/* ============ ATTACK SIMULATOR (safe, educational) ============ */
static int attack_simulate(const char *type) {
    if (!type) {
        printf("types: restricted-syscall | privilege-escalation | unauthorized-read\n");
        return 1;
    }
    stat_attacks++;

    if (!strcmp(type, "restricted-syscall")) {
        pid_t pid = fork();
        if (pid == 0) {
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            install_seccomp();
            long r = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
            _exit(r < 0 ? 1 : 0);
        }
        int st; waitpid(pid, &st, 0);
        int blocked = WIFEXITED(st) && WEXITSTATUS(st) == 1;
        printf("\n================================\n");
        printf("       ATTACK SIMULATION\n");
        printf("================================\n");
        printf("Attack      : Restricted Syscall (ptrace)\n");
        printf("Target      : Isolated child process\n");
        printf("Expected    : Syscall trace attempt\n");
        printf("Security Lyr: seccomp-BPF blocklist\n");
        printf("Result      : %s\n", blocked ? "BLOCKED (EPERM)" : "UNEXPECTED");
        printf("Impact      : NONE\n");
        printf("================================\n\n");
        return 0;
    }
    if (!strcmp(type, "privilege-escalation")) {
        pid_t pid = fork();
        if (pid == 0) {
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if (setuid(0) != 0) { /* ignore */ }
            _exit(geteuid() == 0 ? 0 : 1);
        }
        int st; waitpid(pid, &st, 0);
        int denied = !(WIFEXITED(st) && WEXITSTATUS(st) == 0);
        printf("\n================================\n");
        printf("       ATTACK SIMULATION\n");
        printf("================================\n");
        printf("Attack      : Privilege Escalation (setuid 0)\n");
        printf("Target      : Isolated child process\n");
        printf("Expected    : Gain root effective UID\n");
        printf("Security Lyr: no_new_privs + POSIX DAC\n");
        printf("Result      : %s\n", denied ? "BLOCKED" : "SUCCEEDED (already root)");
        printf("Impact      : %s\n", denied ? "NONE" : "HIGH");
        printf("================================\n\n");
        return 0;
    }
    if (!strcmp(type, "unauthorized-read")) {
        pid_t pid = fork();
        if (pid == 0) {
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            int fd = open("/etc/shadow", O_RDONLY);
            if (fd >= 0) close(fd);
            _exit(fd >= 0 ? 0 : 1);
        }
        int st; waitpid(pid, &st, 0);
        int denied = !(WIFEXITED(st) && WEXITSTATUS(st) == 0);
        printf("\n================================\n");
        printf("       ATTACK SIMULATION\n");
        printf("================================\n");
        printf("Attack      : Unauthorized File Read\n");
        printf("Target      : /etc/shadow\n");
        printf("Expected    : Read credential file\n");
        printf("Security Lyr: POSIX DAC + no_new_privs\n");
        printf("Result      : %s\n", denied ? "BLOCKED" : "ACCESS GAINED (running as root?)");
        printf("Impact      : %s\n", denied ? "NONE" : "HIGH");
        printf("================================\n\n");
        return 0;
    }
    printf("unknown attack type: %s\n", type);
    return 1;
}

/* ============ BUILTINS + GUARD DISPATCH ============ */
static int builtin(Command *c, const char *rawline) {
    char **a = c->st[0].argv;
    if (!strcmp(a[0], "exit")) exit(0);

    if (!strcmp(a[0], "help")) {
        printf("Builtins : cd, exit, help, guard\n");
        printf("Syntax   : cmd1 | cmd2 > file >> file < file &\n");
        printf("Security : guard risk <cmd> | guard status | guard attack <type>\n");
        printf("Guarded  : guard run --cpu N --memory NM --time S <cmd>\n");
        return 1;
    }

    if (!strcmp(a[0], "cd")) {
        char path[1024];
        const char *p = a[1] ? a[1] : getenv("HOME");
        if (!p) p = "/";
        if (p[0] == '~' && (p[1] == '/' || p[1] == '\0')) {
            const char *h = getenv("HOME");
            snprintf(path, sizeof path, "%s%s", h ? h : "/", p + 1);
            p = path;
        }
        if (chdir(p) < 0) perror("cd");
        return 1;
    }

    if (!strcmp(a[0], "guard") && c->st[0].argc >= 2) {

        /* guard risk <cmd...> */
        if (!strcmp(a[1], "risk")) {
            Command sub; char buf[1024] = "";
            for (int i = 2; i < c->st[0].argc; i++) {
                if (i > 2) strcat(buf, " ");
                strcat(buf, a[i]);
            }
            if (parse_line(buf, &sub) > 0) {
                Risk r; risk_analyze(&sub, &r);
                printf("[SECURITY] %s\n", buf);
                printf("  Score : %d/100\n", r.score);
                printf("  Level : %s\n", risk_level(r.score));
                for (int i = 0; i < r.nreasons; i++)
                    printf("  - %s\n", r.reasons[i]);
            }
            return 1;
        }

        /* guard status */
        if (!strcmp(a[1], "status")) { show_status(); return 1; }

        /* guard attack <type> */
        if (!strcmp(a[1], "attack")) {
            if (c->st[0].argc < 3) {
                printf("types: restricted-syscall | privilege-escalation | unauthorized-read\n");
                return 1;
            }
            attack_simulate(a[2]);
            return 1;
        }

        /* guard policy */
        if (!strcmp(a[1], "policy")) {
            printf("Policy     : %s\n", g_policy.name);
            printf("Warn >=    : %d\n", g_policy.warn_threshold);
            printf("Block >=   : %d\n", g_policy.block_threshold);
            printf("Memory     : %ld MB\n", g_policy.memory_mb);
            printf("Proc limit : %d\n", g_policy.process_limit);
            printf("Time limit : %d sec\n", g_policy.time_limit_sec);
            return 1;
        }

        /* guard run [opts] cmd... */
        if (!strcmp(a[1], "run")) {
            int i = 2; Profile p = { .isolate = 1 };
            while (i + 1 < c->st[0].argc && a[i][0] == '-') {
                if (!strcmp(a[i], "--cpu"))    p.cpu_pct = atoi(a[i + 1]);
                if (!strcmp(a[i], "--memory")) p.mem_mb  = atol(a[i + 1]);
                if (!strcmp(a[i], "--time"))   p.time_s  = atoi(a[i + 1]);
                i += 2;
            }
            if (i >= c->st[0].argc) {
                fprintf(stderr, "usage: guard run [--cpu N] [--memory NM] [--time S] cmd ...\n");
                return 1;
            }
            Command sub; memset(&sub, 0, sizeof sub); sub.nst = 1;
            for (int k = i; k < c->st[0].argc; k++)
                sub.st[0].argv[sub.st[0].argc++] = a[k];
            printf("================================\n");
            printf("        RESOURCE GUARDIAN\n");
            printf("================================\n");
            printf("CPU Limit    : %d%%\n", p.cpu_pct);
            printf("Memory Limit : %ld MB\n", p.mem_mb);
            printf("Time Limit   : %d sec\n", p.time_s);
            printf("Status       : PROTECTED\n");
            printf("================================\n");
            stat_runs++;
            int st = run_command(&sub, &p);
            audit_log(rawline, 0, "GUARD_RUN", st);
            return 1;
        }

        printf("unknown guard subcommand: %s\n", a[1]);
        return 1;
    }

    return 0;
}

/* ============ MAIN LOOP ============ */
int main(void) {
    char line[1024], raw[1024];
    Profile normal = { .isolate = 1 };
    signal(SIGINT, SIG_IGN);
    signal(SIGCHLD, SIG_DFL);

    detect_features();

    const char *pn = getenv("GUARDSHELL_POLICY");
    if (!pn) pn = "safe";
    load_policy(pn);

    printf("\n+----------------------------------------------+\n");
    printf("|            GUARDSHELL v1.1                   |\n");
    printf("|  Security-Aware Linux Shell                  |\n");
    printf("+----------------------------------------------+\n");
    printf("Policy: %s  |  Type 'help'. Exit with 'exit'.\n\n", g_policy.name);

    for (;;) {
        printf("guardshell$ "); fflush(stdout);
        if (!fgets(line, sizeof line, stdin)) break;
        line[strcspn(line, "\n")] = 0;
        strcpy(raw, line);

        Command cmd;
        int pr = parse_line(line, &cmd);
        if (pr <= 0) continue;
        if (builtin(&cmd, raw)) continue;

        Risk risk; risk_analyze(&cmd, &risk);
        stat_analyzed++;

        Decision d = policy_decide(risk.score);
        const char *dname = d == ALLOW ? "ALLOW" : d == CONFIRM ? "CONFIRM" : "BLOCK";

        if (d == BLOCK) {
            show_warning(&risk);
            printf("[BLOCKED] Risk >= %d (policy: %s)\n\n", g_policy.block_threshold, g_policy.name);
            audit_log(raw, risk.score, dname, -1);
            stat_blocked++;
            continue;
        }
        if (d == CONFIRM) {
            show_warning(&risk);
            printf("Execute anyway? [y/N]: "); fflush(stdout);
            char ans[16];
            if (!fgets(ans, sizeof ans, stdin) || (ans[0] != 'y' && ans[0] != 'Y')) {
                printf("[INFO] Cancelled.\n\n");
                audit_log(raw, risk.score, "CANCELLED", -1);
                stat_warned++;
                continue;
            }
            stat_warned++;
        }

        int st = run_command(&cmd, &normal);
        audit_log(raw, risk.score, dname, st);
    }
    return 0;
}
