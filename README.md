# GuardShell

**A Security-Aware Linux Shell with Risk-Based Execution, Resource Governance, and KernelGuard-Inspired Process Isolation**

Built in C as an Operating Systems + Cybersecurity project.

---

## What It Does

GuardShell is a Linux shell that analyzes every command before executing it. It combines a rule-based risk engine, configurable security policies, kernel-enforced isolation, and comprehensive audit logging — all in one shell workflow.

---

## Features

- **Real shell:** pipes, redirection, background jobs, built-ins
- **Risk engine:** rule-based scoring (0-100) with explainable reasons
- **Policy engine:** configurable profiles (safe / restricted / development)
- **Warning system:** interactive Y/N confirmation for high-risk commands
- **Kernel-enforced isolation:**
  - `seccomp-BPF` — syscall filtering
  - `Landlock` — filesystem sandboxing (write-only to /tmp)
  - `no_new_privs` — privilege escalation prevention
  - `setrlimit` — memory / CPU / process limits
  - `cgroups v2` — resource accounting (with rlimit fallback)
- **Audit logging:** every decision recorded to `~/.guardshell_audit.log`
- **Attack simulations:** safe, controlled tests of defense layers

---

## Quick Start

```bash
# Build
gcc -Wall -Wextra -O2 -o guardshell guardshell.c

# Run with default policy (safe)
./guardshell

# Run with strict policy
GUARDSHELL_POLICY=restricted ./guardshell
```

---

## Try It

```bash
guardshell$ ls -la
guardshell$ ls | head -3
guardshell$ echo hello > /tmp/x.txt
guardshell$ cat /tmp/x.txt

guardshell$ guard risk sudo rm -rf /     # Score: 100/100 CRITICAL
guardshell$ guard status                  # Security dashboard
guardshell$ guard attack restricted-syscall
guardshell$ rm -rf /tmp/nonexistent       # Y/N warning
guardshell$ sudo rm -rf /                 # BLOCKED
guardshell$ exit
```

---

## Guard Commands

| Command | Purpose |
|---------|---------|
| `guard risk <cmd>` | Analyze without executing |
| `guard policy` | Show active policy |
| `guard status` | Security center dashboard |
| `guard attack <type>` | Safe attack simulation |
| `guard run [opts] <cmd>` | Guarded execution with limits |

**Attack types:**
- `restricted-syscall` — seccomp-BPF blocks `ptrace`
- `privilege-escalation` — `no_new_privs` blocks `setuid(0)`
- `unauthorized-read` — POSIX DAC blocks `/etc/shadow` access

---

## Test Suite

```bash
./test_all.sh
# Tests passed: 17
# Tests failed: 0
```

---

## Architecture

```
User Input → Parser → Risk Engine → Policy Engine
                                        ↓
                              ALLOW / CONFIRM / BLOCK
                                        ↓
                              Isolation Manager
                              ├── no_new_privs
                              ├── seccomp-BPF
                              ├── Landlock
                              └── setrlimit / cgroups
                                        ↓
                                 fork() + execvp()
                                        ↓
                                  Audit Log
```

---

## Limitations

- Sequential `;` not supported (only `|`, `&`, redirection)
- No tab completion or arrow-key history
- Landlock requires kernel ≥ 5.13 (graceful fallback otherwise)
- cgroups v2 writable permission varies by environment
- Not a kernel replacement — uses existing Linux primitives

---

## Honesty Statement

GuardShell is a **userspace** shell. It does not modify or replace the Linux kernel. It composes existing kernel security primitives (seccomp, Landlock, rlimits, no_new_privs) into a coherent layer.

"KernelGuard" is a conceptual model inspired by microkernel principles — not an implementation of seL4 or any microkernel.

---

## Author

Kanha Mahajan  
GitHub: [@KanhaMahajan](https://github.com/KanhaMahajan)

---

## License

Educational use. See repository for details.
