#!/usr/bin/env bash
BIN=./guardshell
PASS=0
FAIL=0

t() {
    local desc="$1"; local cmd="$2"; local expect="$3"
    local out
    out=$(printf "%s\nexit\n" "$cmd" | $BIN 2>&1)
    if echo "$out" | grep -q "$expect"; then
        echo "  PASS  $desc"; PASS=$((PASS+1))
    else
        echo "  FAIL  $desc"
        echo "        expected: $expect"
        echo "        got: $(echo "$out" | tr '\n' ' ' | cut -c1-120)"
        FAIL=$((FAIL+1))
    fi
}

echo "=== Basic commands ==="
t "whoami"           "whoami"           "hpkanha"
t "date"             "date"             "2026"
t "echo"             "echo hello"       "hello"
t "pwd"              "pwd"              "/home"

echo "=== File operations ==="
t "touch + write"    "touch /tmp/gst.txt" "guardshell"
t "cat file"         "cat /tmp/gst.txt"  ""

echo "=== Pipes ==="
t "pipe ls|wc"       "ls /etc | wc -l"   "[0-9]"
t "pipe grep"        "echo apple | grep app" "apple"

echo "=== Redirection ==="
t "output redirect"  "echo test > /tmp/gso.txt"  "guardshell"
t "read redirect"    "cat < /tmp/gso.txt"        "test"

echo "=== Builtins ==="
t "help"             "help"                 "Builtins"
t "cd + pwd"         "pwd"                  "/home"

echo "=== Security ==="
t "risk low"         "guard risk ls"        "LOW"
t "risk high"        "guard risk sudo rm -rf /"  "CRITICAL"
t "status"           "guard status"         "PROTECTED"
t "attack syscall"   "guard attack restricted-syscall"  "BLOCKED"
t "attack privesc"   "guard attack privilege-escalation" "BLOCKED"

echo
echo "================================"
echo "Tests passed: $PASS"
echo "Tests failed: $FAIL"
echo "================================"
