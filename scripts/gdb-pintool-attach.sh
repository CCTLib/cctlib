#!/bin/bash
# Launch a Pintool under `-pause_tool`, wait for the pause message,
# attach gdb non-interactively with signal handlers set up to catch a
# SIGSEGV in tool code, dump the backtrace and register state, and exit.
#
# Companion to the debug-pintool skill (.claude/skills/debug-pintool).
# Use for reproducing a Pintool crash in CI or when you don't have
# access to two terminals.
#
# Usage:
#   scripts/gdb-pintool-attach.sh \
#       --tool clients/obj-intel64/deadspy_client.so \
#       --app  /path/to/victim \
#       [--arg <argN>]... \
#       [--out /tmp/gdb.log]        # default: /tmp/gdb-pintool.log
#       [--pause-seconds 300]       # default: 300
#       [--timeout 600]             # gdb attach timeout, default: 600
#
# Env:
#   PIN_ROOT    -- required
#
# Requires:
#   * gdb on PATH; must have cap_sys_ptrace if kernel.yama.ptrace_scope>0
#   * Tool built with -g -O0 (see build-debug-tool.sh) for readable BTs
set -u
: "${PIN_ROOT:?PIN_ROOT must be set to the Pin install root}"

TOOL=""; APP=""; APP_ARGS=(); OUT=/tmp/gdb-pintool.log
PAUSE=300; ATTACH_TO=600
while [ $# -gt 0 ]; do
    case "$1" in
        --tool) TOOL="$2"; shift 2 ;;
        --app)  APP="$2"; shift 2 ;;
        --arg)  APP_ARGS+=("$2"); shift 2 ;;
        --out)  OUT="$2"; shift 2 ;;
        --pause-seconds) PAUSE="$2"; shift 2 ;;
        --timeout) ATTACH_TO="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done
if [ -z "$TOOL" ] || [ -z "$APP" ]; then
    echo "Usage: $0 --tool <pintool.so> --app <app-binary> [--arg ...]..." >&2
    exit 2
fi
if [ ! -f "$TOOL" ]; then echo "tool not found: $TOOL" >&2; exit 2; fi
if [ ! -x "$APP" ];  then echo "app not executable: $APP" >&2; exit 2; fi

TMPDIR=$(mktemp -d /tmp/gdb-pintool.XXXXXX)
PAUSE_LOG="$TMPDIR/pause.txt"
GDB_CMDS="$TMPDIR/cmds.txt"
DONE_FLAG="$TMPDIR/done"
trap 'rm -rf "$TMPDIR"' EXIT

# Kill any previous run of the same app / pind (avoids attaching to
# the wrong process).
pkill -9 -f "pind.*$(basename "$APP")" 2>/dev/null || true
pkill -9 -f "$(basename "$APP")" 2>/dev/null || true
sleep 1

# Launch Pin. The stdout redirection lets us parse the pause message.
( "$PIN_ROOT/pin" -pause_tool "$PAUSE" -t "$TOOL" -- "$APP" "${APP_ARGS[@]}" \
      > "$PAUSE_LOG" 2>&1 ; touch "$DONE_FLAG" ) &
LAUNCH=$!

# Wait for the pause message (or Pin to fail early).
for _ in $(seq 1 30); do
    grep -q "attach to process" "$PAUSE_LOG" 2>/dev/null && break
    [ -f "$DONE_FLAG" ] && break
    sleep 1
done

TARGET_PID=$(grep -oE "process with pid [0-9]+" "$PAUSE_LOG" | tail -1 | awk '{print $NF}')
SYM=$(grep -oE "add-symbol-file [^ ]+ 0x[0-9a-f]+" "$PAUSE_LOG" | tail -1 | awk '{print $NF}')
DATA=$(grep -oE "\-s \.data 0x[0-9a-f]+" "$PAUSE_LOG" | tail -1 | awk '{print $NF}')
BSS=$(grep -oE "\-s \.bss 0x[0-9a-f]+" "$PAUSE_LOG" | tail -1 | awk '{print $NF}')
if [ -z "$TARGET_PID" ]; then
    echo "Failed to find pid in Pin pause message. Log:" >&2
    cat "$PAUSE_LOG" >&2
    exit 3
fi
echo "TARGET=$TARGET_PID SYM=$SYM"

cat > "$GDB_CMDS" <<EOFGDB
set confirm off
set pagination off
set breakpoint pending on
handle SIGCHLD nostop noprint pass
handle SIGUSR1 nostop noprint pass
handle SIGUSR2 nostop noprint pass
handle SIG34   nostop noprint pass
handle SIG35   nostop noprint pass
handle SIGABRT nostop noprint pass
handle SIGSEGV stop nopass print
set sysroot /not/existing/dir
file
python gdb.execute("set debug-file-directory ${PIN_ROOT}/debug_files/intel64:" + gdb.parameter("debug-file-directory"))
add-symbol-file $TOOL ${SYM} -s .data ${DATA} -s .bss ${BSS}
info sharedlibrary
continue
echo ============ CRASH SNAPSHOT ============\n
info threads
bt 40
echo ---- REGS ----\n
info registers rip rsp rbp rax rbx rcx rdx rdi rsi r8 r9 r10 r11 r12 r13 r14 r15
echo ---- INSN AROUND PC ----\n
x/16i \$rip-64
x/8i \$rip
echo ---- PC RESOLUTION ----\n
info symbol \$rip
info line *\$rip
detach
quit
EOFGDB

timeout "$ATTACH_TO" gdb -p "$TARGET_PID" -batch -x "$GDB_CMDS" > "$OUT" 2>&1
rc=$?

# Let Pin finish (crash cleanup or continued run to completion).
for _ in $(seq 1 60); do [ -f "$DONE_FLAG" ] && break; sleep 1; done

echo
echo "=== gdb exit=$rc; log written to $OUT ==="
echo "=== pin tail ==="
tail -3 "$PAUSE_LOG"
