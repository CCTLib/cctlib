---
name: debug-pintool
description: Debug a crashing or misbehaving Pintool (deadspy/redspy/loadspy or any cctlib client) via Pin's `-pause_tool` handoff and gdb attach. Use when the tool exits with `Tool (or Pin) caused signal ...`, a raw SIGSEGV, or wrong analysis results. Not for debugging the *application* being instrumented — for that, use Pin's `-appdebug` or a normal gdb session on the app.
---

# Debug a Pintool

Pin runs the application under its dynamic instrumentation engine; the Pintool
code (deadspy, redspy, loadspy, ...) executes inside the application's address
space. A normal `gdb --args pin ...` won't work because Pin itself uses the
kernel debugging API to bootstrap the application.

The intended workflow is **launch Pin from one terminal with `-pause_tool N`;
attach gdb from another terminal to the paused process; load the tool's debug
symbols via `add-symbol-file` at the address Pin printed; then `continue`**.

Reference: <https://software.intel.com/sites/landingpage/pintool/docs/99850/Pin/doc/html/index.html#DEBUGGING>

## Prerequisites

- Rebuild the tool (and libcctlib) with debug info and no optimization so gdb
  can resolve symbols and locals. Do NOT rely on the release build for
  debugging — inlining and `-fomit-frame-pointer` will make backtraces
  useless.

  ```sh
  cd cctlib
  # Compile with -g -O0 -fno-omit-frame-pointer. The Pin toolchain honors
  # DEBUG=1 but does not override -O3 in the cctlib Makefiles, so pass the
  # flags explicitly. Example for deadspy:
  export PIN_ROOT=/path/to/pin
  cd src && $PIN_ROOT/intel64/pinrt/bin/pin-g++ ... -g -O0 -fno-omit-frame-pointer ... -c cctlib.cpp
  ar cr obj-intel64/libcctlib.a obj-intel64/cctlib.o
  cd ../clients && $PIN_ROOT/intel64/pinrt/bin/pin-g++ ... -g -O0 -fno-omit-frame-pointer ... -c deadspy_client.cpp
  # Then link normally with pin-g++ -shared ... -lcctlib
  ```

  A pre-baked script exists at `scripts/build-debug-tool.sh` (build one tool
  under `-g -O0`) — run it before starting a debug session.

- On a system where `/proc/sys/kernel/yama/ptrace_scope` is `1` (Debian /
  Ubuntu default), gdb cannot attach to a process it did not spawn UNLESS
  gdb has `cap_sys_ptrace`. Check with `getcap /usr/bin/gdb`. If missing,
  either request root to run `setcap cap_sys_ptrace=eip $(which gdb)` or
  `sysctl -w kernel.yama.ptrace_scope=0`.

## Step-by-step

1. **Launch Pin with `-pause_tool`** in one terminal (or background it). Pick
   a long-enough pause window that you have time to attach.

   ```sh
   $PIN_ROOT/pin -pause_tool 300 \
     -t /path/to/cctlib/clients/obj-intel64/deadspy_client.so \
     -- /path/to/victim <args>
   ```

   Pin prints something like:

   ```
   Pausing for 300 seconds to attach to process with pid 12345
   To load the debug info to gdb use:
   *****************************************************************
   set sysroot /not/existing/dir
   file
   python gdb.execute("set debug-file-directory .../debug_files/intel64:" + gdb.parameter("debug-file-directory"))
   add-symbol-file /path/to/deadspy_client.so 0x7fXXXXXXXXXX -s .data 0x7fXXXXXXXXXX -s .bss 0x7fXXXXXXXXXX
   *****************************************************************
   ```

   Copy the `add-symbol-file ...` line — you'll paste it into gdb.

2. **Attach gdb** in another terminal to the pid Pin printed:

   ```sh
   gdb -p 12345
   ```

3. In the gdb prompt, set up so signals used by Pin's runtime don't stop
   you and so SIGSEGV in the tool code is caught:

   ```gdb
   (gdb) set confirm off
   (gdb) set pagination off
   (gdb) handle SIGCHLD nostop noprint pass
   (gdb) handle SIGUSR1 nostop noprint pass
   (gdb) handle SIGUSR2 nostop noprint pass
   (gdb) handle SIG34   nostop noprint pass
   (gdb) handle SIG35   nostop noprint pass
   (gdb) handle SIGSEGV stop nopass print
   ```

4. Paste Pin's four-line symbol-loading block (`set sysroot`, `file`,
   `python gdb.execute(...)`, `add-symbol-file ...`) verbatim. The
   `add-symbol-file` command tells gdb where the tool's `.text`, `.data`,
   and `.bss` are loaded — those addresses vary per run because Pin's
   loader picks them.

5. **Continue** execution. gdb will hand control back to Pin, the app
   starts running, and gdb will stop at your breakpoint or at the SIGSEGV.

   ```gdb
   (gdb) continue
   ```

6. When gdb stops, get a backtrace and register state:

   ```gdb
   (gdb) bt 40
   (gdb) info registers
   (gdb) x/8i $rip-32
   (gdb) info symbol $rip
   ```

## Non-interactive debugging (recommended for CI / batch)

Use the harness script `scripts/gdb-pintool-attach.sh` (checked into
the cctlib repo). It launches Pin with `-pause_tool`, parses the pause
message, and attaches gdb with a canned command file that catches SIGSEGV,
loads the tool's symbols, dumps a backtrace, and detaches.

```sh
scripts/gdb-pintool-attach.sh \
  --tool clients/obj-intel64/deadspy_client.so \
  --app  /path/to/victim \
  --arg  test.sgf \
  --out  /tmp/mydebug.log
```

The output log contains the full backtrace at the crash point with source
lines (assuming `-g` debug build).

## What to look for in the output

- **`PinCCTLib::<function> at cctlib.cpp:<line>`** at any frame — a real
  cctlib bug. See recent examples: `CaptureCallerThatCanHandleException` (exc
  unwind ABI), `UpdateCurTraceAndIp(trace=0x0, ...)` (uncaught-exception
  NULL deref).
- **`RedSpyAnalysis::CheckNByteValueAfterRead(addr=0x1, ...)`** — client
  callback derefs an invalid address the app is about to fault on. Wrap
  with `PIN_SafeCopy`.
- **PC in `[heap]` region with `perms=rw-p`** — an indirect call/jump
  through a corrupted function pointer landed in data memory (NX fault).
  Usually means an ABI mismatch (e.g., `_Unwind_GetIP` resolved to Pin's
  libunwind instead of libgcc).
- **Frame 1 in `libunwind-dynamic.so`** — Pin's private libunwind ran.
  If the crash chain is `CaptureCallerThatCanHandleException` → Pin
  libunwind → heap, that's the exact "wrong `_Unwind_GetIP` resolved"
  bug that was root-caused in cctlib.cpp's `RememberUnwindGetIPFromImage`.
- **`Pin stack overflow in thread N`** — Pin's own C stack blown, most
  often by cctlib's recursive `VisitAllNodesOfSplayTree` at Fini for large
  workloads. Not a tool-runtime bug — either reduce workload or convert
  the walker to an iterative one.

## Common gotchas

- The pid Pin prints is the *application's* pid, not `pind`'s. Attach to
  that pid.
- `add-symbol-file` addresses change every run (ASLR of Pin's loader). Never
  hardcode; always copy from Pin's most recent pause message.
- If your gdb hits `ptrace: Operation not permitted`, check
  `/proc/sys/kernel/yama/ptrace_scope` and `getcap $(which gdb)`.
- If the tool is built with `-O3` you'll see `<optimized out>` for locals
  and the backtrace may be truncated. **Debug builds only.**
- Do NOT put breakpoints in the tool's instrumentation callback for
  every-instruction hooks (e.g. `Record8ByteMemRead`); breakpoints slow
  execution 10 000× — set a conditional or watchpoint.

## Related: attach for a coredump instead

If gdb attach isn't feasible (e.g., no ptrace cap), and the tool
crashes with SIGSEGV, enable core dumps and inspect with gdb on the
core file after the fact:

```sh
ulimit -c unlimited
# Ensure kernel writes cores to CWD:
sudo sysctl -w kernel.core_pattern='/tmp/core.%e.%p'
# ... run pin ... (it will crash and drop /tmp/core.*)
gdb /path/to/pin-tool /tmp/core.*
```

Pin sets its own core-dump behavior; if the core is empty or truncated,
prefer the `-pause_tool` + attach path.
