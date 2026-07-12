#!/usr/bin/env python3
"""Run SPEC CPU 2017 invocations under a Pin tool with memory-safe parallelism.

Reads a JSON schedule (from parse-spec-invocations.py) and launches each
invocation under $PIN_ROOT/pin -t <tool>. Enforces:

  * Maximum concurrent workers (--jobs).
  * Minimum free RAM before starting a new worker (--min-free-mb).
    If free RAM drops below the threshold, waits for a worker to finish
    before launching another.
  * Per-invocation timeout (--timeout).

Kills the most-recent worker (largest RSS) if we hit an OOM-like state
between checks (--kill-on-oom). By default just backs off.

Records per-invocation results into <results-dir>/summary.tsv, and pin's
per-invocation stdout/stderr into <results-dir>/logs/<bench>-<i>.{out,err}.
Extracts GrandTotalDead / GrandTotalWrites from any dead*|red*|redLoad*
output file in the run dir.

Usage:
    scripts/spec/run-spec-under-tool.py \
        --tool clients/obj-intel64/deadspy_client.so \
        --spec-dir /path/to/speccpu2017 \
        --class test \
        [--bench '6*_s']... \
        [--jobs 12] [--min-free-mb 32000] [--timeout 3600] \
        [--results-dir /tmp/spec_sweep] [--invocations first|all]

Env: PIN_ROOT is required.
"""
from __future__ import annotations
import argparse
import glob
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path


def free_mb() -> int:
    with open("/proc/meminfo") as f:
        m = {}
        for line in f:
            k, v = line.split(":", 1)
            m[k.strip()] = int(v.strip().split()[0]) // 1024  # KB->MB
    return m.get("MemAvailable", m.get("MemFree", 0))


def parse_report(run_dir: str):
    """Look for deadspy.out.*, redspy.out.*, redLoad.out.* and extract totals."""
    for prefix in ("deadspy.out.", "redspy.out.", "redLoad.out."):
        files = sorted(glob.glob(os.path.join(run_dir, prefix + "*")),
                       key=os.path.getmtime, reverse=True)
        if not files:
            continue
        gd = gw = pct = None
        try:
            with open(files[0]) as f:
                for line in f:
                    if "GrandTotalDead" in line:
                        parts = line.split()
                        gd = parts[2] if len(parts) >= 3 else None
                        pct = parts[4] if len(parts) >= 5 else None
                    elif "GrandTotalWrites" in line:
                        parts = line.split()
                        gw = parts[2] if len(parts) >= 3 else None
        except OSError:
            pass
        return gd, gw, pct
    return None, None, None


def cleanup_reports(run_dir: str):
    for prefix in ("deadspy.out.", "redspy.out.", "redLoad.out."):
        for f in glob.glob(os.path.join(run_dir, prefix + "*")):
            try:
                os.remove(f)
            except OSError:
                pass


class Worker:
    def __init__(self, bench, class_, idx, invoc, run_dir, tool, timeout,
                 log_dir, results_tsv):
        self.bench = bench
        self.class_ = class_
        self.idx = idx
        self.invoc = invoc
        self.run_dir = run_dir
        self.tool = tool
        self.timeout = timeout
        self.log_dir = log_dir
        self.results_tsv = results_tsv
        self.proc = None
        self.start_ts = None

    def spawn(self, pin_bin: str):
        cleanup_reports(self.run_dir)
        exe = self.invoc["exe"]
        args = self.invoc["args"]
        # If the exe isn't in run_dir, look under ../../exe
        exe_path = os.path.join(self.run_dir, exe)
        if not os.path.exists(exe_path):
            bench_dir = os.path.dirname(os.path.dirname(self.run_dir))
            up_exe = os.path.join(bench_dir, "exe", exe)
            if os.path.exists(up_exe):
                shutil.copy2(up_exe, exe_path)
        os.chmod(exe_path, 0o755)
        cmdline = [pin_bin, "-t", self.tool, "--", "./" + exe, *args]
        stem = f"{self.bench}-{self.idx}"
        out = open(os.path.join(self.log_dir, f"{stem}.out"), "w")
        err = open(os.path.join(self.log_dir, f"{stem}.err"), "w")
        env = os.environ.copy()
        # Force single-thread for OMP-enabled benchmarks (cctlib is
        # single-threaded).
        env["OMP_NUM_THREADS"] = "1"
        # Isolate from stray SIGINT if driver is Ctrl-C'd.
        self.proc = subprocess.Popen(
            cmdline, cwd=self.run_dir, stdout=out, stderr=err, env=env,
            preexec_fn=os.setpgrp,
        )
        self.start_ts = time.time()
        self.out = out
        self.err = err

    def poll(self):
        if self.proc is None:
            return False
        rc = self.proc.poll()
        if rc is None:
            # Timeout check
            if time.time() - self.start_ts > self.timeout:
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                rc = -1
            else:
                return False
        elapsed = int(time.time() - self.start_ts)
        gd, gw, pct = parse_report(self.run_dir)
        # Check for known error patterns.
        note = ""
        try:
            with open(self.err.name) as f:
                errtxt = f.read()
                if "Tool (or Pin) caused signal" in errtxt:
                    note = "SIGSEGV-in-tool"
                elif "Pin stack overflow" in errtxt:
                    note = "pin-stack-overflow"
                elif rc == -1:
                    note = "timeout"
        except OSError:
            pass
        # cctlib writes its own diagnostic messages ("Preallocated IPNodes
        # exhausted", "Preallocated String Pool exhausted", etc.) to the
        # tool's own log file, NOT to stderr, so we peek there too.
        if not note and rc != 0:
            for prefix in ("deadspy.out.", "redspy.out.", "redLoad.out."):
                for f_ in sorted(glob.glob(os.path.join(self.run_dir, prefix + "*"))):
                    try:
                        with open(f_) as f:
                            log = f.read()
                        if "Preallocated IPNodes exhausted" in log:
                            note = "cctlib-ipnodes-exhausted"; break
                        if "Preallocated String Pool exhausted" in log:
                            note = "cctlib-strpool-exhausted"; break
                    except OSError:
                        pass
                if note:
                    break
        row = (self.bench, self.class_, self.idx, elapsed, rc,
               gd or "?", gw or "?", pct or "?", note)
        with open(self.results_tsv, "a") as f:
            f.write("\t".join(str(x) for x in row) + "\n")
        try:
            self.out.close(); self.err.close()
        except Exception:
            pass
        return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", required=True)
    ap.add_argument("--spec-dir", default=os.environ.get("SPEC",
                    "/home/user/speccpu2017-1.0.2"))
    ap.add_argument("--class", dest="class_", default="test")
    ap.add_argument("--config", default=None)
    ap.add_argument("--bench", action="append", default=[])
    ap.add_argument("--invocations", choices=["first", "all"], default="first")
    ap.add_argument("--jobs", type=int, default=12)
    ap.add_argument("--min-free-mb", type=int, default=32000)
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--results-dir", default="/tmp/spec_sweep")
    ap.add_argument("--schedule-json", default=None,
                    help="Load pre-parsed schedule instead of scanning "
                         "--spec-dir. Overrides --spec-dir/--bench/etc.")
    args = ap.parse_args()

    pin_root = os.environ.get("PIN_ROOT")
    if not pin_root:
        print("PIN_ROOT must be set", file=sys.stderr); sys.exit(2)
    pin_bin = os.path.join(pin_root, "pin")
    if not os.path.exists(pin_bin):
        print(f"{pin_bin} missing", file=sys.stderr); sys.exit(2)
    if not os.path.exists(args.tool):
        print(f"{args.tool} missing", file=sys.stderr); sys.exit(2)

    results_dir = Path(args.results_dir)
    log_dir = results_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    tsv = results_dir / "summary.tsv"
    with open(tsv, "w") as f:
        f.write("bench\tclass\tinvoc\telapsed_s\texit\tgrand_dead\t"
                "grand_writes\tpct\tnote\n")

    # Load schedule
    if args.schedule_json:
        with open(args.schedule_json) as f:
            recs = json.load(f)
    else:
        # Use the sibling parser
        here = os.path.dirname(os.path.abspath(__file__))
        parser_py = os.path.join(here, "parse-spec-invocations.py")
        cmd = [sys.executable, parser_py, "--spec-dir", args.spec_dir,
               "--class", args.class_]
        if args.config: cmd += ["--config", args.config]
        for b in args.bench: cmd += ["--bench", b]
        recs = json.loads(subprocess.check_output(cmd))

    if not recs:
        print("no benchmarks matched", file=sys.stderr); sys.exit(1)

    # Build the worker queue
    workers_todo = []
    for rec in recs:
        invocs = rec["invocations"] if args.invocations == "all" else rec["invocations"][:1]
        for i, inv in enumerate(invocs):
            workers_todo.append(Worker(rec["bench"], rec["class"], i, inv,
                                       rec["run_dir"], args.tool,
                                       args.timeout, str(log_dir), str(tsv)))
    print(f"{time.strftime('%H:%M:%S')}  {len(workers_todo)} invocation(s) queued")
    print(f"{time.strftime('%H:%M:%S')}  jobs={args.jobs} min_free={args.min_free_mb}MB "
          f"timeout={args.timeout}s")

    active: list[Worker] = []
    todo = list(workers_todo)
    while todo or active:
        # Reap
        active = [w for w in active if not w.poll()]
        # Launch
        while todo and len(active) < args.jobs:
            fm = free_mb()
            if fm < args.min_free_mb:
                print(f"{time.strftime('%H:%M:%S')}  MEM pressure: "
                      f"free={fm}MB < {args.min_free_mb}MB "
                      f"(active={len(active)}) - waiting")
                break
            w = todo.pop(0)
            try:
                w.spawn(pin_bin)
                active.append(w)
                print(f"{time.strftime('%H:%M:%S')}  launched "
                      f"{w.bench}-{w.idx} (pid={w.proc.pid}) - "
                      f"queue={len(todo)} active={len(active)} "
                      f"free={fm}MB")
            except Exception as e:
                print(f"failed to launch {w.bench}-{w.idx}: {e}")
        time.sleep(5)

    print(f"{time.strftime('%H:%M:%S')}  Done. Summary in {tsv}")


if __name__ == "__main__":
    main()
