#!/usr/bin/env python3
"""Parse SPEC CPU 2017 speccmds.cmd files and emit a JSON schedule.

For each benchmark under $SPEC_DIR/benchspec/CPU that has a prebuilt exe
and a run/run_base_<class>_<config>.0000 directory, read the speccmds.cmd
and extract every invocation. Emit a JSON list of records like:

    [
      {
        "bench": "605.mcf_s",
        "class": "test",
        "config": "gcctest-m64",
        "run_dir": "/path/to/run_base_test_gcctest-m64.0000",
        "invocations": [
          {"exe": "mcf_s_base.gcctest-m64", "args": ["inp.in"],
           "stdout": "inp.out", "stderr": "inp.err"},
          ...
        ]
      }, ...
    ]

Usage:
    scripts/spec/parse-spec-invocations.py [--spec-dir DIR]
        [--class test|train|refspeed|refrate|...] [--config CONFIG]
        [--bench <glob>]... [-o out.json]

Defaults: --spec-dir=$SPEC or /home/user/speccpu2017-1.0.2;
--class=test; --config auto-detected per benchmark.

Speccmds.cmd is Perl's ExtUtils::Command-like format: one command per
line, `-E K V` sets env vars, `-C dir` chdirs, `-o path` and `-e path`
redirect stdio, then the command line follows.
"""
from __future__ import annotations
import argparse
import fnmatch
import glob
import json
import os
import re
import shlex
import sys


def parse_speccmds(path: str):
    invocs = []
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith(("-E ", "-C ", "-r", "-N ")):
                continue
            # Format:  -o STDOUT -e STDERR CMD ARGS...  [> ... 2>> ...]
            m = re.match(r"^-o\s+(\S+)\s+-e\s+(\S+)\s+(\S+)\s+(.*)$", line)
            if not m:
                continue
            out_f, err_f, exe, args_str = m.groups()
            # Strip trailing shell redirection SPEC appends
            args_str = re.sub(r"\s*>\s*\S+\s*2>>?\s*\S+\s*$", "", args_str)
            try:
                args = shlex.split(args_str)
            except ValueError:
                args = args_str.split()
            invocs.append({
                "exe": os.path.basename(exe),
                "args": args,
                "stdout": out_f,
                "stderr": err_f,
            })
    return invocs


def find_benchmarks(spec_dir: str, class_: str, config: str | None,
                    bench_globs: list[str]):
    out = []
    for bench_dir in sorted(glob.glob(os.path.join(spec_dir, "benchspec", "CPU", "*"))):
        bench = os.path.basename(bench_dir)
        # Match against globs (or all if none supplied)
        if bench_globs and not any(fnmatch.fnmatch(bench, g) for g in bench_globs):
            continue
        run_root = os.path.join(bench_dir, "run")
        if not os.path.isdir(run_root):
            continue
        # Discover per-benchmark configs. When --config is not given,
        # use the first one found for the requested class.
        pattern = f"run_base_{class_}_*.0000"
        matches = sorted(glob.glob(os.path.join(run_root, pattern)))
        if config:
            matches = [m for m in matches
                       if os.path.basename(m).startswith(f"run_base_{class_}_{config}")]
        for run_dir in matches:
            cmd = os.path.join(run_dir, "speccmds.cmd")
            if not os.path.isfile(cmd):
                continue
            invocs = parse_speccmds(cmd)
            if not invocs:
                continue
            # config is embedded in the dirname:
            # run_base_<class>_<config>.0000
            cfg = re.sub(r"^run_base_" + re.escape(class_) + r"_", "",
                         os.path.basename(run_dir)).rsplit(".", 1)[0]
            # Verify at least one invocation's exe exists in the run dir
            first_exe = invocs[0]["exe"]
            if not os.path.exists(os.path.join(run_dir, first_exe)):
                # Sometimes the exe lives up one level in exe/ - link it in
                exe_path = os.path.join(bench_dir, "exe", first_exe)
                if not os.path.exists(exe_path):
                    continue
            out.append({
                "bench": bench,
                "class": class_,
                "config": cfg,
                "run_dir": run_dir,
                "invocations": invocs,
            })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec-dir",
                    default=os.environ.get("SPEC", "/home/user/speccpu2017-1.0.2"))
    ap.add_argument("--class", dest="class_", default="test",
                    help="test / train / refspeed / refrate / etc")
    ap.add_argument("--config", default=None,
                    help="config name (e.g., gcctest-m64); autodetect if omitted")
    ap.add_argument("--bench", action="append", default=[],
                    help="glob for benchmark names, repeatable "
                         "(e.g. --bench '6*_s')")
    ap.add_argument("-o", "--out", default=None, help="write JSON here")
    args = ap.parse_args()

    records = find_benchmarks(args.spec_dir, args.class_, args.config,
                              args.bench)
    if not records:
        print("no matching benchmarks found", file=sys.stderr)
        sys.exit(1)
    text = json.dumps(records, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text)
        print(f"wrote {len(records)} benchmark(s) to {args.out}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
