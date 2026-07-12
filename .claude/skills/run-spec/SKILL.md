---
name: run-spec
description: Run SPEC CPU 2017 benchmarks (a subset or the full suite) under a Pin tool, safely in parallel — the driver enforces per-worker RAM and per-invocation timeouts, records per-benchmark deadspy/redspy/loadspy totals, and works across any workload class (test / train / refspeed / refrate). Use when you want a full-suite characterization under cctlib.
---

# Run SPEC CPU 2017 under a Pin tool

The `scripts/spec/` directory in this repo provides a two-part harness:

1. **`parse-spec-invocations.py`** — walks a SPEC install, finds every
   `run_base_<class>_<config>.0000/speccmds.cmd`, parses the invocation
   lines (env, exe, args, redirections), and emits a JSON schedule.
2. **`run-spec-under-tool.py`** — consumes that schedule (or scans on
   its own) and drives the invocations under `pin -t <tool>` with
   memory-safe parallelism.

The harness assumes the SPEC install has been built with `runcpu` and
the `run_base_<class>_<config>.0000` directories exist for the class
you want (typically `test`, `train`, or `refspeed`/`refrate`). Building
SPEC itself is out of scope for this skill — do it once via the SPEC
toolchain:

```sh
cd /path/to/speccpu2017 && source shrc
runcpu --config gcctest-m64.cfg --action build --tune base intspeed
runcpu --config gcctest-m64.cfg --action runsetup --tune base --size test intspeed
```

## Quick start

Run the `test` workload of every speed benchmark that's already built,
under deadspy, with 12 parallel workers and 32 GB free-RAM guardrail:

```sh
export PIN_ROOT=/path/to/pin
export SPEC=/path/to/speccpu2017
scripts/spec/run-spec-under-tool.py \
    --tool  clients/obj-intel64/deadspy_client.so \
    --class test \
    --jobs  12 \
    --min-free-mb 32000 \
    --results-dir /tmp/spec_sweep
```

Progress lines land on stdout; per-benchmark stdout/stderr under
`/tmp/spec_sweep/logs/`; final results in `/tmp/spec_sweep/summary.tsv`
with columns `bench class invoc elapsed_s exit grand_dead grand_writes pct note`.

## Selecting a subset

Bench globs are additive:

```sh
--bench '6*_s'          # all speed benchmarks starting with 6
--bench '605.mcf_s' --bench '641.leela_s'
```

Some benchmarks (notably `657.xz_s`) have multiple invocations per
workload. Default is `--invocations first` (representative). Use
`--invocations all` to run every one.

## Workload classes

Pass `--class` matching the workload directory naming SPEC used:

| Class          | When to use                                       |
|----------------|---------------------------------------------------|
| `test`         | Smallest input; ~seconds native; ~minutes under Pin. Good for smoke testing. |
| `train`        | Medium input; ~minutes native; ~hours under Pin.  |
| `refspeed`     | Reference / official input for speed benchmarks. Hours under Pin. |
| `refrate`      | Reference for rate benchmarks.                    |

Which classes exist depends on what `runcpu --action runsetup` produced.
`--config` lets you disambiguate when multiple configs are built for the
same class (e.g. `gcctest-m64` vs `mytune-m64`).

## Memory-safe scheduling

The driver checks `/proc/meminfo`'s `MemAvailable` before every launch.
If it's below `--min-free-mb`, it waits for a currently-running worker
to finish before starting the next. Deadspy shadow memory can grow to a
few GB per process on ref-workloads, so keep the guardrail conservative
(rule of thumb: `--min-free-mb = 4 * expected_peak_shadow_MB`).

Per-invocation `--timeout` (default 3600 s) hard-kills a stuck worker.
The row is recorded with `note=timeout`.

## OMP-parallel benchmarks

cctlib is single-threaded. The driver sets `OMP_NUM_THREADS=1` in the
child's environment so multithreaded benchmarks (`619.lbm_s`, several
fp) run single-threaded under Pin. If you want multithreaded, disable
that in the driver — but be prepared for cctlib races.

## Interpreting the results

`summary.tsv` after a `--class test --tool deadspy_client.so` run on all
10 SPEC speed benchmarks looks like:

```
bench            class  invoc  elapsed_s  exit  grand_dead    grand_writes    pct
602.gcc_s        test   0      7          0     1841657       15629781        11.78%
600.perlbench_s  test   0      12         0     241528863     2662835861      9.07%
605.mcf_s        test   0      143        0     3094682545    22347356966     13.85%
...
```

Sanity checks:

- `exit=0` and non-empty `grand_dead / grand_writes / pct` — successful run.
- `note` is either empty, or one of `SIGSEGV-in-tool` (a tool bug), 
  `pin-stack-overflow` (cctlib's recursive VisitAllNodesOfSplayTree
  blew Pin's C stack; typically at ref-workload scale), `timeout`,
  or `cctlib-ipnodes-exhausted` / `cctlib-strpool-exhausted` (see
  below).
- `pct` in the low-single-digit-to-teens range is typical for
  well-behaved benchmarks. Anything way out of that range is worth a
  second look.

## cctlib design limits

The `cctlib-ipnodes-exhausted` note means the benchmark generated
more distinct call-path contexts than cctlib's preallocated
`MAX_IPNODES` (2^32 on x86_64) can hold. `ContextHandle_t` is a
`uint32_t`, so this is a hard ceiling; PIN\_ExitProcess(-1) fires
(exit=255). Observed on `631.deepsjeng_s` refspeed: chess minimax
recursion at depth 15+ produces billions of unique callchains. If
you hit this and need a report anyway, options are:

  * Run the `test` workload of the same benchmark (much smaller
    call-graph coverage).
  * Instrument only a subset of images with `-follow_execv 0` and
    Pin's include/exclude flags.
  * A deeper fix is to widen `ContextHandle_t` to 64-bit, which
    also doubles per-node metadata memory.

## Debugging a failing benchmark

If a specific benchmark reports `SIGSEGV-in-tool`:

1. Rebuild the tool with `-g -O0`:
   `scripts/build-debug-tool.sh deadspy_client`
2. Attach gdb non-interactively:
   `scripts/gdb-pintool-attach.sh --tool clients/obj-intel64/deadspy_client.so --app <benchmark_exe> --arg <args>...`

See the `debug-pintool` skill for full debugging workflow.

## Two-step invocation (parse once, run many times)

For iterating on tool code without rescanning SPEC:

```sh
# One time: dump schedule
scripts/spec/parse-spec-invocations.py --class test -o /tmp/sched.json

# Each iteration: run against a rebuilt tool
scripts/spec/run-spec-under-tool.py \
    --tool clients/obj-intel64/deadspy_client.so \
    --schedule-json /tmp/sched.json
```

## Extending to a new SPEC install / new config

`parse-spec-invocations.py` walks any layout that matches
`benchspec/CPU/*/run/run_base_<class>_<config>.0000/speccmds.cmd`. That
covers the standard SPEC-2017 tree; adjust the script's `find_benchmarks`
regex if a downstream distributor uses a different naming.
