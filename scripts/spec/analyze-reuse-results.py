#!/usr/bin/env python3
"""Analyze SPEC CPU 2017 instruction reuse distance results.

Reads JSON output files from ins_reuse_client and produces a summary
with key insights for each benchmark and cross-benchmark comparisons.
"""
import json
import glob
import os
import sys


def parse_multi_json(path):
    with open(path) as f:
        content = f.read()
    results = []
    decoder = json.JSONDecoder()
    pos = 0
    while pos < len(content):
        remaining = content[pos:].lstrip()
        if not remaining:
            break
        try:
            obj, end = decoder.raw_decode(remaining)
            pos += len(content) - len(remaining) - pos + end
            results.append(obj)
        except json.JSONDecodeError:
            break
    return results


def analyze_benchmark(name, results):
    info = {"name": name}
    for obj in results:
        metric = obj.get("Metric", "")
        source = obj.get("Source", "")

        if metric == "InsReuse" and source == "Whole program":
            raw = obj.get("raw", [])
            fp = obj.get("Footprint", 0)
            total = sum(raw) if isinstance(raw, list) else 0
            if fp == 0 and raw:
                fp = raw[0]
            info["footprint"] = fp
            info["total_instructions"] = total
            info["ins_histo"] = raw

            # Compute L1i-miss-prone fraction (reuse dist > 8192 = ~32KB L1i)
            beyond_l1i = sum(raw[i] for i in range(14, len(raw)))
            info["beyond_l1i_frac"] = beyond_l1i / total if total > 0 else 0

            # Compute working set 90th percentile
            if total > 0 and isinstance(raw, list):
                cumul = 0
                for i, v in enumerate(raw):
                    cumul += v
                    if cumul >= 0.9 * total:
                        info["p90_reuse_dist"] = 2**i if i > 0 else 0
                        break

        elif metric.startswith("EvictionPairs_"):
            level = metric.replace("EvictionPairs_", "")
            misses = obj.get("TotalMisses", 0)
            cap = obj.get("Capacity", 0)
            pairs = obj.get("pairs", [])
            if "eviction" not in info:
                info["eviction"] = {}
            info["eviction"][level] = {
                "misses": misses,
                "capacity": cap,
                "top_pairs": pairs[:5],
            }

        elif metric == "64B CacheLineReuse" and source == "Whole program":
            raw = obj.get("raw", [])
            fp = obj.get("Footprint", 0)
            if fp == 0 and raw:
                fp = raw[0]
            info["cacheline_footprint"] = fp

        elif metric == "4K OS PageSizeReuse" and source == "Whole program":
            raw = obj.get("raw", [])
            fp = obj.get("Footprint", 0)
            if fp == 0 and raw:
                fp = raw[0]
            info["page_footprint"] = fp

    return info


def format_number(n):
    if n >= 1e9:
        return f"{n/1e9:.1f}B"
    elif n >= 1e6:
        return f"{n/1e6:.1f}M"
    elif n >= 1e3:
        return f"{n/1e3:.1f}K"
    return str(int(n))


def main():
    log_dir = sys.argv[1] if len(sys.argv) > 1 else "/home/user/cctlib/spec_results/logs"
    tsv_file = os.path.join(os.path.dirname(log_dir), "summary.tsv")

    # Parse timing data
    timing = {}
    if os.path.exists(tsv_file):
        with open(tsv_file) as f:
            header = f.readline()
            for line in f:
                parts = line.strip().split("\t")
                if len(parts) >= 5:
                    timing[parts[0]] = {
                        "elapsed": int(parts[3]),
                        "exit": int(parts[4]),
                    }

    benchmarks = []
    for jf in sorted(glob.glob(os.path.join(log_dir, "*.json"))):
        name = os.path.basename(jf).split(".reuse.")[0]
        sz = os.path.getsize(jf)
        if sz < 200:
            continue
        results = parse_multi_json(jf)
        info = analyze_benchmark(name, results)
        if name.replace("-0", "") in timing:
            info["elapsed"] = timing[name.replace("-0", "")]["elapsed"]
        benchmarks.append(info)

    if not benchmarks:
        print("No completed benchmarks found.")
        return

    # Sort by footprint
    benchmarks.sort(key=lambda b: b.get("footprint", 0), reverse=True)

    print("=" * 90)
    print("  SPEC CPU 2017 Instruction Reuse Distance Analysis — Summary")
    print("=" * 90)
    print()

    # Overview table
    print(f"{'Benchmark':<20} {'Footprint':>9} {'CL-FP':>7} {'Pg-FP':>6} {'Total Ins':>10} {'P90 Dist':>8} "
          f"{'L1i Miss':>9} {'L2 Miss':>9} {'iTLB Miss':>10} {'Time':>6}")
    print("-" * 104)

    for b in benchmarks:
        name = b["name"].replace("-0", "")
        fp = format_number(b.get("footprint", 0))
        clfp = format_number(b.get("cacheline_footprint", 0))
        pgfp = format_number(b.get("page_footprint", 0))
        total = format_number(b.get("total_instructions", 0))
        p90 = format_number(b.get("p90_reuse_dist", 0))
        ev = b.get("eviction", {})
        l1i = format_number(ev.get("L1i", {}).get("misses", 0))
        l2 = format_number(ev.get("L2", {}).get("misses", 0))
        itlb = format_number(ev.get("iTLB", {}).get("misses", 0))
        elapsed = f"{b.get('elapsed', '?')}s"
        print(f"{name:<20} {fp:>9} {clfp:>7} {pgfp:>6} {total:>10} {p90:>8} {l1i:>9} {l2:>9} {itlb:>10} {elapsed:>6}")

    # Sanity checks
    print()
    print("=" * 104)
    print("  Sanity Checks")
    print("=" * 104)
    issues = []
    for b in benchmarks:
        name = b["name"].replace("-0", "")
        ev = b.get("eviction", {})
        l1i_m = ev.get("L1i", {}).get("misses", 0)
        l2_m = ev.get("L2", {}).get("misses", 0)
        l3_m = ev.get("L3", {}).get("misses", 0)
        itlb_m = ev.get("iTLB", {}).get("misses", 0)
        if l1i_m > 0 and l2_m > 0 and l1i_m < l2_m:
            issues.append(f"  WARN: {name}: L1i misses ({l1i_m}) < L2 misses ({l2_m}) — violates inclusivity")
        if l2_m > 0 and l3_m > 0 and l2_m < l3_m:
            issues.append(f"  WARN: {name}: L2 misses ({l2_m}) < L3 misses ({l3_m}) — violates inclusivity")
        fp = b.get("footprint", 0)
        total = b.get("total_instructions", 0)
        if fp > 0 and total > 0 and fp > total:
            issues.append(f"  WARN: {name}: footprint ({fp}) > total instructions ({total})")
        if total == 0:
            issues.append(f"  WARN: {name}: total_instructions = 0 (empty histogram)")
    if issues:
        for iss in issues:
            print(iss)
    else:
        print("  All checks passed: L1i >= L2 >= L3 (inclusivity), footprint <= total")

    print()

    # Ranking by frontend pressure
    print("=" * 90)
    print("  Frontend Pressure Ranking")
    print("=" * 90)

    by_l1i = sorted(benchmarks,
                    key=lambda b: b.get("eviction", {}).get("L1i", {}).get("misses", 0),
                    reverse=True)
    print("\n  Top L1i eviction miss counts:")
    for i, b in enumerate(by_l1i[:10]):
        ev = b.get("eviction", {}).get("L1i", {})
        if ev.get("misses", 0) > 0:
            mpki = ev["misses"] / (b.get("total_instructions", 1) / 1000)
            print(f"    {i+1}. {b['name']:<22} {ev['misses']:>10,} misses "
                  f"({mpki:.2f} MPKI)")

    by_itlb = sorted(benchmarks,
                     key=lambda b: b.get("eviction", {}).get("iTLB", {}).get("misses", 0),
                     reverse=True)
    print("\n  Top iTLB eviction miss counts:")
    for i, b in enumerate(by_itlb[:10]):
        ev = b.get("eviction", {}).get("iTLB", {})
        if ev.get("misses", 0) > 0:
            mpki = ev["misses"] / (b.get("total_instructions", 1) / 1000)
            print(f"    {i+1}. {b['name']:<22} {ev['misses']:>10,} misses "
                  f"({mpki:.4f} MPKI)")

    print()

    # Top eviction pairs per benchmark
    print("=" * 90)
    print("  Top Eviction Pairs (Actionable Optimization Targets)")
    print("=" * 90)

    for b in benchmarks:
        ev = b.get("eviction", {})
        has_pairs = False
        for level in ["L1i", "L2", "iTLB"]:
            if level in ev and ev[level]["misses"] > 100:
                pairs = ev[level].get("top_pairs", [])
                concentrated = [p for p in pairs if p.get("count", 0) > 1]
                if concentrated:
                    has_pairs = True
        if not has_pairs:
            continue

        print(f"\n  {b['name']}:")
        for level in ["L1i", "L2", "iTLB"]:
            if level not in ev or ev[level]["misses"] < 100:
                continue
            pairs = ev[level].get("top_pairs", [])
            concentrated = [p for p in pairs if p.get("count", 0) > 1]
            if not concentrated:
                continue
            total_miss = ev[level]["misses"]
            print(f"    {level} (cap={ev[level]['capacity']:,}, total={total_miss:,}):")
            for p in concentrated[:3]:
                cnt = p["count"]
                pct = cnt / total_miss * 100
                evicted = p.get("evicted", ["?"])
                incoming = p.get("incoming", ["?"])
                print(f"      {cnt:>8,} ({pct:5.1f}%) "
                      f"evict={evicted[0][:45]}")
                print(f"                       "
                      f"   by={incoming[0][:45]}")

    print()

    # Reuse distance histogram insights
    print("=" * 90)
    print("  Instruction Locality Characterization")
    print("=" * 90)
    print()

    for b in benchmarks:
        histo = b.get("ins_histo", [])
        total = b.get("total_instructions", 0)
        if not histo or total == 0:
            continue
        # Find where 50% and 90% of accesses fall
        cumul = 0
        p50 = p90 = p99 = None
        for i, v in enumerate(histo):
            cumul += v
            if p50 is None and cumul >= 0.5 * total:
                p50 = i
            if p90 is None and cumul >= 0.9 * total:
                p90 = i
            if p99 is None and cumul >= 0.99 * total:
                p99 = i
                break

        cold_frac = histo[0] / total * 100 if len(histo) > 0 else 0
        name = b["name"].replace("-0", "")
        print(f"  {name}: fp={b.get('footprint',0):,}")
        print(f"    Cold starts: {histo[0]:,} ({cold_frac:.2f}%)")
        if p50 is not None:
            print(f"    50%: reuse dist <= {2**p50:,} (bin {p50})")
        if p90 is not None:
            print(f"    90%: reuse dist <= {2**p90:,} (bin {p90})")
        if p99 is not None:
            print(f"    99%: reuse dist <= {2**p99:,} (bin {p99})")
        print()


if __name__ == "__main__":
    main()
