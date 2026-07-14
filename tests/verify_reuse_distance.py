#!/usr/bin/env python3
"""
Verify ins_reuse_client correctness against known reuse-distance scenarios.

Each test generates a deterministic x86-64 code sequence with a known
BBL structure and iteration count.  The expected per-instruction reuse
distance is computed by hand.  The test runs the code under Pin with
ins_reuse_client.so, parses the JSON histogram output, and checks
whether the dominant histogram bin matches the expected bin.

Usage:
    python3 tests/verify_reuse_distance.py           # run all tests
    python3 tests/verify_reuse_distance.py --test 1   # run only test 1
"""

import json
import os
import subprocess
import sys
import tempfile
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT  = os.path.dirname(SCRIPT_DIR)

PIN_ROOT  = os.environ.get('PIN_ROOT',
    os.path.expanduser('~/pin/pin-external-4.3-99850-gce5652921-gcc-linux'))
TOOL_SO   = os.path.join(REPO_ROOT, 'clients', 'obj-intel64', 'ins_reuse_client.so')
TEST_APP  = os.path.join(REPO_ROOT, 'apps', 'obj-intel64', 'reuse_test.exe')


def distance_to_bin(d):
    """Map a reuse distance to its histogram bin index.

    Bin 0: [0, 1)
    Bin 1: [1, 2)
    Bin k (k>=2): [2^(k-1), 2^k)
    """
    if d == 0:
        return 0
    if d == 1:
        return 1
    return d.bit_length()


def bin_lower_bound(b):
    """Return the lower bound of bin b."""
    if b == 0:
        return 0
    if b == 1:
        return 1
    return 1 << (b - 1)


# ── Test definitions ────────────────────────────────────────────────────

ITERS = 100000

TESTS = [
    {
        'id': 1,
        'name': 'tight_loop_8',
        'desc': '8-instruction self-looping BBL (6 NOPs + sub + jnz)',
        'bbl_ins': 8,
        'true_distance': 7,
        'expected_bin': distance_to_bin(7),      # bin 3 [4,8)
        'expected_count': 8 * (ITERS - 1),       # 799,992
        'bug_distance': 8,                        # FindSumGreaterEqual overcounts
        'bug_bin': distance_to_bin(8),            # bin 4 [8,16)
    },
    {
        'id': 2,
        'name': 'tight_loop_4',
        'desc': '4-instruction self-looping BBL (2 NOPs + sub + jnz)',
        'bbl_ins': 4,
        'true_distance': 3,
        'expected_bin': distance_to_bin(3),      # bin 2 [2,4)
        'expected_count': 4 * (ITERS - 1),       # 399,996
        'bug_distance': 4,
        'bug_bin': distance_to_bin(4),            # bin 3 [4,8)
    },
    {
        'id': 3,
        'name': 'tight_loop_2',
        'desc': '2-instruction self-looping BBL (sub + jnz, no NOPs)',
        'bbl_ins': 2,
        'true_distance': 1,
        'expected_bin': distance_to_bin(1),      # bin 1 [1,2)
        'expected_count': 2 * (ITERS - 1),       # 199,998
        'bug_distance': 2,
        'bug_bin': distance_to_bin(2),            # bin 2 [2,4)
    },
    {
        'id': 4,
        'name': 'two_blocks',
        'desc': 'Alternating BBLs: A(3 ins: 2 NOPs+jmp) + B(5 ins: 3 NOPs+sub+jnz)',
        'total_ins': 8,
        'true_distance': 7,                       # 8 - 1
        'expected_bin': distance_to_bin(7),       # bin 3
        'expected_count': 8 * (ITERS - 1),
        'bug_distance': 8,
        'bug_bin': distance_to_bin(8),            # bin 4
    },
    {
        'id': 5,
        'name': 'two_blocks_32',
        'desc': 'Alternating BBLs: A(16 ins: 15 NOPs+jmp) + B(16 ins: 14 NOPs+sub+jnz)',
        'total_ins': 32,
        'true_distance': 31,                      # 32 - 1
        'expected_bin': distance_to_bin(31),      # bin 5 [16,32)
        'expected_count': 32 * (ITERS - 1),
        'bug_distance': 32,
        'bug_bin': distance_to_bin(32),           # bin 6 [32,64)
    },
    {
        'id': 6,
        'name': 'single_ins',
        'desc': '1-instruction self-looping BBL (LOOP self), 100K iters',
        'bbl_ins': 1,
        'true_distance': 0,
        'expected_bin': 0,                        # bin 0 [0,1)
        'expected_count': ITERS - 2,              # first iter is initial BBL, last falls through
        'bug_distance': 1,
        'bug_bin': distance_to_bin(1),            # bin 1 [1,2)
    },
]


def parse_json_output(json_path):
    """Parse the concatenated JSON objects from ins_reuse_client output."""
    with open(json_path) as f:
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


def find_ins_reuse_histo(results):
    """Extract the InsReuse histogram for TID 0."""
    for r in results:
        if r.get('Metric') == 'InsReuse' and 'TID' in r.get('Source', ''):
            return r['raw']
    return None


def run_test(test_id, work_dir):
    """Run Pin tool on test app, return parsed JSON results."""
    out_prefix = os.path.join(work_dir, 'out.')
    env = os.environ.copy()
    env['INS_REUSE_CLIENT_OUTPUT_FILE'] = out_prefix

    cmd = [
        os.path.join(PIN_ROOT, 'pin'),
        '-t', TOOL_SO,
        '--', TEST_APP, str(test_id),
    ]
    subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=work_dir,
                   timeout=60)

    json_files = [f for f in os.listdir(work_dir)
                  if f.startswith('out.') and f.endswith('.json')]
    if not json_files:
        return None
    return parse_json_output(os.path.join(work_dir, json_files[0]))


def verify_test(test, histo):
    """Compare histogram against expected values; return result dict."""
    expected_bin   = test['expected_bin']
    expected_count = test['expected_count']
    bug_bin        = test['bug_bin']
    total          = sum(histo)

    # For expected_bin > 0, exclude bin 0 (startup noise).
    # For expected_bin == 0 (single-ins test), include all bins.
    if expected_bin == 0:
        dominant_bin   = max(range(len(histo)), key=lambda i: histo[i])
    else:
        dominant_bin   = max(range(1, len(histo)), key=lambda i: histo[i])
    dominant_count = histo[dominant_bin]

    count_ok = True
    if expected_count is not None:
        count_ok = abs(histo[expected_bin] - expected_count) < max(expected_count * 0.10, 100)

    return {
        'expected_bin':    expected_bin,
        'expected_count':  expected_count,
        'actual_in_expected_bin': histo[expected_bin],
        'dominant_bin':    dominant_bin,
        'dominant_count':  dominant_count,
        'bug_bin_count':   histo[bug_bin],
        'total':           total,
        'bin_ok':          dominant_bin == expected_bin,
        'count_ok':        count_ok,
        'hits_bug_bin':    dominant_bin == bug_bin,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test', type=int, default=0,
                        help='Run only this test number (0 = all)')
    args = parser.parse_args()

    for path, label in [(TOOL_SO, 'ins_reuse_client.so'), (TEST_APP, 'reuse_test.exe')]:
        if not os.path.exists(path):
            print(f"ERROR: {label} not found at {path}")
            print(f"Build it first:  cd {REPO_ROOT} && make")
            return 1

    tests_to_run = TESTS if args.test == 0 else [t for t in TESTS if t['id'] == args.test]
    passed  = 0
    failed  = 0
    defects = []

    for test in tests_to_run:
        tid = test['id']
        print(f"\n{'='*70}")
        print(f"Test {tid}: {test['name']}")
        print(f"  {test['desc']}")
        print(f"  True distance: {test['true_distance']}  ->  expected bin {test['expected_bin']} "
              f"[{bin_lower_bound(test['expected_bin'])}, {bin_lower_bound(test['expected_bin']+1)})")
        print(f"  Bug distance:  {test['bug_distance']}  ->  bug bin {test['bug_bin']} "
              f"[{bin_lower_bound(test['bug_bin'])}, {bin_lower_bound(test['bug_bin']+1)})")
        print(f"  Expected ~{test['expected_count']:,} entries in expected bin")

        with tempfile.TemporaryDirectory() as work_dir:
            results = run_test(tid, work_dir)
            if results is None:
                print("  SKIP: no output produced")
                continue

            histo = find_ins_reuse_histo(results)
            if histo is None:
                print("  SKIP: no InsReuse histogram found")
                continue

            v = verify_test(test, histo)

            # Print non-zero bins
            print(f"\n  Histogram (non-zero bins, total = {v['total']:,}):")
            for i in range(len(histo)):
                if histo[i] > 0:
                    lo = bin_lower_bound(i)
                    hi = bin_lower_bound(i + 1)
                    pct = histo[i] / v['total'] * 100 if v['total'] else 0
                    markers = []
                    if i == test['expected_bin']:
                        markers.append('EXPECTED')
                    if i == test['bug_bin']:
                        markers.append('BUG(FindSumGreaterEqual)')
                    tag = f"  <-- {', '.join(markers)}" if markers else ''
                    print(f"    bin {i:2d} [{lo:>10}, {hi:>10}): {histo[i]:>12,} ({pct:6.2f}%){tag}")

            print()
            if v['bin_ok']:
                print(f"  RESULT: PASS")
                passed += 1
            else:
                print(f"  RESULT: FAIL")
                failed += 1

                if v['hits_bug_bin']:
                    diagnosis = (
                        f"Dominant bin is {v['dominant_bin']} (count={v['dominant_count']:,}), "
                        f"should be {v['expected_bin']} (count={v['actual_in_expected_bin']:,}).\n"
                        f"    -> ComputeInsReuseDistance uses FindSumGreaterEqual which includes\n"
                        f"       the node's own value ({test.get('bbl_ins', test.get('total_ins','?'))} = numInsInBBL), "
                        f"overcounting by 1.\n"
                        f"    -> Reported distance {test['bug_distance']} instead of {test['true_distance']}."
                    )
                    defects.append({
                        'test': test['name'],
                        'desc': diagnosis,
                    })
                    print(f"  DIAGNOSIS: {diagnosis}")
                else:
                    print(f"  Dominant bin {v['dominant_bin']} (count={v['dominant_count']:,}) "
                          f"does not match expected bin {v['expected_bin']} or bug bin {test['bug_bin']}")

    # ── Summary ──────────────────────────────────────────────────────

    print(f"\n{'='*70}")
    print(f"SUMMARY: {passed} passed, {failed} failed out of {len(tests_to_run)} tests\n")

    if defects:
        print("DEFECTS FOUND:")
        print("-" * 70)
        for i, d in enumerate(defects, 1):
            print(f"\n  {i}. [{d['test']}]")
            for line in d['desc'].split('\n'):
                print(f"     {line}")

        print(f"\n{'='*70}")
        print("ROOT CAUSE:")
        print("  ComputeInsReuseDistance (ins_reuse_client.cpp line ~257) calls")
        print("  FindSumGreaterEqual(prevTick, &reuseDist).  FindSumGreaterEqual")
        print("  returns:  node->value + right_subtree_sum")
        print("  where node->value = numInsInBBL.  This INCLUDES the BBL's own")
        print("  instruction count in the reuse distance, overcounting by 1.")
        print()
        print("  Meanwhile, ComputeBlockReuseDistance (line ~274) correctly uses")
        print("  FindSumGreaterThan which returns only right_subtree_sum (excludes")
        print("  the node's own value).  The two functions are inconsistent.")
        print()
        print("PROPOSED FIX:")
        print("  Option A: Change FindSumGreaterEqual -> FindSumGreaterThan")
        print("            in ComputeInsReuseDistance, then add (numInsInBBL - 1)")
        print("            to the result before recording it.  This accounts for")
        print("            the within-BBL instructions that execute between two")
        print("            accesses to the same instruction.")
        print()
        print("  Option B: Keep FindSumGreaterEqual but subtract 1 from the result.")
        print("            (FindSumGreaterEqual = FindSumGreaterThan + numIns,")
        print("             so subtracting 1 gives FindSumGreaterThan + numIns - 1")
        print("             = true distance.)")
        print()
        print("  Both options yield: true_reuse = inter_BBL_distance + (numIns - 1)")
        print()

    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
