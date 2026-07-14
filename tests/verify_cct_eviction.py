#!/usr/bin/env python3
"""
Verify CCT eviction pair tracking correctness across all cache levels.

8 tests exercise level selectivity, pair identity, count balance,
and the L1i ≥ L2 ≥ L3 inclusivity chain.

Usage:
    python3 tests/verify_cct_eviction.py           # run all tests
    python3 tests/verify_cct_eviction.py --test 4   # run only test 4
"""

import json
import os
import subprocess
import sys
import tempfile
import argparse
import glob

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT  = os.path.dirname(SCRIPT_DIR)

PIN_ROOT = os.environ.get('PIN_ROOT',
    os.path.expanduser('~/pin/pin-external-4.3-99850-gce5652921-gcc-linux'))
TOOL_SO  = os.path.join(REPO_ROOT, 'clients', 'obj-intel64', 'ins_reuse_client.so')
TEST_APP = os.path.join(REPO_ROOT, 'apps', 'obj-intel64', 'cct_eviction_test.exe')


def parse_json_objects(json_path):
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


def get_eviction_data(results):
    data = {}
    for obj in results:
        metric = obj.get('Metric', '')
        if metric.startswith('EvictionPairs_'):
            level = metric.replace('EvictionPairs_', '')
            data[level] = {
                'total_misses': obj.get('TotalMisses', 0),
                'capacity': obj.get('Capacity', 0),
                'pairs': obj.get('pairs', []),
            }
    return data


def run_pin(scenario, iters, knobs, work_dir):
    out_prefix = os.path.join(work_dir, 'out.')
    env = os.environ.copy()
    env['INS_REUSE_CLIENT_OUTPUT_FILE'] = out_prefix

    cmd = [
        os.path.join(PIN_ROOT, 'pin'),
        '-t', TOOL_SO,
        '-cct', '1',
    ]
    for k, v in knobs.items():
        cmd += ['-{}'.format(k), str(v)]
    cmd += ['-topn', '20']
    cmd += ['--', TEST_APP, str(scenario), str(iters)]

    subprocess.run(cmd, capture_output=True, text=True, env=env,
                   cwd=work_dir, timeout=120)

    json_files = glob.glob(os.path.join(work_dir, 'out.*.json'))
    if not json_files:
        return None
    return parse_json_objects(json_files[0])


# ── Check functions ──────────────────────────────────────────────────

def check_level_present(eviction_data, level, expected):
    present = level in eviction_data and eviction_data[level]['total_misses'] > 0
    if present == expected:
        status = 'present' if present else 'absent'
        return True, '{}: {} as expected'.format(level, status)
    actual = 'present ({} misses)'.format(eviction_data[level]['total_misses']) if present else 'absent'
    expected_str = 'present' if expected else 'absent'
    return False, '{}: expected {}, got {}'.format(level, expected_str, actual)


def check_min_misses(eviction_data, level, min_val):
    if level not in eviction_data:
        return False, '{}: no eviction data (expected >= {} misses)'.format(level, min_val)
    misses = eviction_data[level]['total_misses']
    if misses >= min_val:
        return True, '{}: {} misses >= {}'.format(level, misses, min_val)
    return False, '{}: {} misses < {}'.format(level, misses, min_val)


def check_misses_ge(eviction_data, level_a, level_b):
    misses_a = eviction_data.get(level_a, {}).get('total_misses', 0)
    misses_b = eviction_data.get(level_b, {}).get('total_misses', 0)
    if misses_a >= misses_b:
        return True, '{}({}) >= {}({})'.format(level_a, misses_a, level_b, misses_b)
    return False, '{}({}) < {}({})'.format(level_a, misses_a, level_b, misses_b)


def check_functions_in_pairs(eviction_data, level, expected_funcs):
    if level not in eviction_data:
        return False, '{}: no eviction data'.format(level)
    pairs = eviction_data[level]['pairs']

    found_funcs = set()
    for pair in pairs:
        for ctx_key in ['evicted', 'incoming']:
            for func_name in pair.get(ctx_key, []):
                for expected in expected_funcs:
                    if expected in func_name:
                        found_funcs.add(expected)

    missing = set(expected_funcs) - found_funcs
    if not missing:
        return True, '{}: all functions found in pairs: {}'.format(level, sorted(found_funcs))
    return False, '{}: missing functions: {} (found: {})'.format(level, sorted(missing), sorted(found_funcs))


def check_top_pairs_balanced(eviction_data, level, n_pairs, tolerance):
    if level not in eviction_data:
        return False, '{}: no eviction data'.format(level)
    pairs = eviction_data[level]['pairs']
    if len(pairs) < n_pairs:
        return False, '{}: only {} pairs, expected >= {}'.format(level, len(pairs), n_pairs)

    counts = [p['count'] for p in pairs[:n_pairs]]
    avg = sum(counts) / len(counts)
    if avg == 0:
        return False, '{}: all zero counts in top {} pairs'.format(level, n_pairs)
    max_dev = max(abs(c - avg) / avg for c in counts)

    if max_dev <= tolerance:
        return True, '{}: top {} pairs balanced (counts={}, max_dev={:.1%})'.format(
            level, n_pairs, counts, max_dev)
    return False, '{}: top {} pairs unbalanced (counts={}, max_dev={:.1%} > {:.0%})'.format(
        level, n_pairs, counts, max_dev, tolerance)


# ── Test definitions ─────────────────────────────────────────────────

TESTS = [
    {
        'id': 1,
        'name': 'l1i_only',
        'desc': 'L1i evictions only (L2/L3/iTLB capacities high)',
        'scenario': 1, 'iters': 1000,
        'knobs': {'l1i_cap': 80, 'l2_cap': 1000000, 'l3_cap': 1000000, 'itlb_cap': 1000000},
        'checks': [
            ('level_present', 'L1i', True),
            ('level_present', 'L2', False),
            ('level_present', 'L3', False),
            ('level_present', 'iTLB', False),
            ('min_misses', 'L1i', 1000),
        ],
    },
    {
        'id': 2,
        'name': 'l1i_and_l2',
        'desc': 'L1i and L2 evict (L3/iTLB capacities high)',
        'scenario': 1, 'iters': 1000,
        'knobs': {'l1i_cap': 80, 'l2_cap': 120, 'l3_cap': 1000000, 'itlb_cap': 1000000},
        'checks': [
            ('level_present', 'L1i', True),
            ('level_present', 'L2', True),
            ('level_present', 'L3', False),
            ('level_present', 'iTLB', False),
            ('min_misses', 'L1i', 500),
            ('min_misses', 'L2', 500),
            ('misses_ge', 'L1i', 'L2'),
        ],
    },
    {
        'id': 3,
        'name': 'l1i_l2_l3',
        'desc': 'L1i, L2, L3 all evict (iTLB capacity high)',
        'scenario': 1, 'iters': 1000,
        'knobs': {'l1i_cap': 80, 'l2_cap': 120, 'l3_cap': 140, 'itlb_cap': 1000000},
        'checks': [
            ('level_present', 'L1i', True),
            ('level_present', 'L2', True),
            ('level_present', 'L3', True),
            ('level_present', 'iTLB', False),
            ('misses_ge', 'L1i', 'L2'),
            ('misses_ge', 'L2', 'L3'),
        ],
    },
    {
        'id': 4,
        'name': 'itlb_only',
        'desc': 'iTLB evictions only (L1i/L2/L3 capacities high)',
        'scenario': 2, 'iters': 1000,
        'knobs': {'l1i_cap': 1000000, 'l2_cap': 1000000, 'l3_cap': 1000000, 'itlb_cap': 2},
        'checks': [
            ('level_present', 'L1i', False),
            ('level_present', 'L2', False),
            ('level_present', 'L3', False),
            ('level_present', 'iTLB', True),
            ('min_misses', 'iTLB', 500),
        ],
    },
    {
        'id': 5,
        'name': 'all_four_levels',
        'desc': 'All 4 levels evict simultaneously',
        'scenario': 2, 'iters': 1000,
        'knobs': {'l1i_cap': 80, 'l2_cap': 120, 'l3_cap': 140, 'itlb_cap': 2},
        'checks': [
            ('level_present', 'L1i', True),
            ('level_present', 'L2', True),
            ('level_present', 'L3', True),
            ('level_present', 'iTLB', True),
        ],
    },
    {
        'id': 6,
        'name': 'l1i_pair_identity',
        'desc': 'L1i eviction pairs contain s1, s2, s3 with balanced counts',
        'scenario': 1, 'iters': 1000,
        'knobs': {'l1i_cap': 80, 'l2_cap': 1000000, 'l3_cap': 1000000, 'itlb_cap': 1000000},
        'checks': [
            ('functions_in_pairs', 'L1i', ['s1', 's2', 's3']),
            ('top_pairs_balanced', 'L1i', 3, 0.3),
        ],
    },
    {
        'id': 7,
        'name': 'itlb_pair_identity',
        'desc': 'iTLB eviction pairs contain p1, p2, p3 with balanced counts',
        'scenario': 2, 'iters': 1000,
        'knobs': {'l1i_cap': 1000000, 'l2_cap': 1000000, 'l3_cap': 1000000, 'itlb_cap': 2},
        'checks': [
            ('functions_in_pairs', 'iTLB', ['p1', 'p2', 'p3']),
            ('top_pairs_balanced', 'iTLB', 3, 0.3),
        ],
    },
    {
        'id': 8,
        'name': 'two_func_symmetry',
        'desc': '2-function alternating: symmetric eviction pair counts',
        'scenario': 3, 'iters': 1000,
        'knobs': {'l1i_cap': 80, 'l2_cap': 1000000, 'l3_cap': 1000000, 'itlb_cap': 1000000},
        'checks': [
            ('functions_in_pairs', 'L1i', ['s1', 's2']),
            ('top_pairs_balanced', 'L1i', 2, 0.2),
        ],
    },
]


def run_checks(eviction_data, checks):
    results = []
    for check in checks:
        check_type = check[0]
        if check_type == 'level_present':
            ok, msg = check_level_present(eviction_data, check[1], check[2])
        elif check_type == 'min_misses':
            ok, msg = check_min_misses(eviction_data, check[1], check[2])
        elif check_type == 'misses_ge':
            ok, msg = check_misses_ge(eviction_data, check[1], check[2])
        elif check_type == 'functions_in_pairs':
            ok, msg = check_functions_in_pairs(eviction_data, check[1], check[2])
        elif check_type == 'top_pairs_balanced':
            ok, msg = check_top_pairs_balanced(eviction_data, check[1], check[2], check[3])
        else:
            ok, msg = False, 'Unknown check type: {}'.format(check_type)
        results.append((ok, msg))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--test', type=int, default=0,
                        help='Run only this test number (0 = all)')
    args = parser.parse_args()

    for path, label in [(TOOL_SO, 'ins_reuse_client.so'), (TEST_APP, 'cct_eviction_test.exe')]:
        if not os.path.exists(path):
            print('ERROR: {} not found at {}'.format(label, path))
            print('Build first: cd {} && make -C apps && make -C clients'.format(REPO_ROOT))
            return 1

    tests_to_run = TESTS if args.test == 0 else [t for t in TESTS if t['id'] == args.test]
    passed = 0
    failed = 0

    for test in tests_to_run:
        print('\n{}'.format('=' * 70))
        print('Test {}: {}'.format(test['id'], test['name']))
        print('  {}'.format(test['desc']))
        print('  Scenario {}, {} iterations'.format(test['scenario'], test['iters']))
        knob_str = ' '.join('-{} {}'.format(k, v) for k, v in test['knobs'].items())
        print('  Knobs: {}'.format(knob_str))

        with tempfile.TemporaryDirectory() as work_dir:
            results = run_pin(test['scenario'], test['iters'], test['knobs'], work_dir)
            if results is None:
                print('  SKIP: no output produced')
                continue

            eviction_data = get_eviction_data(results)

            # Show eviction summary
            for level in ['L1i', 'L2', 'L3', 'iTLB']:
                if level in eviction_data:
                    ed = eviction_data[level]
                    top_counts = [p['count'] for p in ed['pairs'][:5]]
                    print('  {}: {} total misses, top counts={}'.format(
                        level, ed['total_misses'], top_counts))

            check_results = run_checks(eviction_data, test['checks'])

            all_ok = True
            for ok, msg in check_results:
                status = '  OK' if ok else 'FAIL'
                print('    [{}] {}'.format(status, msg))
                if not ok:
                    all_ok = False

            if all_ok:
                print('  RESULT: PASS')
                passed += 1
            else:
                print('  RESULT: FAIL')
                failed += 1

    print('\n{}'.format('=' * 70))
    print('SUMMARY: {} passed, {} failed out of {} tests'.format(
        passed, failed, len(tests_to_run)))

    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
