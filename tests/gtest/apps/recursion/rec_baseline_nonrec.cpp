// Control: purely iterative workload, no recursion. Locks in the
// zero-overhead-on-non-recursive-path contract from constraint #1 of
// the design. If this test's report diverges from the pre-change
// baseline for any of the three clients, we introduced runtime cost
// (or worse, a correctness bug) on code that doesn't recurse at all.
//
// The test that consumes this victim compares only "runs cleanly"
// today; byte-identical report validation across the whole suite is
// covered by the deadspy/redspy/loadspy integration tests already in
// the tree -- adding one more recursion-free workload here ensures
// the recursion classifier's presence doesn't shift attribution for
// non-recursive code.
#include <cstdint>
#include <cstdio>

static volatile uint64_t sink;
static uint64_t buf[4096];

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    for (int outer = 0; outer < 1000; ++outer) {
        for (int i = 0; i < 4096; ++i) {
            buf[i] = (uint64_t)outer * (uint64_t)i;
        }
        for (int i = 0; i < 4096; ++i) {
            sink ^= buf[i];
        }
    }
    fprintf(stderr, "rec_baseline_nonrec: sink=%llx\n",
            (unsigned long long)sink);
    return 0;
}
