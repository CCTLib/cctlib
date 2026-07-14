// Three static direct self-call sites in three different basic blocks
// of the same routine. Each site's INS_NextAddress differs. Verifies
// that MaybeGoUpCallChain's per-routine set correctly enumerates all
// N return addresses -- a bug that matched only one would corrupt the
// CCT on returns from the other two sites.
//
// Structure: multi(n) picks one of three recursive descents based on
// n%3, driving the interpreter through every self-call site over many
// iterations. Each site does slightly different arithmetic so the
// compiler can't fold them together.
#include <cstdint>
#include <cstdio>

static volatile uint64_t sink;

static uint64_t multi(int n) {
    if (n <= 0) return 1;
    if ((n % 3) == 0) {
        uint64_t a = multi(n - 1);           // site 1
        return a + 1;
    } else if ((n % 3) == 1) {
        uint64_t b = multi(n - 1);           // site 2
        return b * 2;
    } else {
        uint64_t c = multi(n - 1);           // site 3
        return c ^ 3;
    }
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    // depth of 15 -> 15 recursive activations cycling through all 3
    // sites. Kept under cctlib's MAX_CCT_PRINT_DEPTH=20 so the shape
    // check remains sensitive when collapse is disabled.
    uint64_t r = multi(15);
    sink ^= r;
    fprintf(stderr, "rec_multi_direct: multi(15)=%llu sink=%llx\n",
            (unsigned long long)r, (unsigned long long)sink);
    return 0;
}
