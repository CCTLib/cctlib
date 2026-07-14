// Ackermann function: A(3, 4) has stack depth ~11 and exercises deep
// single-argument recursion with two direct self-call sites in the
// m>0 branches. Kept under cctlib's MAX_CCT_PRINT_DEPTH=20 so the
// shape-check assertion isn't blunted by chain truncation when the
// collapse mechanism is intentionally disabled for the sensitivity
// test. Fib is high-branching-low-depth; Ackermann is low-branching-
// high-depth. Both must collapse to O(1) TraceNodes for the routine.
#include <cstdint>
#include <cstdio>

static volatile uint64_t sink;

static uint64_t A(uint64_t m, uint64_t n) {
    if (m == 0) return n + 1;
    if (n == 0) return A(m - 1, 1);
    return A(m - 1, A(m, n - 1));
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    uint64_t r = A(3, 4);
    sink ^= r;
    fprintf(stderr, "rec_ackermann: A(3,4)=%llu sink=%llx\n",
            (unsigned long long)r, (unsigned long long)sink);
    return r == 125 ? 0 : 1;
}
