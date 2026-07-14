// Canonical direct self-recursion: naive Fibonacci. fib() contains two
// direct calls to itself; the classifier must see both, populate
// selfRecReturnAddrs with the return address after each call, and fold
// every recursive activation into a single TraceNode. fib(15) exercises
// depth 16 (comfortably under cctlib's MAX_CCT_PRINT_DEPTH=20 so the
// sensitivity of the shape assertion isn't blunted by chain truncation
// when the collapse mechanism is intentionally disabled).
#include <cstdint>
#include <cstdio>

static volatile int64_t sink;

static int64_t fib(int n) {
    if (n < 2) return n;
    return fib(n - 1) + fib(n - 2);
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    int64_t r = fib(15);
    sink ^= r;
    fprintf(stderr, "rec_fib_deep: fib(15)=%lld sink=%llx\n",
            (long long)r, (unsigned long long)sink);
    return r == 610 ? 0 : 1;
}
