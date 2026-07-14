// Same body as fib_deep but built with -s (symbols stripped). Validates
// that the classifier works on decoded CALL immediates alone -- it must
// NOT depend on RTN_Name/RTN_Size/anything symbol-derived. If a
// stripped binary regresses, cctlib collapses only when it can name
// the function -- exactly the kind of fragile behavior the design
// rejected in favor of exact-address sets.
#include <cstdint>
#include <cstdio>

static volatile int64_t sink;

static int64_t fib(int n) {
    if (n < 2) return n;
    return fib(n - 1) + fib(n - 2);
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    int64_t r = fib(14);
    sink ^= r;
    fprintf(stderr, "rec_stripped: fib(14)=%lld sink=%llx\n",
            (long long)r, (unsigned long long)sink);
    return r == 377 ? 0 : 1;
}
