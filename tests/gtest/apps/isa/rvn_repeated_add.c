// RVN ISA test: repeated identical scalar ADD on same operands. The
// second addq should get the same value number as the first (both
// compute a+b for the same a, b).
#include <stdint.h>
static volatile uint64_t sink;
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    uint64_t s = 0;
    uint64_t a = 0x1234, b = 0x5678;
    for (int i = 0; i < 100000; ++i) {
        uint64_t r1, r2;
        __asm__ __volatile__(
            "movq %[a], %[r1]\n\t"
            "addq %[b], %[r1]\n\t"
            "movq %[a], %[r2]\n\t"
            "addq %[b], %[r2]\n\t"   // same value as r1 -- redundant
            : [r1] "=&r"(r1), [r2] "=&r"(r2)
            : [a] "r"(a), [b] "r"(b)
            :
        );
        s += r1 + r2;
    }
    sink = s;
    return 0;
}
