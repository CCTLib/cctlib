// runtime_value_numbering true-negative: two computations that produce
// DIFFERENT values (different operands per iteration). RVN should NOT
// classify these as redundant.
#include <stdint.h>

static volatile uint64_t sink;

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    uint64_t a = 0x1234;
    uint64_t sum1 = 0, sum2 = 0;
    for (int i = 0; i < 100000; ++i) {
        uint64_t b = (uint64_t)i;   // b changes every iteration
        uint64_t c = (uint64_t)(i * 3 + 7);
        __asm__ __volatile__ (
            "leaq (%[a], %[b]), %[s1]\n\t"
            "leaq (%[a], %[c]), %[s2]\n\t"
            : [s1] "=r"(sum1), [s2] "=r"(sum2)
            : [a] "r"(a), [b] "r"(b), [c] "r"(c)
            :
        );
        sink = sum1 + sum2;
    }
    return 0;
}
