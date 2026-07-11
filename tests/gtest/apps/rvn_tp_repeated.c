// runtime_value_numbering victim: recompute the SAME arithmetic expression
// twice with the same operands. RVN should identify the second computation
// as producing the same value number as the first -- redundant.
//
// Inline asm keeps the compiler from folding the two operations into one.
#include <stdint.h>

static volatile uint64_t sink;

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    uint64_t a = 0x1234, b = 0x5678;
    uint64_t sum1 = 0, sum2 = 0;
    for (int i = 0; i < 100000; ++i) {
        // Two identical add-lea instructions on identical operands.
        // rvn should notice sum2 comes out with the same value number as sum1.
        __asm__ __volatile__ (
            "leaq (%[a], %[b]), %[s1]\n\t"
            "leaq (%[a], %[b]), %[s2]\n\t"
            : [s1] "=r"(sum1), [s2] "=r"(sum2)
            : [a] "r"(a), [b] "r"(b)
            :
        );
        sink = sum1 + sum2;
    }
    return 0;
}
