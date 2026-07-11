// ins_reuse ISA test: SIMD tight loop.
// Two-instruction inline-asm loop with SIMD instructions. Each SIMD op
// reuses the same instruction at distance 2, so the reuse histogram
// should peak in bin 1 or 2.
#include <stdint.h>
static volatile uint64_t sink;
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    uint64_t n = 1000000;
    __asm__ __volatile__(
        "vpxor %%ymm0, %%ymm0, %%ymm0\n\t"
        ".p2align 4\n"
        "1:\n\t"
        "vpaddq %%ymm0, %%ymm0, %%ymm0\n\t"
        "subq $1, %[n]\n\t"
        "jnz 1b\n\t"
        : [n] "+r"(n)
        :
        : "cc", "ymm0"
    );
    sink = n;
    return 0;
}
