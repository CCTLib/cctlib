// footprint ISA test: AVX 32-byte stride sweep.
// Each iteration issues one 32B AVX store to a NEW address (stride 32B).
// N=100000 unique 32B slots => footprint should be at least 100000 * 32 /
// (footprint's unit) bytes distinct addresses.
//
// This exercises footprint tracking under wide SIMD stores that touch
// multiple bytes per instruction.
#include <stdint.h>
#define N 100000
static volatile uint64_t sink;
static uint64_t buf[N * 4] __attribute__((aligned(32)));
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    for (int i = 0; i < N; ++i) {
        __asm__ __volatile__(
            "vmovdqu %%ymm0, (%0)\n\t"   // 32B store to a fresh cacheline
            :
            : "r"(&buf[i * 4])
            : "memory", "ymm0");
    }
    sink = buf[0];
    return 0;
}
