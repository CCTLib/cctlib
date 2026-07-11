// Redspy ISA edge case: SIMD zero-fill (common redundancy pattern in
// real-world code). pxor xmm, xmm zeroes an xmm register, then movdqu
// writes 16 zero bytes to memory. Doing this twice to the same address
// writes the SAME 16 zero bytes -> second is redundant.
//
// The common real-world pattern this reflects: initializing memory to
// zero by calling memset(buf, 0, N) then writing zeros again (defensive
// double-clear, or two callers along the same code path).
#include <stdint.h>
#define WORK_COUNT 10000
static volatile uint64_t sink;
static uint64_t buf[2] __attribute__((aligned(16)));
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    for (int i = 0; i < WORK_COUNT; ++i) {
        __asm__ __volatile__(
            "pxor %%xmm0, %%xmm0\n\t"       // xmm0 = 0
            "movdqu %%xmm0, (%[p])\n\t"     // 16B zero write
            "movdqu %%xmm0, (%[p])\n\t"     // 16B zero write again -- redundant
            :
            : [p] "r"(buf)
            : "memory", "xmm0");
    }
    sink = buf[0];
    return 0;
}
