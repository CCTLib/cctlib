// loadspy ISA test: back-to-back 32B AVX loads from same address.
#include <stdint.h>
#define WORK_COUNT 100000
static volatile uint64_t sink;
static uint64_t buf[4] __attribute__((aligned(32))) = {1, 2, 3, 4};
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    uint64_t acc = 0;
    for (int i = 0; i < WORK_COUNT; ++i) {
        __asm__ __volatile__(
            "vmovdqu (%1), %%ymm0\n\t"
            "vmovdqu (%1), %%ymm1\n\t"   // redundant 32B load
            "vmovq %%xmm0, %0\n\t"
            : "=r"(acc)
            : "r"(buf)
            : "ymm0", "ymm1", "memory");
    }
    sink = acc;
    return 0;
}
