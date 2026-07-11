// redspy ISA test: back-to-back 32B AVX stores of the SAME ymm value.
#include <stdint.h>
#define WORK_COUNT 10000
static volatile uint64_t sink;
static uint64_t buf[4] __attribute__((aligned(32)));
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    __asm__ __volatile__("vpcmpeqd %%ymm0, %%ymm0, %%ymm0" : : : "ymm0");
    for (int i = 0; i < WORK_COUNT; ++i) {
        __asm__ __volatile__(
            "vmovdqu %%ymm0, (%0)\n\t"
            "vmovdqu %%ymm0, (%0)\n\t"   // same value -- redundant
            :
            : "r"(buf)
            : "memory", "ymm0");
    }
    sink = buf[0];
    return 0;
}
