// deadspy ISA test: back-to-back 32B AVX stores. Hits RecordLargeMemWrite
// with size=32.
#include <stdint.h>
#define WORK_COUNT 10000
static volatile uint64_t sink;
static uint64_t buf[4] __attribute__((aligned(32)));
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    for (int i = 0; i < WORK_COUNT; ++i) {
        __asm__ __volatile__(
            "vmovdqu %%ymm0, (%0)\n\t"
            "vmovdqu %%ymm1, (%0)\n\t"
            :
            : "r"(buf)
            : "memory", "ymm0", "ymm1");
    }
    sink = buf[0];
    return 0;
}
