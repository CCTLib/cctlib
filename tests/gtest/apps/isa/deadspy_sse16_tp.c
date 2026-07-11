// deadspy ISA test: back-to-back 16B SSE stores to same address, no read
// between. Second store makes the first's 16 bytes dead.
//
// Hits deadspy's RecordLargeMemWrite handler (writes > 8 bytes).
#include <stdint.h>
#define WORK_COUNT 10000
static volatile uint64_t sink;
static uint64_t buf[2] __attribute__((aligned(16)));
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    for (int i = 0; i < WORK_COUNT; ++i) {
        __asm__ __volatile__(
            "movdqa %%xmm0, (%0)\n\t"
            "movdqa %%xmm1, (%0)\n\t"
            :
            : "r"(buf)
            : "memory", "xmm0", "xmm1");
    }
    sink = buf[0];
    return 0;
}
