// redspy ISA test: back-to-back 16B SSE stores of the SAME xmm register
// value. The second store is redundant.
#include <stdint.h>
#include <string.h>
#define WORK_COUNT 10000
static volatile uint64_t sink;
static uint64_t buf[2] __attribute__((aligned(16)));
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    // Prime xmm0 with a known pattern.
    __asm__ __volatile__("pcmpeqb %%xmm0, %%xmm0" : : : "xmm0");
    for (int i = 0; i < WORK_COUNT; ++i) {
        __asm__ __volatile__(
            "movdqa %%xmm0, (%0)\n\t"
            "movdqa %%xmm0, (%0)\n\t"   // same value -- redundant
            :
            : "r"(buf)
            : "memory", "xmm0");
    }
    sink = buf[0];
    return 0;
}
