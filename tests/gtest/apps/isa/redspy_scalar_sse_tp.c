// Redspy ISA edge case: scalar SSE movsd (double-precision scalar move).
// movsd writes 8 bytes; two identical movsd to same address is redundant.
// Different instruction encoding path from the general-purpose movq;
// exercises the SSE scalar path.
#include <stdint.h>
#define WORK_COUNT 10000
static volatile uint64_t sink;
static double buf[WORK_COUNT] __attribute__((aligned(16)));
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    for (int i = 0; i < WORK_COUNT; ++i) {
        // Load 3.14 into xmm0, store it twice via scalar movsd.
        __asm__ __volatile__(
            "movsd %[val], %%xmm0\n\t"      // xmm0 = val
            "movsd %%xmm0, (%[p])\n\t"      // 8B write
            "movsd %%xmm0, (%[p])\n\t"      // 8B write same value -- redundant
            :
            : [val] "m"(buf[i]), [p] "r"(&buf[i])
            : "memory", "xmm0");
    }
    sink = (uint64_t)buf[0];
    return 0;
}
