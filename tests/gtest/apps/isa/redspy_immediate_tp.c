// redspy ISA test: repeatedly write the SAME 32-bit immediate to the same
// dword. The second store is redundant (same value already at address).
// Exercises immediate-operand instrumentation.
#include <stdint.h>
#define WORK_COUNT 20000
static volatile uint64_t sink;
static uint32_t buf[WORK_COUNT];
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    for (int i = 0; i < WORK_COUNT; ++i) {
        __asm__ __volatile__(
            "movl $0xC0FFEE, (%0)\n\t"
            "movl $0xC0FFEE, (%0)\n\t"   // same immediate -- redundant
            :
            : "r"(&buf[i])
            : "memory");
    }
    sink = buf[0];
    return 0;
}
