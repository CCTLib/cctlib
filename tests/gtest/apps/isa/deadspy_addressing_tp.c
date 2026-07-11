// deadspy ISA test: various addressing modes for the killer store.
// Verifies deadspy attributes correctly regardless of how the memory
// operand is encoded (indexed, [reg+idx*8+disp]).
#include <stdint.h>
#define WORK_COUNT 20000
static volatile uint64_t sink;
static uint64_t buf[WORK_COUNT + 32];
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    for (int i = 0; i < WORK_COUNT; ++i) {
        uint64_t idx = (uint64_t)i;
        uint64_t v1 = 0x1, v2 = 0x2;
        __asm__ __volatile__(
            "movq %2, (%0, %1, 8)\n\t"     // [reg+idx*8] -- first 8B write
            "movq %3, 0(%0, %1, 8)\n\t"    // [reg+idx*8+disp8=0] -- same addr, dead
            :
            : "r"(buf), "r"(idx), "r"(v1), "r"(v2)
            : "memory");
    }
    sink = buf[0];
    return 0;
}
