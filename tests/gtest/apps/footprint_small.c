// Footprint victim: SMALL footprint. Load from the SAME 8-byte address
// many times. Total instructions high, but unique addresses touched: 1.
//
// Inline asm so the compiler cannot lift the load out of the loop --
// each `movq (%rax), %rax` reads memory anew every iteration.
#include <stdint.h>

static volatile uint64_t sink;
static uint64_t buf[8];

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    buf[0] = 0xDEADBEEF;
    volatile uint64_t* p = &buf[0];
    uint64_t acc = 0;

    for (int i = 0; i < 100000; ++i) {
        uint64_t v;
        __asm__ __volatile__ ("movq (%1), %0" : "=r"(v) : "r"(p) : "memory");
        acc += v;
    }
    sink = acc;
    return 0;
}
