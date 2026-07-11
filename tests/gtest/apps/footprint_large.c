// Footprint victim: LARGE footprint. Load from N distinct addresses in a
// stride-1 sweep so each iteration touches a fresh 8-byte slot.
#include <stdint.h>

#define N 100000

static volatile uint64_t sink;
static uint64_t buf[N];

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    // Prime.
    for (int i = 0; i < N; ++i) buf[i] = (uint64_t)i;

    uint64_t acc = 0;
    for (int i = 0; i < N; ++i) {
        volatile uint64_t* p = &buf[i];
        uint64_t v;
        __asm__ __volatile__ ("movq (%1), %0" : "=r"(v) : "r"(p) : "memory");
        acc += v;
    }
    sink = acc;
    return 0;
}
