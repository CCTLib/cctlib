// Absolute minimal victim: exactly 1 dead 8-byte write via store8, nothing else.
#include <stdint.h>

static volatile uint64_t sink;

__attribute__((noinline)) void store8(volatile uint64_t* p, uint64_t v) {
    *p = v;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    volatile uint64_t x = 0xAA;
    store8(&x, 1);
    store8(&x, 2);   // dead: the previous store to &x has not been read
    sink = x;
    return 0;
}
