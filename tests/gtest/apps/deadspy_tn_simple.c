// True-negative victim: same total number of stores, but each pair of
// writes to a cell has an intervening READ, so neither write is dead.
//
// Anti-optimization measures match the TP program so the two are directly
// comparable.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define WORK_COUNT 10000

static volatile uint64_t sink;

__attribute__((noinline)) void store8(volatile uint64_t* p, uint64_t v) {
    *p = v;
}
__attribute__((noinline)) uint64_t load8(volatile uint64_t* p) {
    return *p;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    uint64_t buf[WORK_COUNT];
    for (int i = 0; i < WORK_COUNT; ++i) buf[i] = 0xAAULL;

    uint64_t s = 0;
    for (int i = 0; i < WORK_COUNT; ++i) {
        store8(&buf[i], 1);
        s += load8(&buf[i]);         // reads buf[i], so the previous write is USED, not dead
        store8(&buf[i], 2);
        s += load8(&buf[i]);         // ditto
    }

    sink = s;
    return 0;
}
