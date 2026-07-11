// True-positive victim: two consecutive writes to the same memory location
// with NO intervening read. Every second write is a dead write.
//
// Anti-optimization measures:
//   - `volatile` to prevent the compiler from collapsing the two stores
//   - `-O0` in the test build
//   - external function calls between phases so the compiler can't reorder
//
// The program deliberately does WORK_COUNT iterations of a paired
// write-write so a machine-tested threshold can catch regressions.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define WORK_COUNT 10000

static volatile uint64_t sink;

// Force a store the compiler can't elide.
__attribute__((noinline)) void store8(volatile uint64_t* p, uint64_t v) {
    *p = v;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    uint64_t buf[WORK_COUNT];
    // Prime buf to non-zero so the FIRST write of each pair definitely
    // overwrites a previously-written cell (making it dead once the
    // SECOND write happens).
    for (int i = 0; i < WORK_COUNT; ++i) buf[i] = 0xAAULL;

    for (int i = 0; i < WORK_COUNT; ++i) {
        store8(&buf[i], 1);          // dead: overwritten below with no read between
        store8(&buf[i], 2);          // this is the survivor
    }

    // Publish a checksum so DCE doesn't kill the loop.
    uint64_t s = 0;
    for (int i = 0; i < WORK_COUNT; ++i) s += buf[i];
    sink = s;
    return 0;
}
