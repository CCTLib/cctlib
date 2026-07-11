// True-positive victim for loadspy: two consecutive loads from the same
// address with NO intervening store. The second load reads the SAME value
// that the first load produced -- redundant.
#include <stdint.h>

#define WORK_COUNT 100000

static volatile uint64_t sink;
static uint64_t buf[WORK_COUNT];  // static: BSS, not stack

__attribute__((noinline)) uint64_t load8(volatile uint64_t* p) { return *p; }
__attribute__((noinline)) void      store8(volatile uint64_t* p, uint64_t v) { *p = v; }

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    for (int i = 0; i < WORK_COUNT; ++i) store8(&buf[i], (uint64_t)i);

    uint64_t s = 0;
    for (int i = 0; i < WORK_COUNT; ++i) {
        s += load8(&buf[i]);
        s += load8(&buf[i]);   // redundant load: same value, no intervening store
    }

    sink = s;
    return 0;
}
