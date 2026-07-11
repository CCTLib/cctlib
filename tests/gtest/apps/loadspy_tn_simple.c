// True-negative victim for loadspy: an intervening store between the two
// loads invalidates redundancy tracking. Each pair does load-store-load.
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
        store8(&buf[i], (uint64_t)(i * 3 + 1));   // intervening store: kills redundancy
        s += load8(&buf[i]);
    }

    sink = s;
    return 0;
}
