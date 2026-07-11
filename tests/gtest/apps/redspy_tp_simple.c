// True-positive victim for redspy: write the SAME value to the same
// location twice. Redspy classifies the second write as REDUNDANT because
// the memory content did not change.
#include <stdint.h>

#define WORK_COUNT 10000

static volatile uint64_t sink;

__attribute__((noinline)) void store8(volatile uint64_t* p, uint64_t v) {
    *p = v;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    uint64_t buf[WORK_COUNT];
    for (int i = 0; i < WORK_COUNT; ++i) buf[i] = 0xAAULL;

    for (int i = 0; i < WORK_COUNT; ++i) {
        store8(&buf[i], 0xDEADBEEF);
        store8(&buf[i], 0xDEADBEEF);   // redundant: same value as previous
    }

    uint64_t s = 0;
    for (int i = 0; i < WORK_COUNT; ++i) s += buf[i];
    sink = s;
    return 0;
}
