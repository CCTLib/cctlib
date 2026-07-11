// Deadspy ISA edge case: non-temporal MOVNTI store.
// Non-temporal stores bypass the cache hierarchy but are still WRITES
// from the ISA's perspective. Deadspy should track them the same as any
// other store. Two back-to-back MOVNTI to the same address makes the
// first dead.
#include <stdint.h>
#define WORK_COUNT 10000
static volatile uint64_t sink;
static uint64_t buf[WORK_COUNT] __attribute__((aligned(16)));
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    for (int i = 0; i < WORK_COUNT; ++i) {
        uint64_t v1 = 0x1234, v2 = 0x5678;
        __asm__ __volatile__(
            "movnti %[v1], (%[p])\n\t"
            "movnti %[v2], (%[p])\n\t"   // dead
            "sfence\n\t"                 // required after MOVNT to enforce order
            :
            : [p] "r"(&buf[i]), [v1] "r"(v1), [v2] "r"(v2)
            : "memory");
    }
    sink = buf[0];
    return 0;
}
