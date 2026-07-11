// Deadspy ISA test: PREFETCH must not clear the "was-written" shadow.
//
// Prefetch has no architectural effect on program state -- it only hints
// to the hardware cache. If deadspy treated prefetch as a real read, it
// would erase the "was-written" marker set by a preceding store, so the
// following store to the same address would be missed as a dead write.
//
// Per iteration:
//   movq  %[v], (%[p])        // store #1 -- kills prime
//   prefetcht0 (%[p])         // prefetch -- MUST NOT clear shadow
//   movq  %[v], (%[p])        // store #2 -- kills store #1
//
// Prime is one memset, so per iter we expect 2 * 8B dead writes:
//   * store #1 kills prime
//   * store #2 kills store #1
// 20000 iters * 16B = 320000 dead bytes.
//
// The gtest threshold picks a value well above baseline noise but below
// the expected 320K, so a regression that lets prefetch clear the shadow
// (dropping the workload dead to 0) trips the test.
#include <stdint.h>
#include <string.h>
#define WORK_COUNT 20000
static volatile uint64_t sink;
static uint64_t buf[WORK_COUNT];
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    memset(buf, 0xAA, sizeof(buf));  // prime
    for (int i = 0; i < WORK_COUNT; ++i) {
        uint64_t v = 0x11;
        __asm__ __volatile__(
            "movq       %[v], (%[p])\n\t"
            "prefetcht0 (%[p])\n\t"
            "movq       %[v], (%[p])\n\t"
            :
            : [p] "r"(&buf[i]), [v] "r"(v)
            : "memory");
    }
    sink = buf[0];
    return 0;
}
