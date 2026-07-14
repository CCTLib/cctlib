// High-frequency exception loop. Exercises the resolver's static caching
// (g_appUnwindGetIP) and asserts that repeated exception CCT unwinds do
// not corrupt cctlib state. ITERS bounded so the CCT still fits under
// Pin's recursive VisitAllNodesOfSplayTree stack budget at Fini.
//
// stress_try_marker / stress_catch_marker verify both markers are direct
// children of main across many iterations (regression: pending-reset
// state must not drift as CCT accumulates).
#include <cstdint>
#include <cstdio>
#define ITERS 5000
static volatile uint64_t sink;

extern "C" __attribute__((noinline)) void stress_try_marker(uint64_t i) {
    __asm__ __volatile__("" ::: "memory"); sink ^= i;
}
extern "C" __attribute__((noinline)) void stress_catch_marker(uint64_t i) {
    __asm__ __volatile__("" ::: "memory"); sink ^= i << 8;
}

static void thrower(uint64_t v) { throw v; }

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    uint64_t sum = 0;
    for (uint64_t i = 0; i < ITERS; ++i) {
        try {
            stress_try_marker(i);
            thrower(i * 3);
        } catch (uint64_t v) {
            stress_catch_marker(i);
            sum += v;
        }
    }
    sink = sum;
    fprintf(stderr, "exc_stress_loop: iters=%d sum=%llu\n", ITERS,
            (unsigned long long)sum);
    return sum == (uint64_t)ITERS * (ITERS - 1) / 2 * 3 ? 0 : 1;
}
