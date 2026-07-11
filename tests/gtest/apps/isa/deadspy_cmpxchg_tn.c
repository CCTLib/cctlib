// Deadspy ISA edge case: LOCK CMPXCHG.
//
// This is a TRUE-NEGATIVE test. cmpxchg is a read-modify-write: it always
// reads the memory operand (to compare against RAX). Even when the second
// cmpxchg's compare succeeds (both stores happen), the intervening READ
// by the second cmpxchg CLEARS the shadow "was written" bit that the
// first cmpxchg set -- so deadspy should NOT report the first write as
// dead.
//
// Contrast this with XCHG (deadspy_xchg_tp.c): Pin classifies XCHG's
// memory operand as write-only (empirically), so deadspy sees two
// consecutive writes with no intervening read -> DOES report dead.
//
// The test that consumes this victim asserts the delta over baseline is
// SMALL (bounded above), verifying deadspy correctly does NOT
// false-positive on RMW instructions that read before they write.
#include <stdint.h>
#define WORK_COUNT 10000
static volatile uint64_t sink;
static uint64_t buf[WORK_COUNT];
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    for (int i = 0; i < WORK_COUNT; ++i) buf[i] = 0xAAAAAAAAULL;

    for (int i = 0; i < WORK_COUNT; ++i) {
        uint64_t expected = 0xAAAAAAAAULL;
        uint64_t desired  = 0xBBBBBBBBULL;
        uint64_t desired2 = 0xCCCCCCCCULL;
        __asm__ __volatile__(
            "movq %[e], %%rax\n\t"
            "lock cmpxchgq %[d], (%[p])\n\t"     // rmw: read+write
            "movq %[d], %%rax\n\t"
            "lock cmpxchgq %[d2], (%[p])\n\t"    // rmw: read (clears dead) + write
            :
            : [p] "r"(&buf[i]), [e] "r"(expected), [d] "r"(desired), [d2] "r"(desired2)
            : "memory", "cc", "rax");
    }
    sink = buf[0];
    return 0;
}
