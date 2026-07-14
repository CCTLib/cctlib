// Try/catch INSIDE a recursive frame. Every recursive activation of
// `rec` wraps its downward call in try{...}catch(int){rethrow;}, so the
// throw at the deepest frame propagates through every frame's catch on
// its way out to main. Exercises marker anchoring while direct-self-
// recursion collapse is active: all `rec` activations share ONE
// TraceNode, so all four in-`rec` markers must appear as direct
// children of that single `rec` node, and never as descendants of
// __cxa_throw / _Unwind_*.
//
// Markers:
//   rectry_try_marker      called in the try body BEFORE the recursive
//                          call (fires on every entering frame; parent = rec)
//   rectry_deep_marker     called at depth==0 just before the throw
//                          (parent = rec)
//   rectry_catch_marker    called in the catch body BEFORE the rethrow
//                          (fires on every unwinding frame; parent = rec)
//   rectry_after_marker    called after the try (never reached in this
//                          test -- every path either throws or rethrows;
//                          we assert it does NOT appear as a leaf so a
//                          compiler that hoisted the call would be caught)
//   rectry_outer_try       in main's try body before recurse; parent = main
//   rectry_outer_catch     in main's catch body; parent = main
//
// Choose D and ITERS so total CCT stays small (rec collapses to 1 node
// but marker leaves count linearly). D=8, ITERS=100 = 900 throws total.
#include <cstdint>
#include <cstdio>
#define D 8
#define ITERS 100
static volatile uint64_t sink;
static uint64_t buf[ITERS];

extern "C" __attribute__((noinline)) void rectry_try_marker(int i) {
    __asm__ __volatile__("" ::: "memory"); sink ^= (uint64_t)i;
}
extern "C" __attribute__((noinline)) void rectry_deep_marker(int i) {
    __asm__ __volatile__("" ::: "memory"); sink ^= (uint64_t)i << 4;
}
extern "C" __attribute__((noinline)) void rectry_catch_marker(int i) {
    __asm__ __volatile__("" ::: "memory"); sink ^= (uint64_t)i << 8;
}
extern "C" __attribute__((noinline)) void rectry_after_marker(int i) {
    __asm__ __volatile__("" ::: "memory"); sink ^= (uint64_t)i << 12;
}
extern "C" __attribute__((noinline)) void rectry_outer_try(int i) {
    __asm__ __volatile__("" ::: "memory"); sink ^= (uint64_t)i << 16;
}
extern "C" __attribute__((noinline)) void rectry_outer_catch(int i) {
    __asm__ __volatile__("" ::: "memory"); sink ^= (uint64_t)i << 20;
}

static void rec(int depth, int iter) {
    // Stack write so each frame is materialized.
    volatile uint64_t local = (uint64_t)depth * 0x101ULL + (uint64_t)iter;
    if (depth == 0) {
        rectry_deep_marker(iter);
        buf[iter] = local;
        throw iter;
    }
    try {
        rectry_try_marker(iter);
        rec(depth - 1, iter);
        rectry_after_marker(iter);   // unreached: rec always throws
    } catch (int v) {
        rectry_catch_marker(iter);
        buf[iter] ^= (uint64_t)v;
        throw;   // rethrow up to the next frame's catch
    }
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    int caught = 0;
    for (int i = 0; i < ITERS; ++i) {
        try {
            rectry_outer_try(i);
            rec(D, i);
        } catch (int v) {
            rectry_outer_catch(i);
            caught += (v == i);
        }
    }
    for (int i = 0; i < ITERS; ++i) sink ^= buf[i];
    fprintf(stderr, "exc_recurse_trycatch: depth=%d iters=%d caught=%d sink=%llx\n",
            D, ITERS, caught, (unsigned long long)sink);
    return caught == ITERS ? 0 : 1;
}
