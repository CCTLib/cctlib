// Basic C++ exception: single throw, single catch, three-level unwind.
// Exercises cctlib's exception path with the simplest possible pattern.
//
// simple_try_marker (called just before the throw inside the try block)
// and simple_catch_marker (called inside the catch handler) let the
// shape-check tool assert that both are direct children of main -- NOT
// rooted somewhere under __cxa_throw's subtree.
#include <cstdint>
#include <cstdio>
#define N 5000
static volatile uint64_t sink;
static uint64_t buf[N];

extern "C" __attribute__((noinline)) void simple_try_marker(int i) {
    __asm__ __volatile__("" ::: "memory");
    sink ^= (uint64_t)i;
}
extern "C" __attribute__((noinline)) void simple_catch_marker(int i) {
    __asm__ __volatile__("" ::: "memory");
    sink ^= (uint64_t)i << 8;
}

static void inner(int i) {
    buf[i] = 0xAA;
    throw i;
}
static void middle(int i) { inner(i); buf[i] = 0xBB; /* never reached */ }
static void outer(int i) { middle(i); buf[i] = 0xCC; /* never reached */ }

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    int caught = 0;
    for (int i = 0; i < N; ++i) buf[i] = 0x11;   // prime
    for (int i = 0; i < N; ++i) {
        try {
            simple_try_marker(i);  // in-try, non-throwing marker
            outer(i);
        } catch (int v) {
            simple_catch_marker(i);  // in-catch marker
            caught += v == i;
            buf[i] = 0xDD;   // post-unwind write, tool must record correctly
        }
    }
    for (int i = 0; i < N; ++i) sink ^= buf[i];
    fprintf(stderr, "exc_simple_throw: caught=%d expected=%d sink=%llx\n",
            caught, N, (unsigned long long)sink);
    return caught == N ? 0 : 1;
}
