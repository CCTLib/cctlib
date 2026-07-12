// Basic C++ exception: single throw, single catch, three-level unwind.
// Exercises cctlib's exception path with the simplest possible pattern.
#include <cstdint>
#include <cstdio>
#define N 5000
static volatile uint64_t sink;
static uint64_t buf[N];

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
            outer(i);
        } catch (int v) {
            caught += v == i;
            buf[i] = 0xDD;   // post-unwind write, tool must record correctly
        }
    }
    for (int i = 0; i < N; ++i) sink ^= buf[i];
    fprintf(stderr, "exc_simple_throw: caught=%d expected=%d sink=%llx\n",
            caught, N, (unsigned long long)sink);
    return caught == N ? 0 : 1;
}
