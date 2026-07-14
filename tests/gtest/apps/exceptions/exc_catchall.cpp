// catch(...) exercises the general handler with a variety of thrown types:
// int, POD struct, std::string, and a class with a virtual destructor.
// Ensures the resolver reaches the exception path regardless of throw type.
//
// catchall_try_marker (in-try) and catchall_catch_marker (in-catch(...)),
// asserted to be direct children of main by the shape checks.
#include <cstdint>
#include <cstdio>
#include <string>
#define ITERS 400
static volatile uint64_t sink;
static uint64_t buf[ITERS];

extern "C" __attribute__((noinline)) void catchall_try_marker(int i) {
    __asm__ __volatile__("" ::: "memory"); sink ^= (uint64_t)i;
}
extern "C" __attribute__((noinline)) void catchall_catch_marker(int i) {
    __asm__ __volatile__("" ::: "memory"); sink ^= (uint64_t)i << 8;
}

struct Pod { uint64_t a, b, c; };
struct Virt {
    uint64_t x;
    virtual ~Virt() {}
};

static void thrower(int kind, int i) {
    buf[i] = kind * 0x111ULL;
    switch (kind & 3) {
        case 0: throw 42;
        case 1: { Pod p{1,2,3}; throw p; }
        case 2: throw std::string("boom");
        case 3: { Virt v; v.x = i; throw v; }
    }
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    int caught = 0;
    for (int i = 0; i < ITERS; ++i) {
        try {
            catchall_try_marker(i);
            thrower(i, i);
        } catch (...) {
            catchall_catch_marker(i);
            buf[i] ^= 0x88;
            ++caught;
        }
    }
    for (int i = 0; i < ITERS; ++i) sink ^= buf[i];
    fprintf(stderr, "exc_catchall: caught=%d iters=%d sink=%llx\n",
            caught, ITERS, (unsigned long long)sink);
    return caught == ITERS ? 0 : 1;
}
