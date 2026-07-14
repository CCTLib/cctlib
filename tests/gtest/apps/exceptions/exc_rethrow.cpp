// Rethrow: catch an exception, do some work, then re-raise via `throw;`.
// The outer handler then catches it. Two _Unwind_SetIP call chains per
// iteration.
//
// Four markers so both catch blocks are testable:
//   rethrow_outer_try_marker    inner-try body in main
//   rethrow_inner_try_marker    inner-try body in inner()
//   rethrow_inner_catch_marker  inner's catch body (before the re-throw)
//   rethrow_outer_catch_marker  main's catch body
// The shape checks assert each marker is a direct child of its enclosing
// function (main / inner), not descended from __cxa_throw.
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#define ITERS 2000
static volatile uint64_t sink;
static uint64_t buf[ITERS];

extern "C" __attribute__((noinline)) void rethrow_outer_try_marker(int i) {
    __asm__ __volatile__("" ::: "memory"); sink ^= (uint64_t)i;
}
extern "C" __attribute__((noinline)) void rethrow_inner_try_marker(int i) {
    __asm__ __volatile__("" ::: "memory"); sink ^= (uint64_t)i << 4;
}
extern "C" __attribute__((noinline)) void rethrow_inner_catch_marker(int i) {
    __asm__ __volatile__("" ::: "memory"); sink ^= (uint64_t)i << 8;
}
extern "C" __attribute__((noinline)) void rethrow_outer_catch_marker(int i) {
    __asm__ __volatile__("" ::: "memory"); sink ^= (uint64_t)i << 12;
}

static void raise_it(int i) {
    buf[i] = 0xA1;
    throw std::runtime_error("first");
}

static void inner(int i) {
    try {
        rethrow_inner_try_marker(i);
        raise_it(i);
    } catch (const std::exception& e) {
        rethrow_inner_catch_marker(i);
        (void)e;
        buf[i] ^= 0xF0;
        throw;   // rethrow
    }
    buf[i] = 0xEE;   // never reached
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    int caught = 0;
    for (int i = 0; i < ITERS; ++i) buf[i] = 0x22;
    for (int i = 0; i < ITERS; ++i) {
        try {
            rethrow_outer_try_marker(i);
            inner(i);
        } catch (const std::exception&) {
            rethrow_outer_catch_marker(i);
            buf[i] ^= 0x0F;
            ++caught;
        }
    }
    for (int i = 0; i < ITERS; ++i) sink ^= buf[i];
    fprintf(stderr, "exc_rethrow: caught=%d iters=%d sink=%llx\n",
            caught, ITERS, (unsigned long long)sink);
    return caught == ITERS ? 0 : 1;
}
