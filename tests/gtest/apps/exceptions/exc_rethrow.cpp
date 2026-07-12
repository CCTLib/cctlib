// Rethrow: catch an exception, do some work, then re-raise via `throw;`.
// The outer handler then catches it. Two _Unwind_SetIP call chains per
// iteration.
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#define ITERS 2000
static volatile uint64_t sink;
static uint64_t buf[ITERS];

static void raise_it(int i) {
    buf[i] = 0xA1;
    throw std::runtime_error("first");
}

static void inner(int i) {
    try {
        raise_it(i);
    } catch (const std::exception& e) {
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
            inner(i);
        } catch (const std::exception&) {
            buf[i] ^= 0x0F;
            ++caught;
        }
    }
    for (int i = 0; i < ITERS; ++i) sink ^= buf[i];
    fprintf(stderr, "exc_rethrow: caught=%d iters=%d sink=%llx\n",
            caught, ITERS, (unsigned long long)sink);
    return caught == ITERS ? 0 : 1;
}
