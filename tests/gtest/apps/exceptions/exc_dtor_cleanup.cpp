// Destructor called during unwind. Each Guard object writes to buf in its
// destructor while an exception propagates. Verifies cctlib's callback
// ordering plays nicely with per-frame cleanup code, which itself contains
// memory writes deadspy/redspy/loadspy must track.
#include <cstdint>
#include <cstdio>
#define ITERS 500
static volatile uint64_t sink;
static uint64_t buf[ITERS];

struct Guard {
    uint64_t* slot;
    uint64_t v;
    Guard(uint64_t* s, uint64_t v_) : slot(s), v(v_) { *slot = v; }
    // noexcept: an exception from a destructor called during unwind would
    // call std::terminate, which would defeat the point of this test.
    ~Guard() noexcept { *slot ^= 0x00FF00FF00FF00FFULL; }
};

static void thrower(int i) {
    Guard g1(&buf[i], 0x1010);
    {
        Guard g2(&buf[i], 0x2020);
        throw i;   // both guards' destructors run during unwind
    }
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    int caught = 0;
    for (int i = 0; i < ITERS; ++i) {
        try {
            thrower(i);
        } catch (int v) {
            caught += v == i;
            buf[i] ^= 0xCC;
        }
    }
    for (int i = 0; i < ITERS; ++i) sink ^= buf[i];
    fprintf(stderr, "exc_dtor_cleanup: caught=%d iters=%d sink=%llx\n",
            caught, ITERS, (unsigned long long)sink);
    return caught == ITERS ? 0 : 1;
}
