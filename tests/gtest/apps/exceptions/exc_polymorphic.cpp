// Polymorphic catch: throw derived, catch by base reference. Exercises
// libstdc++'s __cxa_throw + type-info matching path.
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#define ITERS 1000
static volatile uint64_t sink;
static uint64_t buf[ITERS];

struct Base : std::exception { const char* what() const noexcept override { return "Base"; } };
struct Mid  : Base            { const char* what() const noexcept override { return "Mid";  } };
struct Leaf : Mid             { const char* what() const noexcept override { return "Leaf"; } };

static void thrower(int i) {
    buf[i] = 0x55;
    switch (i % 3) {
        case 0: throw Base{};
        case 1: throw Mid{};
        case 2: throw Leaf{};
    }
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    int caught = 0;
    for (int i = 0; i < ITERS; ++i) {
        try {
            thrower(i);
        } catch (const std::exception& e) {
            buf[i] ^= 0x99;
            caught += (e.what() != nullptr);
        }
    }
    for (int i = 0; i < ITERS; ++i) sink ^= buf[i];
    fprintf(stderr, "exc_polymorphic: caught=%d iters=%d sink=%llx\n",
            caught, ITERS, (unsigned long long)sink);
    return caught == ITERS ? 0 : 1;
}
