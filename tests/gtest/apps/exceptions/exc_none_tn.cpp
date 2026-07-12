// True-negative: no throws, no signals, no non-local jumps. Just a normal
// C++ program with vector ops. Verifies the exception path isn't invoked
// unnecessarily and cctlib's non-exception path still functions.
#include <cstdint>
#include <cstdio>
#include <vector>
#define ITERS 20000
static volatile uint64_t sink;

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    std::vector<uint64_t> v;
    v.reserve(4);
    for (uint64_t i = 0; i < ITERS; ++i) {
        v.push_back(i * 7);
    }
    uint64_t sum = 0;
    for (uint64_t x : v) sum += x;
    sink = sum;
    fprintf(stderr, "exc_none_tn: iters=%d sum=%llu\n", ITERS,
            (unsigned long long)sum);
    return 0;
}
