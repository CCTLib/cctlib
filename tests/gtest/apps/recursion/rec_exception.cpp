// Exception thrown from deep in direct-self-recursion, caught at the
// outermost frame. Verifies that cctlib's existing exception-unwind
// path (RememberUnwindGetIPFromImage / FindNearestCallerCoveringIP)
// continues to work when the recursive routine's activations have
// been collapsed to a single physical TraceNode. A regression would
// either strand tlsCurrentTraceNode inside the collapsed frame after
// the catch, or fail to find the handler at all.
#include <cstdint>
#include <cstdio>
#include <cstdlib>

static volatile int64_t sink;

struct Deep {};

static void descend(int n) {
    if (n <= 0) throw Deep{};
    descend(n - 1);
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    int caught = 0;
    try {
        // Depth 15 -> comfortably under cctlib's MAX_CCT_PRINT_DEPTH=20.
        descend(15);
    } catch (const Deep&) {
        caught = 1;
    }
    sink ^= caught;
    fprintf(stderr, "rec_exception: caught=%d sink=%llx\n",
            caught, (unsigned long long)sink);
    return caught ? 0 : 1;
}
