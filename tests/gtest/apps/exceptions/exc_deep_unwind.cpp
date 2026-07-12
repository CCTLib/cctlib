// Deep-stack exception unwind. Recurses to depth D, then throws.
// cctlib must correctly walk up the CCT past D frames when the exception
// handler resets tlsCurrentTraceNode.
//
// D and ITERS are picked so that the total CCT size (roughly D*ITERS
// trace nodes) fits under Pin's own C-stack budget for the recursive
// CCTLibFini/VisitAllNodesOfSplayTree walker. Deeper/wider is a
// separate stress that hits a Pin-side limit, not a cctlib exception
// bug.
#include <cstdint>
#include <cstdio>
#define D 32
#define ITERS 200
static volatile uint64_t sink;
static uint64_t buf[ITERS];

static void recurse(int depth, int iter) {
    // Force a stack write so each frame is materialized.
    volatile uint64_t local = depth * 0x1010101ULL;
    if (depth == 0) {
        buf[iter] = local;
        throw local;
    }
    recurse(depth - 1, iter);
    // Never reached; keeps compiler from tail-call-optimizing away frames.
    buf[iter] += local;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    int ok = 0;
    for (int i = 0; i < ITERS; ++i) {
        try {
            recurse(D, i);
        } catch (uint64_t v) {
            (void)v;
            ++ok;
        }
    }
    for (int i = 0; i < ITERS; ++i) sink ^= buf[i];
    fprintf(stderr, "exc_deep_unwind: depth=%d iters=%d ok=%d sink=%llx\n",
            D, ITERS, ok, (unsigned long long)sink);
    return ok == ITERS ? 0 : 1;
}
