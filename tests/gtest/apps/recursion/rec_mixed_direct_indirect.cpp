// Same routine has BOTH a direct self-call and an indirect self-call.
// Verifies the two mechanisms are mutually orthogonal per the design:
//   * direct site: hasSelfRec=true -> SetCallInitFlag suppressed ->
//     splay/sibling-branch collapses activation in place.
//   * indirect site: SetCallInitFlag fires as before -> new frame is
//     allocated. From inside the new frame, further direct calls
//     still collapse under that (new) frame.
// A regression where the two paths cross-contaminate would either
// blow up the CCT (direct sites not folding) or wrongly return past
// the indirect-frame boundary.
#include <cstdint>
#include <cstdio>

static volatile uint64_t sink;

typedef uint64_t (*RecFn)(int);
static RecFn g_next;

static uint64_t mixed(int n) {
    if (n <= 0) return 0;
    // n % 4 == 0: indirect recursion (introduces a physical frame).
    // otherwise: direct recursion (collapses in place).
    if ((n % 5) == 0) {
        return 1 + g_next(n - 1);   // indirect self-call (~1 in 5)
    }
    return 1 + mixed(n - 1);        // direct self-call
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    g_next = &mixed;
    // depth 30 with every-5th indirect -> ~6 indirect physical frames
    // (uncollapsed) plus ~24 direct-collapse steps folded into them.
    // Under cctlib's MAX_CCT_PRINT_DEPTH=20 the deepest chain is
    // main + 6 indirect frames + one collapsed direct-frame = 8.
    uint64_t r = mixed(30);
    sink ^= r;
    fprintf(stderr, "rec_mixed_direct_indirect: r=%llu sink=%llx\n",
            (unsigned long long)r, (unsigned long long)sink);
    return r == 30 ? 0 : 1;
}
