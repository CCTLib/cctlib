// Indirect self-recursion via function pointer. The classifier does
// NOT see this as self-recursion (INS_IsDirectControlFlow is false),
// so it falls back to today's behavior: CCT grows one node per
// activation. Test asserts (a) no crash, (b) correct final result.
// This locks in the "graceful degradation" contract for the
// indirect-only case documented in the design.
#include <cstdint>
#include <cstdio>

static volatile uint64_t sink;

typedef uint64_t (*RecFn)(int);
static RecFn g_next;

static uint64_t indirect_rec(int n) {
    if (n <= 0) return 1;
    // Indirect call. g_next is set to point back at indirect_rec
    // itself; Pin's classifier sees an indirect call and marks the
    // site as not-direct-self-recursive.
    return 1 + g_next(n - 1);
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    g_next = &indirect_rec;
    // Depth 12 -> 12 physical frames of indirect_rec plus main.
    // Kept comfortably under cctlib's MAX_CCT_PRINT_DEPTH=20 so the
    // shape check assertion can see distinct chain signatures per
    // uncollapsed frame -- if we ever regressed by accidentally
    // collapsing indirect recursion, chainCountForFn("indirect_rec")
    // would drop and the assertion would fail.
    uint64_t r = indirect_rec(12);
    sink ^= r;
    fprintf(stderr, "rec_indirect_only: r=%llu sink=%llx\n",
            (unsigned long long)r, (unsigned long long)sink);
    return r == 13 ? 0 : 1;
}
