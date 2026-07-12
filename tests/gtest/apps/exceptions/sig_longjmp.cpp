// setjmp/longjmp: non-C++ stack unwinding. cctlib has separate hooks for
// setjmp/longjmp (CaptureSigSetJmpCtxt/HoldLongJmpBuf/RestoreSigLongJmpCtxt).
// This test ensures the exception-path resolver changes don't regress that
// path. ITERS bounded so the CCT fits under Pin's Fini stack budget.
#include <cstdint>
#include <cstdio>
#include <setjmp.h>
#define ITERS 500
static volatile uint64_t sink;
static uint64_t buf[ITERS];
static jmp_buf jb;

static void go_deep(int i, int depth) {
    volatile uint64_t local = 0;
    if (depth == 0) {
        buf[i] = 0xEE;
        longjmp(jb, i + 1);   // never returns
    }
    go_deep(i, depth - 1);
    (void)local;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    int jumps = 0;
    for (int i = 0; i < ITERS; ++i) {
        int rc = setjmp(jb);
        if (rc == 0) {
            go_deep(i, 8);
        } else {
            buf[i] ^= 0x77;
            ++jumps;
        }
    }
    for (int i = 0; i < ITERS; ++i) sink ^= buf[i];
    fprintf(stderr, "sig_longjmp: jumps=%d iters=%d sink=%llx\n",
            jumps, ITERS, (unsigned long long)sink);
    return jumps == ITERS ? 0 : 1;
}
