// SIGSEGV recovery via siglongjmp. Program deliberately dereferences NULL;
// SIGSEGV handler siglongjmp's back into main and the loop continues.
// This is a common pattern (JIT probes, GC page-fault trampolines).
// cctlib must handle the fault-plus-non-local-return without corrupting
// its trace-node state.
#include <cstdint>
#include <cstdio>
#include <csetjmp>
#include <csignal>
#include <cstring>
#define ITERS 200
static volatile uint64_t sink;
static uint64_t buf[ITERS];
static sigjmp_buf sjb;

static void handler(int) {
    siglongjmp(sjb, 1);
}

static void poke(int i) {
    buf[i] = 0xC0;
    // Force a real memory access to an unmapped page.
    volatile int* bad = (volatile int*)(uintptr_t)0x1;
    (void)*bad;   // SIGSEGV -> handler -> siglongjmp
    buf[i] = 0xC1;   // never reached
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGSEGV, &sa, nullptr);

    int recovered = 0;
    for (int i = 0; i < ITERS; ++i) {
        if (sigsetjmp(sjb, 1) == 0) {
            poke(i);
        } else {
            buf[i] ^= 0x0F;
            ++recovered;
        }
    }
    for (int i = 0; i < ITERS; ++i) sink ^= buf[i];
    fprintf(stderr, "sig_sigsegv_recover: recovered=%d iters=%d sink=%llx\n",
            recovered, ITERS, (unsigned long long)sink);
    return recovered == ITERS ? 0 : 1;
}
