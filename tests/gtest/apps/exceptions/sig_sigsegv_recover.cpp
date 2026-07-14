// SIGSEGV recovery via siglongjmp. Program deliberately dereferences NULL;
// SIGSEGV handler siglongjmp's back into main and the loop continues.
// This is a common pattern (JIT probes, GC page-fault trampolines).
// cctlib must handle the fault-plus-non-local-return without corrupting
// its trace-node state.
//
// sigsegv_try_marker (before poke) and sigsegv_recover_marker (post-
// siglongjmp on the sigsetjmp-returns-nonzero path) verify the signal-
// recovery re-anchor leaves the landing block as a direct child of main.
#include <cstdint>
#include <cstdio>
#include <csetjmp>
#include <csignal>
#include <cstring>
#define ITERS 200
static volatile uint64_t sink;
static uint64_t buf[ITERS];
static sigjmp_buf sjb;

extern "C" __attribute__((noinline)) void sigsegv_try_marker(int i) {
    __asm__ __volatile__("" ::: "memory"); sink ^= (uint64_t)i;
}
extern "C" __attribute__((noinline)) void sigsegv_recover_marker(int i) {
    __asm__ __volatile__("" ::: "memory"); sink ^= (uint64_t)i << 8;
}

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
            sigsegv_try_marker(i);
            poke(i);
        } else {
            sigsegv_recover_marker(i);
            buf[i] ^= 0x0F;
            ++recovered;
        }
    }
    for (int i = 0; i < ITERS; ++i) sink ^= buf[i];
    fprintf(stderr, "sig_sigsegv_recover: recovered=%d iters=%d sink=%llx\n",
            recovered, ITERS, (unsigned long long)sink);
    return recovered == ITERS ? 0 : 1;
}
