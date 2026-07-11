// loadspy ISA test: back-to-back 16B SSE loads from same address with no
// intervening write. Second load reads same 16 bytes as first -> redundant.
#include <stdint.h>
#define WORK_COUNT 100000
static volatile uint64_t sink;
static uint64_t buf[2] __attribute__((aligned(16))) = {0x1122334455667788ULL,
                                                        0x99AABBCCDDEEFF00ULL};
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    uint64_t acc = 0;
    for (int i = 0; i < WORK_COUNT; ++i) {
        __asm__ __volatile__(
            "movdqa (%1), %%xmm0\n\t"
            "movdqa (%1), %%xmm1\n\t"   // redundant 16B load
            "movq %%xmm0, %0\n\t"
            : "=r"(acc)
            : "r"(buf)
            : "xmm0", "xmm1", "memory");
    }
    sink = acc;
    return 0;
}
