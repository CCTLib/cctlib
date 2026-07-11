// Deadspy ISA edge case: push, adjust rsp, push same effective address.
// The two `pushq %rax` instructions both write 8 bytes at the SAME
// effective stack address because the intervening `addq $8, %rsp` rewinds
// the stack pointer between them. The second push dead-writes the first.
//
// This tests deadspy's ability to see through
//   (a) rsp-relative addressing,
//   (b) implicit RSP updates,
//   (c) the address computed at instruction-time, not statically.
#include <stdint.h>
#define WORK_COUNT 10000
static volatile uint64_t sink;
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    uint64_t v1 = 0x1111, v2 = 0x2222;
    uint64_t acc = 0;
    for (int i = 0; i < WORK_COUNT; ++i) {
        // Reserve 16 bytes of scratch stack so we don't clobber return addr.
        __asm__ __volatile__(
            "subq $16, %%rsp\n\t"
            "pushq %[v1]\n\t"          // 8B write at rsp-8
            "addq $8, %%rsp\n\t"       // rewind rsp back
            "pushq %[v2]\n\t"          // 8B write at rsp-8 == same addr, dead
            "popq %[out]\n\t"          // read back v2
            "addq $16, %%rsp\n\t"      // release scratch
            : [out] "=r"(acc)
            : [v1] "r"(v1), [v2] "r"(v2)
            : "memory", "cc");
        (void)acc;
    }
    sink = acc;
    return 0;
}
