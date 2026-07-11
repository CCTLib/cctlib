// Instruction-reuse victim: a tight 4-instruction inline-asm loop. Every
// instruction inside the loop is re-executed after exactly 4 instructions
// (mov / add / cmp / jl), so the ins_reuse histogram should be strongly
// peaked around the bin covering distance ~4 (bin index 3, which covers
// [4,8)).
//
// N=1e6 iterations gives a substantial signal above libc-startup noise.
#include <stdint.h>

static volatile uint64_t sink;

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    uint64_t acc = 0;
    uint64_t n = 1000000;
    // Force a real tight loop in the emitted code. The `.p2align 4` keeps
    // the loop entry cache-line-aligned so timing/instrumentation is
    // reproducible.
    __asm__ __volatile__ (
        "movq $0, %[a]\n\t"
        ".p2align 4\n"
        "1:\n\t"
        "addq $1, %[a]\n\t"
        "subq $1, %[n]\n\t"
        "jnz 1b\n\t"
        : [a] "+r"(acc), [n] "+r"(n)
        :
        : "cc"
    );
    sink = acc;
    return 0;
}
