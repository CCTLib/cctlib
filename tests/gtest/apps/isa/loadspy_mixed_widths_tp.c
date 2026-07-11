// Loadspy ISA edge case: mixed-width redundant loads (qword then two
// dwords covering the same 8 bytes). If loadspy's per-byte shadow works
// correctly across access-size boundaries, the two dword loads should be
// classified as redundant against the earlier qword load.
#include <stdint.h>
#define WORK_COUNT 50000
static volatile uint64_t sink;
static uint64_t buf[2] __attribute__((aligned(8))) = {0x1122334455667788ULL, 0};
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    uint64_t acc = 0;
    for (int i = 0; i < WORK_COUNT; ++i) {
        uint64_t q;
        uint32_t d1, d2;
        __asm__ __volatile__(
            "movq (%[p]), %[q]\n\t"           // 8B load
            "movl (%[p]), %[d1]\n\t"          // 4B load, covers bytes 0..3 -- redundant
            "movl 4(%[p]), %[d2]\n\t"         // 4B load, covers bytes 4..7 -- redundant
            : [q] "=r"(q), [d1] "=r"(d1), [d2] "=r"(d2)
            : [p] "r"(buf)
            : "memory");
        acc += q + d1 + d2;
    }
    sink = acc;
    return 0;
}
