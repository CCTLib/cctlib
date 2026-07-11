// deadspy ISA test: partial overlap.
// Pattern per iter: write full qword to &buf[i], then write single byte to
// same address. The qword's byte 0 is dead (overwritten by the byte store
// without a read); bytes 1-7 are NOT dead.
// This exercises deadspy's per-byte shadow: exactly 1 dead byte per iter.
#include <stdint.h>
#define WORK_COUNT 20000
static volatile uint64_t sink;
static uint64_t buf[WORK_COUNT];
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    for (int i = 0; i < WORK_COUNT; ++i) {
        uint64_t qval = 0xDEADBEEFULL;
        uint8_t bval = 0x5A;
        __asm__ __volatile__(
            "movq %1, (%0)\n\t"     // 8B write of qval
            "movb %2, (%0)\n\t"     // 1B write of bval over byte 0 -- byte 0 dead
            :
            : "r"(&buf[i]), "r"(qval), "r"(bval)
            : "memory");
    }
    sink = buf[0];
    return 0;
}
