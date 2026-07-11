// Deadspy ISA edge case: byte-at-HIGH-offset partial overlap.
// Companion to deadspy_partial_qword_then_byte_tp.c which tests offset 0.
// Here the byte store hits offset 7 of the qword. The high byte of the
// qword is dead; bytes 0..6 remain live. Verifies deadspy's per-byte
// tracking symmetrically at both ends of a word.
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
            "movq %1, (%0)\n\t"       // 8B write at &buf[i]
            "movb %2, 7(%0)\n\t"      // 1B write at byte offset 7 -- kills byte 7
            :
            : "r"(&buf[i]), "r"(qval), "r"(bval)
            : "memory");
    }
    sink = buf[0];
    return 0;
}
