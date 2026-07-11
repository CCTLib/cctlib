// redspy ISA test: partial-overlap redundancy. Write a qword, then write
// a byte to the same address with a value that matches the qword's low
// byte -- byte 0's value is unchanged (redundant), bytes 1-7 unchanged
// too, so the byte write is a redundant single byte.
#include <stdint.h>
#define WORK_COUNT 20000
static volatile uint64_t sink;
static uint64_t buf[WORK_COUNT];
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    for (int i = 0; i < WORK_COUNT; ++i) {
        uint64_t qval = 0xDEADBEEFCAFEB05AULL;   // low byte is 0x5A
        uint8_t  bval = 0x5A;                    // same as qval's low byte
        __asm__ __volatile__(
            "movq %1, (%0)\n\t"
            "movb %2, (%0)\n\t"   // same low byte -- 1 byte of redundancy
            :
            : "r"(&buf[i]), "r"(qval), "r"(bval)
            : "memory");
    }
    sink = buf[0];
    return 0;
}
