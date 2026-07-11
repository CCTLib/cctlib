// deadspy ISA test: `rep stosq` -- string store instruction.
// Writes N * 8 bytes of the same value in a single instruction. Doing it
// TWICE without an intervening read makes the first N*8 bytes dead.
// Exercises deadspy's handling of variable-length string writes.
#include <stdint.h>
#include <string.h>
#define N 512
static volatile uint64_t sink;
static uint64_t buf[N];
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    for (int iter = 0; iter < 100; ++iter) {
        // First: rep stosq of 512 qwords
        __asm__ __volatile__(
            "cld\n\t"
            "rep stosq"
            :
            : "D"(buf), "c"((size_t)N), "a"((uint64_t)0xDEADBEEF)
            : "memory", "cc");
        // Second: rep stosq of same range -- overwrite -> dead writes
        __asm__ __volatile__(
            "cld\n\t"
            "rep stosq"
            :
            : "D"(buf), "c"((size_t)N), "a"((uint64_t)0xCAFEB0BA)
            : "memory", "cc");
    }
    sink = buf[0];
    return 0;
}
