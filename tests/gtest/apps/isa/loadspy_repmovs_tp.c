// loadspy ISA test: rep movsq -- string-move that both loads and stores
// the same buffer over itself. Second iteration's loads are all redundant
// with the first iteration's writes (which just wrote the same values
// back).
#include <stdint.h>
#include <stddef.h>
#define N 512
static volatile uint64_t sink;
static uint64_t src[N];
static uint64_t dst[N];
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    for (int i = 0; i < N; ++i) src[i] = i;
    for (int iter = 0; iter < 100; ++iter) {
        // First: copy src -> dst (loads from src, stores to dst)
        __asm__ __volatile__(
            "cld\n\t"
            "rep movsq"
            :
            : "S"(src), "D"(dst), "c"((size_t)N)
            : "memory", "cc");
        // Second: same rep movsq -- reads the SAME src values again.
        // Each load is redundant with the previous iteration's load.
        __asm__ __volatile__(
            "cld\n\t"
            "rep movsq"
            :
            : "S"(src), "D"(dst), "c"((size_t)N)
            : "memory", "cc");
    }
    sink = dst[0];
    return 0;
}
