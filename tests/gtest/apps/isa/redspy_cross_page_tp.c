// Redspy ISA edge case: cross-page same-value write. The qword store
// starts 4 bytes before a 4KB page boundary, so the write straddles two
// pages. Repeated writes of the SAME value at the same straddled address
// are redundant. Verifies redspy's shadow correctly maintains value
// tracking across page boundaries.
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#define WORK_COUNT 10000
static volatile uint64_t sink;
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    const size_t pagesz = 4096;
    void* region = mmap(NULL, 2 * pagesz, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) return 1;
    uint64_t* straddle = (uint64_t*)((char*)region + pagesz - 4);
    uint64_t v = 0xC0FFEEDEADBEEFULL;
    for (int i = 0; i < WORK_COUNT; ++i) {
        __asm__ __volatile__(
            "movq %[v], (%[p])\n\t"
            "movq %[v], (%[p])\n\t"   // same value -- redundant
            :
            : [p] "r"(straddle), [v] "r"(v)
            : "memory");
    }
    sink = *straddle;
    munmap(region, 2 * pagesz);
    return 0;
}
