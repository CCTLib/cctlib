// Deadspy ISA edge case: cross-page qword write.
// The qword store starts 4 bytes before a page boundary, so the 8-byte
// store straddles two 4KB pages. Deadspy's per-byte shadow (organized
// as a 2-level page table with 64KB shadow pages) must correctly handle
// a store that spans two shadow-page slots.
//
// Pattern: write qword at addr X, then write qword at same addr X.
// Both stores straddle a page boundary. Second store's 8B are dead.
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#define WORK_COUNT 10000
static volatile uint64_t sink;
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    // mmap two contiguous 4KB pages so we can address across the boundary.
    const size_t pagesz = 4096;
    void* region = mmap(NULL, 2 * pagesz, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) return 1;
    // Straddle offset: last 4B of page 0 + first 4B of page 1.
    uint64_t* straddle = (uint64_t*)((char*)region + pagesz - 4);
    uint64_t v1 = 0xDEADBEEF, v2 = 0xC0FFEE;
    for (int i = 0; i < WORK_COUNT; ++i) {
        __asm__ __volatile__(
            "movq %[v1], (%[p])\n\t"
            "movq %[v2], (%[p])\n\t"   // dead: 8B write over 8B write, straddles page
            :
            : [p] "r"(straddle), [v1] "r"(v1), [v2] "r"(v2)
            : "memory");
    }
    sink = *straddle;
    munmap(region, 2 * pagesz);
    return 0;
}
