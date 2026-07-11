// Loadspy ISA edge case: cross-page redundant load. Qword load straddles
// two 4KB pages; back-to-back same loads should be counted as redundant
// by loadspy even across the page boundary.
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#define WORK_COUNT 50000
static volatile uint64_t sink;
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    const size_t pagesz = 4096;
    void* region = mmap(NULL, 2 * pagesz, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) return 1;
    uint64_t* straddle = (uint64_t*)((char*)region + pagesz - 4);
    *straddle = 0x1122334455667788ULL;   // seed with a known value
    uint64_t acc = 0;
    for (int i = 0; i < WORK_COUNT; ++i) {
        uint64_t v1, v2;
        __asm__ __volatile__(
            "movq (%[p]), %[v1]\n\t"
            "movq (%[p]), %[v2]\n\t"   // redundant qword load, across page boundary
            : [v1] "=r"(v1), [v2] "=r"(v2)
            : [p] "r"(straddle)
            : "memory");
        acc += v1 + v2;
    }
    sink = acc;
    munmap(region, 2 * pagesz);
    return 0;
}
