// deadspy ISA test: atomic writes (LOCK XCHG). Even though the store is
// atomic, deadspy should still see it as a write and, if not read between
// two consecutive atomics to same location, the first is dead.
#include <stdint.h>
#define WORK_COUNT 20000
static volatile uint64_t sink;
static uint64_t buf[WORK_COUNT];
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    for (int i = 0; i < WORK_COUNT; ++i) {
        uint64_t v1 = 0x1111, v2 = 0x2222;
        __asm__ __volatile__(
            "xchgq %0, (%2)\n\t"   // atomic 8B write of v1
            "xchgq %1, (%2)\n\t"   // atomic 8B write of v2 -- kills v1
            : "+r"(v1), "+r"(v2)
            : "r"(&buf[i])
            : "memory");
    }
    sink = buf[0];
    return 0;
}
