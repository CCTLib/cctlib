// True-positive victim exercising multiple write sizes: for each size class
// (1/2/4/8 bytes), write the same value twice to the same location.
#include <stdint.h>

#define WORK_COUNT 5000

static volatile uint64_t sink;

__attribute__((noinline)) void s1(volatile uint8_t* p,  uint8_t v)  { *p = v; }
__attribute__((noinline)) void s2(volatile uint16_t* p, uint16_t v) { *p = v; }
__attribute__((noinline)) void s4(volatile uint32_t* p, uint32_t v) { *p = v; }
__attribute__((noinline)) void s8(volatile uint64_t* p, uint64_t v) { *p = v; }

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    uint8_t  b1[WORK_COUNT] __attribute__((aligned(64)));
    uint16_t b2[WORK_COUNT] __attribute__((aligned(64)));
    uint32_t b4[WORK_COUNT] __attribute__((aligned(64)));
    uint64_t b8[WORK_COUNT] __attribute__((aligned(64)));

    for (int i = 0; i < WORK_COUNT; ++i) {
        b1[i]=0xA; b2[i]=0xAAAA; b4[i]=0xAAAAAAAAu; b8[i]=0xAAAAAAAAAAAAAAAAull;
    }
    for (int i = 0; i < WORK_COUNT; ++i) {
        s1(&b1[i], 0x5A); s1(&b1[i], 0x5A);   // redundant byte pair
        s2(&b2[i], 0x1234); s2(&b2[i], 0x1234);
        s4(&b4[i], 0xC0FFEEu); s4(&b4[i], 0xC0FFEEu);
        s8(&b8[i], 0xDEADBEEFull); s8(&b8[i], 0xDEADBEEFull);
    }

    uint64_t s = 0;
    for (int i = 0; i < WORK_COUNT; ++i) s += (uint64_t)b1[i] + b2[i] + b4[i] + b8[i];
    sink = s;
    return 0;
}
