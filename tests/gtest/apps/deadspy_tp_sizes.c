// True-positive victim exercising a range of write sizes.
//
// For each size class (1/2/4/8 bytes), we do two back-to-back stores to the
// same address with no intervening read. Every second store is dead.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

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

    // Prime.
    for (int i = 0; i < WORK_COUNT; ++i) { b1[i]=0xA; b2[i]=0xAAAA; b4[i]=0xAAAAAAAAu; b8[i]=0xAAAAAAAAAAAAAAAAull; }

    for (int i = 0; i < WORK_COUNT; ++i) {
        s1(&b1[i], 1); s1(&b1[i], 2);
        s2(&b2[i], 1); s2(&b2[i], 2);
        s4(&b4[i], 1); s4(&b4[i], 2);
        s8(&b8[i], 1); s8(&b8[i], 2);
    }

    // Publish checksum.
    uint64_t s = 0;
    for (int i = 0; i < WORK_COUNT; ++i) s += (uint64_t)b1[i] + b2[i] + b4[i] + b8[i];
    sink = s;
    return 0;
}
