// CCT eviction pair correctness test.
//
// Scenario 1: s1, s2, s3 in round-robin — tests L1i/L2/L3 instruction-level eviction.
// Scenario 2: p1, p2, p3 (page-aligned) in round-robin — tests iTLB page-level eviction.
// Scenario 3: s1, s2 alternating — tests 2-function symmetric eviction pair counts.
//
// Usage: cct_eviction_test <scenario> [iterations]

#include <stdio.h>
#include <stdlib.h>

void __attribute__((noinline)) s1() {
    asm volatile(".rept 50\nnop\n.endr");
}
void __attribute__((noinline)) s2() {
    asm volatile(".rept 50\nnop\n.endr");
}
void __attribute__((noinline)) s3() {
    asm volatile(".rept 50\nnop\n.endr");
}

void __attribute__((noinline, aligned(4096))) p1() {
    asm volatile(".rept 50\nnop\n.endr");
}
void __attribute__((noinline, aligned(4096))) p2() {
    asm volatile(".rept 50\nnop\n.endr");
}
void __attribute__((noinline, aligned(4096))) p3() {
    asm volatile(".rept 50\nnop\n.endr");
}

int main(int argc, char* argv[]) {
    int scenario = argc > 1 ? atoi(argv[1]) : 1;
    int iters = argc > 2 ? atoi(argv[2]) : 1000;

    switch (scenario) {
    case 1:
        for (int i = 0; i < iters; i++) {
            s1();
            s2();
            s3();
        }
        break;
    case 2:
        for (int i = 0; i < iters; i++) {
            p1();
            p2();
            p3();
        }
        break;
    case 3:
        for (int i = 0; i < iters; i++) {
            s1();
            s2();
        }
        break;
    }
    return 0;
}
