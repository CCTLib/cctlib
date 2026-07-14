// CCT eviction pair test: five noinline functions called in round-robin.
// Each has ~52 instructions (50 NOPs + function prologue/epilogue).
// At L1i capacity 100, each call causes an eviction with a predictable victim.
//
// Usage: cct_reuse_test [iterations]
//   Default: 100000 iterations

#include <stdio.h>
#include <stdlib.h>

void __attribute__((noinline)) f1() {
    asm volatile(".rept 50\nnop\n.endr");
}

void __attribute__((noinline)) f2() {
    asm volatile(".rept 50\nnop\n.endr");
}

void __attribute__((noinline)) f3() {
    asm volatile(".rept 50\nnop\n.endr");
}

void __attribute__((noinline)) f4() {
    asm volatile(".rept 50\nnop\n.endr");
}

void __attribute__((noinline)) f5() {
    asm volatile(".rept 50\nnop\n.endr");
}

int main(int argc, char* argv[]) {
    int iters = 100000;
    if (argc > 1)
        iters = atoi(argv[1]);

    fprintf(stdout, "CCT reuse test: 5 functions x %d iterations\n", iters);
    fflush(stdout);

    for (int i = 0; i < iters; i++) {
        f1();
        f2();
        f3();
        f4();
        f5();
    }

    return 0;
}
