// True-negative victim: the same increment is guarded by a critical
// section, so no race. Same shape as the TP victim for direct comparison.
#include <stdio.h>
#include <omp.h>

static volatile int counter;
static volatile int sink;

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    counter = 0;
    #pragma omp parallel num_threads(2)
    {
        for (int i = 0; i < 1000; ++i) {
            #pragma omp critical
            counter++;
        }
    }
    sink = counter;
    return 0;
}
