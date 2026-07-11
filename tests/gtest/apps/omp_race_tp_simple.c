// Victim: minimal OpenMP program with an OBVIOUS data race. Two threads
// both do `counter++` on a shared int without synchronisation. On most
// runs this produces a lost update; the tool should detect the race
// regardless of whether the lost update is observed.
//
// omp_datarace_client is documented as "not very mature", so this test
// primarily verifies the tool CAN load, instrument an OpenMP process,
// and exit cleanly. Detailed accuracy claims are left for future work.
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
            counter++;   // race: read-modify-write on shared, no sync
        }
    }
    sink = counter;
    return 0;
}
