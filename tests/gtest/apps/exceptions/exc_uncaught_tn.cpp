// Regression test for the uncaught-exception NULL guard in
// SetCurTraceNodeAfterException / SetCurTraceNodeAfterExceptionIfContextIsInstalled
// (cctlib.cpp:668, 685).
//
// When an exception has no handler, libgcc's phase-1 search returns
// _URC_END_OF_STACK -> phase 2 is never entered -> _Unwind_SetIP is
// never called -> cctlib's CaptureCallerThatCanHandleException never
// populates tData->tlsExceptionHandlerTraceNode. But cctlib IS still
// hooked at the RET of _Unwind_Resume; that hook (SetCurTraceNodeAfter*)
// used to dereference the NULL trace node and crash the tool.
//
// The victim throws, no one catches, and set_terminate installs a
// handler that _exit(0)s so the OS-visible exit is clean while the
// tool still had to survive the uncaught-exception unwind path.
//
// If the NULL guard is ever removed, this test will surface it as
// SIGSEGV-in-tool.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <unistd.h>

static void my_terminate() {
    // Uncaught-exception path exercised. Exit cleanly so the harness
    // asserts rc == 0.
    fprintf(stderr, "exc_uncaught_tn: my_terminate reached; exiting 0\n");
    _exit(0);
}

static void thrower() {
    volatile int local = 42;
    throw local;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    std::set_terminate(&my_terminate);
    thrower();   // never returns
    return 99;   // unreachable
}
