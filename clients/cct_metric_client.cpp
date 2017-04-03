// @COPYRIGHT@
// Licensed under MIT license.
// See LICENSE.TXT file in the project root for more information.
// ==============================================================

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <iostream>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <sstream>
#include <sys/types.h>
#include <sys/stat.h>
#include "pin.H"

#define HAVE_METRIC_PER_IPNODE
#include "cctlib.H"

#define MAX_THREADS 1024

using namespace std;
using namespace PinCCTLib;

static INT32 Usage() {
    PIN_ERROR("CCTLib client Pin tool to gather calling context on each instruction.\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}


// Main for DeadSpy, initialize the tool, register instrumentation functions and call the target program.
FILE* gTraceFile;

long mm[MAX_THREADS];

// Initialized the needed data structures before launching the target program
void ClientInit(int argc, char* argv[]) {
    // Create output file
    char name[MAX_FILE_PATH] = "client.out.";
    char* envPath = getenv("CCTLIB_CLIENT_OUTPUT_FILE");

    if(envPath) {
        // assumes max of MAX_FILE_PATH
        strcpy(name, envPath);
    }

    gethostname(name + strlen(name), MAX_FILE_PATH - strlen(name));
    pid_t pid = getpid();
    sprintf(name + strlen(name), "%d", pid);
    cerr << "\n Creating log file at:" << name << "\n";
    gTraceFile = fopen(name, "w");
    // print the arguments passed
    fprintf(gTraceFile, "\n");
}

VOID ThreadStartFunc(THREADID threadid, CONTEXT *ctxt, INT32 code, VOID *v)
{
    mm[threadid] = 0;
}

VOID ThreadFiniFunc(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    printf("instructionCount is %ld\n", mm[threadid]);
    newCCT_hpcrun_write(threadid);
}

// user-defined function for metric merging
void mergeFunc(void *des, void *src)
{
    uint64_t *m = (uint64_t *)des;
    uint64_t *n = (uint64_t *)src;
    *m += *n;
}

// user-defined function for metric computation
// hpcviewer can only show the numbers for the metric
uint64_t computeMetricVal(void *metric)
{
    if (!metric) return 0;
    return (uint64_t)*((uint64_t *)metric);
}

// user needs to define the metrics and the method to accumulate the metrics in each node
VOID SimpleCCTQuery(THREADID id, const uint32_t slot) {
    GetContextHandle(id, slot);
    void **c_m = GetIPNodeMetric(id, slot);
    uint64_t *m;
    if (*c_m == NULL) {
      m = (uint64_t*) malloc (sizeof(uint64_t));
      *m = 0;
      *c_m = (void *)m;
    }
    else
      m = (uint64_t*) (*c_m);
    (*m)++;
    // record the number of instructions per each thread
    mm[id]++;    
}

VOID InstrumentInsCallback(INS ins, VOID* v, const uint32_t slot) {
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)SimpleCCTQuery, IARG_THREAD_ID, IARG_UINT32, slot, IARG_END);
}


int main(int argc, char* argv[]) {
    // Initialize PIN
    if(PIN_Init(argc, argv))
        return Usage();

    // Initialize Symbols, we need them to report functions and lines
    PIN_InitSymbols();
    // Init Client
    ClientInit(argc, argv);
    // Intialize CCTLib
    PinCCTLibInit(INTERESTING_INS_ALL, gTraceFile, InstrumentInsCallback, 0);
    // Init hpcrun format output
    init_hpcrun_format(argc, argv, mergeFunc, computeMetricVal, false);
    
    // Collete data for visualization
    PIN_AddThreadStartFunction(ThreadStartFunc, 0);
    PIN_AddThreadFiniFunction(ThreadFiniFunc, 0);
    // Launch program now
    PIN_StartProgram();
    return 0;
}
