// * BeginRiceCopyright *****************************************************
//
// Copyright ((c)) 2002-2014, Rice University
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// * Neither the name of Rice University (RICE) nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// This software is provided by RICE and contributors "as is" and any
// express or implied warranties, including, but not limited to, the
// implied warranties of merchantability and fitness for a particular
// purpose are disclaimed. In no event shall RICE or contributors be
// liable for any direct, indirect, incidental, special, exemplary, or
// consequential damages (including, but not limited to, procurement of
// substitute goods or services; loss of use, data, or profits; or
// business interruption) however caused and on any theory of liability,
// whether in contract, strict liability, or tort (including negligence
// or otherwise) arising in any way out of the use of this software, even
// if advised of the possibility of such damage.
//
// ******************************************************* EndRiceCopyright *


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <iostream>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <sys/mman.h>
#include <sstream>
#include <functional>
#include <unordered_set>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include "pin.H"
using namespace std;

INT32 Usage2() {
    PIN_ERROR("Pin tool to gather calling context on each load and store.\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

// Main for RedSpy, initialize the tool, register instrumentation functions and call the target program.
static FILE* gTraceFile;


#define CACHE_LINE_BITS (6)
#define CACHE_INDEX_BITS (20)
#define CACHE_SZ (1L<< (CACHE_LINE_BITS + CACHE_INDEX_BITS))
#define CACHE_LINE_SZ (1L << CACHE_LINE_BITS)
#define CACHE_LINE_MASK (CACHE_LINE_SZ-1)

#define CACHE_NUM_LINES (CACHE_SZ/CACHE_LINE_SZ)
#define CACHE_TAG_MASK (~(CACHE_SZ-1))
#define CACHE_TAG(address) (((size_t)address) >> CACHE_LINE_BITS)
#define CACHE_LINE_INDEX(address) ((((size_t)address) & (~CACHE_TAG_MASK)) >> CACHE_LINE_BITS)
#define IS_VALID(address) (cache[CACHE_LINE_INDEX(((size_t)address))].tag == CACHE_TAG(((size_t)address)))


struct Cache_t{
    uint64_t tag;
    bool isDirty;
    uint8_t value[CACHE_LINE_SZ];
};

struct Stats_t{
    uint64_t sameData;
    uint64_t evicts;
    uint64_t dirtyEvicts;
};

__thread Stats_t stats;


__thread Cache_t cache[CACHE_NUM_LINES];

void OnEvict(void ** addr) {
    uint64_t address = (uint64_t)addr;
    uint8_t * newValue = (uint8_t *) (address & (~CACHE_LINE_MASK));
    uint8_t * originalVal = cache[CACHE_LINE_INDEX(address)].value;
    bool isDirty = cache[CACHE_LINE_INDEX(address)].isDirty;
    uint8_t * curValue = ( uint8_t *) (address & (~CACHE_LINE_MASK));

    if (isDirty) {
        bool isRedundant = true;
        for(int i = 0; i < CACHE_LINE_SZ; i++){
            if(originalVal[i] != curValue[i]) {
                isRedundant = false;
            }
            originalVal[i] = newValue[i];
        }
    
        if (isRedundant) {
            stats.sameData++;
        }
        cache[CACHE_LINE_INDEX(address)].isDirty = false; 
        stats.dirtyEvicts++;
    }
    stats.evicts++;
}

static inline void HandleOneCacheLine(void ** address, bool isWrite){
    if(!IS_VALID(address)) {
        // cache miss, allocate it.
        OnEvict(address);
    }
   // set dirty if write
   if(isWrite)
        cache[CACHE_LINE_INDEX(address)].isDirty = true;
}

void OnAccess(void ** address, uint64_t accessLen, bool isWrite){
    // Is within cache line?
    if(CACHE_LINE_INDEX(address) == CACHE_LINE_INDEX(address + accessLen - 1)) {
        HandleOneCacheLine(address, isWrite);
    } else {
        for(void ** cur = address; cur < address + accessLen; cur += CACHE_LINE_SZ){
            HandleOneCacheLine(cur, isWrite);
        }
    }
}
#define MAX_FILE_PATH (1000)

// Initialized the needed data structures before launching the target program
static void ClientInit(int argc, char* argv[]) {
    // Create output file
    char name[MAX_FILE_PATH] = "cache.out.";
    char* envPath = getenv("CACHE_CLIENT_OUTPUT_FILE");
    
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
    
    for(int i = 0 ; i < argc; i++) {
        fprintf(gTraceFile, "%s ", argv[i]);
    }
    
    fprintf(gTraceFile, "\n");
}


static VOID InstrumentInsCallback(INS ins, VOID* v) {
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    if (memOperands == 0)
        return;

    for(UINT32 memOp = 0; memOp < memOperands; memOp++) {
         if(INS_MemoryOperandIsWritten(ins, memOp)) {
             INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) OnAccess, IARG_MEMORYOP_EA, memOp, IARG_MEMORYWRITE_SIZE, IARG_BOOL, 1, IARG_END);
         } else {
             INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) OnAccess, IARG_MEMORYOP_EA, memOp, IARG_MEMORYREAD_SIZE, IARG_BOOL, 0,  IARG_END);
        }
    }
}

static VOID FiniFunc(INT32 code, VOID *v) {
    fprintf(gTraceFile, "\n Total evict = %lu, dirtyEvicts=%lu, redundant = %lu, waste = %f", stats.evicts, stats.dirtyEvicts, stats.sameData, 100.0 * stats.sameData/ stats.dirtyEvicts);
}

int main(int argc, char* argv[]) {
    // Initialize PIN
    if(PIN_Init(argc, argv))
        return Usage2();
    
    // Initialize Symbols, we need them to report functions and lines
    PIN_InitSymbols();
    
    // Init Client
    ClientInit(argc, argv);
     
    INS_AddInstrumentFunction(InstrumentInsCallback, 0); 
    // fini function for post-mortem analysis
    PIN_AddFiniFunction(FiniFunc, 0);
    
    // Launch program now
    PIN_StartProgram();
    return 0;
}


