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
#include <sstream>
#include "pin.H"
#include "cctlib.H"
using namespace std;
using namespace PinCCTLib;

#include <unordered_set>
#include <vector>
#include <unordered_map>
#include <algorithm>

#define MAX_FOOTPRINT_CONTEXTS_TO_LOG (1000)

unordered_map<THREADID, unordered_map<uint32_t, unordered_set<void *>>> hmap_vector;

INT32 Usage2() {
    PIN_ERROR("Pin tool to gather calling context on each load and store.\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

// Main for DeadSpy, initialize the tool, register instrumentation functions and call the target program.
FILE* gTraceFile;

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

    for(int i = 0 ; i < argc; i++) {
        fprintf(gTraceFile, "%s ", argv[i]);
    }

    fprintf(gTraceFile, "\n");
}

VOID MemFunc(THREADID id, void* addr) {
    // at memory instruction record the footprint
    void **metric = GetIPNodeMetric(id, 0);

    if (*metric == NULL) {
      // use ctxthndl as the key to associate footprint with the trace
      ContextHandle_t ctxthndl = GetContextHandle(id, 0);
      *metric = &(hmap_vector[id])[ctxthndl];
      (hmap_vector[id])[ctxthndl].insert(addr);
    }
    else
      (static_cast<unordered_set<void *>*>(*metric))->insert(addr);
}

VOID InstrumentInsCallback(INS ins, VOID* v, const uint32_t slot) {
    if (!INS_IsMemoryRead(ins) && !INS_IsMemoryWrite(ins)) return;
    if (INS_IsBranchOrCall(ins) || INS_IsRet(ins)) return;
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)MemFunc, IARG_THREAD_ID, IARG_MEMORYOP_EA, memOp, IARG_END);
    }
}

void MergeFootPrint(const THREADID threadid,  ContextHandle_t myHandle, ContextHandle_t parentHandle, void **myMetric, void **parentMetric)
{
    if (*myMetric == NULL) return;
    unordered_set<void *> *hset = static_cast<unordered_set<void *>*>(*myMetric);

    unordered_set<void *> *hsetParent;
    if (*parentMetric == NULL) {
      *parentMetric = &((hmap_vector[threadid])[parentHandle]);
      hsetParent = &((hmap_vector[threadid])[parentHandle]);
    }
    else 
      hsetParent = static_cast<unordered_set<void *>*>(*parentMetric);

    hsetParent->insert(hset->begin(), hset->end());
}

inline bool FootPrintCompare(const pair<ContextHandle_t, uint64_t> &first, const struct pair<ContextHandle_t, uint64_t> &second)
{
  return first.second > second.second ? true : false;
}

void PrintTopFootPrintPath(THREADID threadid)
{
    uint64_t cntxtNum = 0;
    vector<pair<ContextHandle_t, uint64_t>> TmpList;

    fprintf(gTraceFile, "*************** Dump Data from Thread %d ****************\n", threadid);
    unordered_map<uint32_t, unordered_set<void *>> &hmap = hmap_vector[threadid];
    unordered_map<uint32_t, unordered_set<void *>>::iterator it;
    for (it = hmap.begin(); it != hmap.end(); ++it) {
        TmpList.emplace_back((*it).first, (uint64_t)(*it).second.size());
    }
    sort(TmpList.begin(), TmpList.end(), FootPrintCompare);
    vector<pair<ContextHandle_t, uint64_t>>::iterator ListIt;
    for (ListIt = TmpList.begin(); ListIt != TmpList.end(); ++ListIt) {
      if (cntxtNum < MAX_FOOTPRINT_CONTEXTS_TO_LOG) {
        fprintf(gTraceFile, "Footprint Size is %lu, context is", (*ListIt).second);
        PrintFullCallingContext((*ListIt).first);
	fprintf(gTraceFile, "\n------------------------------------------------\n");
      }
      else {
	break;
      }
      cntxtNum++;
    }
}

VOID ThreadFiniFunc(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    // traverse CCT bottom to up
    TraverseCCTBottomUp(threadid, MergeFootPrint);
    // print the footprint for functions
    PIN_LockClient();
    PrintTopFootPrintPath(threadid);
    PIN_UnlockClient();
}

VOID FiniFunc(INT32 code, VOID *v)
{
    // do whatever you want to the full CCT with footpirnt
}

int main(int argc, char* argv[]) {
    // Initialize PIN
    if(PIN_Init(argc, argv))
        return Usage2();

    // Initialize Symbols, we need them to report functions and lines
    PIN_InitSymbols();
    // Init Client
    ClientInit(argc, argv);
    // Intialize CCTLib
    PinCCTLibInit(INTERESTING_INS_MEMORY_ACCESS, gTraceFile, InstrumentInsCallback, 0);
    
    // fini function for post-mortem analysis
    PIN_AddThreadFiniFunction(ThreadFiniFunc, 0);
    PIN_AddFiniFunction(FiniFunc, 0);

    // Launch program now
    PIN_StartProgram();
    return 0;
}

