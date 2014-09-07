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
#define MEASURESHARING

struct node_metric_t {
#ifdef MEASURESHARING
  unordered_map<void *, uint64_t> addressMap;
#else
  unordered_set<void *> addressSet;
#endif
  uint64_t accessNum;
};

struct sort_format_t {
  ContextHandle_t handle;
  uint64_t footprint;
  uint64_t accessNum;
};

unordered_map<THREADID, unordered_map<uint32_t, struct node_metric_t>> hmap_vector;

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
#ifdef MEASURESHARING
      (hmap_vector[id])[ctxthndl].addressMap[addr]++;
#else
      (hmap_vector[id])[ctxthndl].addressSet.insert(addr);
#endif
      (hmap_vector[id])[ctxthndl].accessNum++;
    }
    else {
#ifdef MEASURESHARING
      (static_cast<struct node_metric_t*>(*metric))->addressMap[addr]++;
#else
      (static_cast<struct node_metric_t*>(*metric))->addressSet.insert(addr);
#endif
      (static_cast<struct node_metric_t*>(*metric))->accessNum++;
    }
}

VOID InstrumentInsCallback(INS ins, VOID* v, const uint32_t slot) {
    if (!INS_IsMemoryRead(ins) && !INS_IsMemoryWrite(ins)) return;
    if (INS_IsStackRead(ins) || INS_IsStackWrite(ins)) return;
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
    struct node_metric_t *hset = static_cast<struct node_metric_t*>(*myMetric);

    if (*parentMetric == NULL) {
      *parentMetric = &((hmap_vector[threadid])[parentHandle]);
#ifdef MEASURESHARING
      unordered_map<void *, uint64_t>::iterator it;
      for (it = hset->addressMap.begin(); it != hset->addressMap.end(); it++)
        (hmap_vector[threadid])[parentHandle].addressMap[it->first] += it->second;
#else
      (hmap_vector[threadid])[parentHandle].addressSet.insert(hset->addressSet.begin(), hset->addressSet.end());
#endif
      (hmap_vector[threadid])[parentHandle].accessNum += hset->accessNum;
    }
    else {
#ifdef MEASURESHARING
      unordered_map<void *, uint64_t>::iterator it;
      for (it = hset->addressMap.begin(); it != hset->addressMap.end(); it++)
        (static_cast<struct node_metric_t*>(*parentMetric))->addressMap[it->first] += it->second;
#else
      (static_cast<struct node_metric_t*>(*parentMetric))->addressSet.insert(hset->addressSet.begin(), hset->addressSet.end());
#endif
      (static_cast<struct node_metric_t*>(*parentMetric))->accessNum += hset->accessNum;
    }
}


inline bool FootPrintCompare(const struct sort_format_t &first, const struct sort_format_t &second)
{
  return first.footprint > second.footprint ? true : false;
}

void PrintTopFootPrintPath(THREADID threadid)
{
    uint64_t cntxtNum = 0;
    vector<struct sort_format_t> TmpList;

    fprintf(gTraceFile, "*************** Dump Data from Thread %d ****************\n", threadid);
    unordered_map<uint32_t, struct node_metric_t> &hmap = hmap_vector[threadid];
    unordered_map<uint32_t, struct node_metric_t>::iterator it;
    for (it = hmap.begin(); it != hmap.end(); ++it) {
        struct sort_format_t tmp;
        tmp.handle = (*it).first;
#ifdef MEASURESHARING
	tmp.footprint = (uint64_t)(*it).second.addressMap.size();
#else
	tmp.footprint = (uint64_t)(*it).second.addressSet.size();
#endif
	tmp.accessNum =  (uint64_t)(*it).second.accessNum;
        TmpList.emplace_back(tmp);
    }
    sort(TmpList.begin(), TmpList.end(), FootPrintCompare);
    vector<struct sort_format_t>::iterator ListIt;
    for (ListIt = TmpList.begin(); ListIt != TmpList.end(); ++ListIt) {
      if (cntxtNum < MAX_FOOTPRINT_CONTEXTS_TO_LOG) {
        fprintf(gTraceFile, "Footprint is %lu, #access is %lu, context is:", (*ListIt).footprint, (*ListIt).accessNum);
        PrintFullCallingContext((*ListIt).handle);
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

