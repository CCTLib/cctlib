// @COPYRIGHT@
// Licensed under MIT license.
// See LICENSE.TXT file in the project root for more information.
// ==============================================================

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <atomic>
#include <malloc.h>
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
#include <list>
#include <bits/stdc++.h>

#include "pin.H"
#include "cctlib.H"
#include "shadow_memory.H"
#include "rbtree.h"
#include <xmmintrin.h>
#include <immintrin.h>

extern "C" {
#include "xed-interface.h"
#include "xed-common-hdrs.h"
}

#include <google/sparse_hash_map>
#include <google/dense_hash_map>
using google::sparse_hash_map;  // namespace where class lives by default
using google::dense_hash_map;

using namespace std;
using namespace PinCCTLib;

#define MAX_REUSE_DISTANCE_BINS (32) // 4 GB
#define MAX_REUSE_DISTANCE (1ULL<< (MAX_REUSE_DISTANCE_BINS)) // 4 GB

#define CACHELINE_BIT (6)
#define CACHELINE_SIZE (1L<<CACHELINE_BIT)
#define CACHELINE_MASK (CACHELINE_SIZE-1)

#define GET_CACHELINE(addr) (((uint64_t)addr) & (~(CACHELINE_MASK)))

#define FIRST_USE (ULLONG_MAX)

#define MULTI_THREADED

struct{
    char dummy1[128];
    xed_state_t  xedState;
    char dummy2[128];
} InsReuseGlobals;

using RBTree_t = RBTree<uint64_t, uint32_t, uint64_t>;

struct InsReuseThreadData{
    char padding1[128];
    uint64_t bytesLoad;
    long long numIns;
    RBTree_t InsRBTree;
    RBTree_t CLRBTree;
    uint64_t numInsExecuted;
    uint64_t numCacheLines;
    uint64_t insReuseHisto[MAX_REUSE_DISTANCE_BINS];
    uint64_t clReuseHisto[MAX_REUSE_DISTANCE_BINS];
    ShadowMemory<uint64_t> smIns;
    ShadowMemory<uint64_t> smCL;
    bool sampleFlag;
    char padding2[128];
};

// key for accessing TLS storage in the threads. initialized once in main()
static  TLS_KEY client_tls_key;
static InsReuseThreadData* gSingleThreadedTData;

// function to access thread-specific data
inline InsReuseThreadData* ClientGetTLS(const THREADID threadId) {
#ifdef MULTI_THREADED
    InsReuseThreadData* tdata =
    static_cast<InsReuseThreadData*>(PIN_GetThreadData(client_tls_key, threadId));
    return tdata;
#else
    return gSingleThreadedTData;
#endif
}

static INT32 Usage() {
    PIN_ERROR("Pin tool to profile instruction reuse distance.\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

// Main for RedSpy, initialize the tool, register instrumentation functions and call the target program.
static FILE* gTraceFile;

// Initialized the needed data structures before launching the target program
static void ClientInit(int argc, char* argv[]) {
    // Create output file
    char name[MAX_FILE_PATH] = "insReuse.out.";
    char* envPath = getenv("INS_REUSE_CLIENT_OUTPUT_FILE");
    
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
    
    // Init Xed
    // Init XED for decoding instructions
    xed_state_init(&InsReuseGlobals.xedState, XED_MACHINE_MODE_LONG_64, (xed_address_width_enum_t) 0, XED_ADDRESS_WIDTH_64b);
}

static inline void UpdateInsReuseStats(uint64_t distance, uint64_t count, InsReuseThreadData* tData){
    uint64_t bin;
    
    // Bin 0: [0, 1)
    // Bin 1  [1, 2)
    // Bin 3  [2, 4)
    // Bin 3  [4, 8)
    
    if (distance >= MAX_REUSE_DISTANCE) {
        bin = MAX_REUSE_DISTANCE_BINS-1;
    } else if (distance == 0) {
        bin = 0;
    } else {
        bin = (sizeof(uint64_t)*8 - 1 - __builtin_clzl(distance)) + 1 /* 1 for dedicated bin 0*/;
    }
    tData->insReuseHisto[bin] += count;
}

static inline void UpdateCacheLineReuseStats(uint64_t distance, uint64_t count, InsReuseThreadData* tData){
    // Bin 0: [0, 1)
    // Bin 1  [1, 2)
    // Bin 3  [2, 4)
    // Bin 3  [4, 8)
    
    uint64_t bin;
    if (distance >= MAX_REUSE_DISTANCE) {
        bin = MAX_REUSE_DISTANCE_BINS-1;
    } else if (distance == 0) {
        bin = 0;
    } else {
        bin = (sizeof(uint64_t)*8 - 1 - __builtin_clzl(distance)) + 1 /* 1 for dedicated bin 0*/;
    }
    // One instruction is at this distance
    tData->clReuseHisto[bin] ++;
    // The rest of the instructions on the same cacheline have a zero distance
    tData->clReuseHisto[0] += count-1;
}

static inline uint64_t ComputeInsReuseDistance(uint64_t prevTick, uint64_t newTick, uint32_t v, InsReuseThreadData * tData, RBTree_t * rbt){
    // Find how many RB-Tree nodes are to the right of this node.
    uint64_t reuseDist;
    auto node = rbt->FindSumGreaterEqual(prevTick, &reuseDist);
    if (node) {
        //  Delete the node from RB-tree
        auto retNode = rbt->Delete(node);
        // reinsert the node with new tick
        retNode->key =  newTick;
        retNode->value =  v;
        rbt->Insert(retNode);
        return reuseDist;
    } else {
        return FIRST_USE;
    }
}



static inline uint64_t ComputeCLReuseDistance(uint64_t prevTick, uint64_t newTick, uint32_t v, InsReuseThreadData * tData, RBTree_t * rbt){
    // Find how many RB-Tree nodes are to the right of this node.
    uint64_t reuseDist;
    auto node = rbt->FindSumGreaterThan(prevTick, &reuseDist);
    if (node) {
        //  Delete the node from RB-tree
        auto retNode = rbt->Delete(node);
        // reinsert the node with new tick
        retNode->key =  newTick;
        retNode->value =  v;
        rbt->Insert(retNode);
        return reuseDist;
    } else {
        return FIRST_USE;
    }
}


static inline void AnalyzeInsLevelReuse(void * insAddr, uint32_t numInsInBBL,  THREADID threadId){
    assert(0 != numInsInBBL);
    InsReuseThreadData* tData = ClientGetTLS(threadId);
    tuple<uint64_t[SHADOW_PAGE_SIZE]> &t = tData->smIns.GetOrCreateShadowBaseAddress((uint64_t)insAddr);
    uint64_t * shadowMemAddr = &(get<0>(t)[PAGE_OFFSET((uint64_t)insAddr)]);
    
    
    uint64_t prevTick = *shadowMemAddr;
    uint64_t newTick = tData->numInsExecuted;
    
    // Update the number of instructions executed
    if (prevTick == 0 /* first use */) {
        // no update needed
        // However, needs a new insertion
        auto newNode = new TreeNode<uint64_t, uint32_t, uint64_t>(tData->numInsExecuted, numInsInBBL);
        tData->InsRBTree.Insert(newNode);
    } else {
        uint64_t reuseDistance = ComputeInsReuseDistance(prevTick,  tData->numInsExecuted, numInsInBBL, tData, & tData->InsRBTree);
        assert(FIRST_USE != reuseDistance);
        UpdateInsReuseStats(reuseDistance, numInsInBBL, tData);
    }
    *shadowMemAddr = tData->numInsExecuted;
    tData->numInsExecuted += numInsInBBL;
}

static inline void AnalyzeCacheLineLevelReuse(void * cacheLine, uint32_t numInsInCacheLine,  THREADID threadId){
    assert(0 != numInsInCacheLine);
    InsReuseThreadData* tData = ClientGetTLS(threadId);
    tuple<uint64_t[SHADOW_PAGE_SIZE]> &t = tData->smCL.GetOrCreateShadowBaseAddress((uint64_t)cacheLine);
    uint64_t * shadowMemAddr = &(get<0>(t)[PAGE_OFFSET((uint64_t)cacheLine)]);
    uint64_t prevTick = *shadowMemAddr;
    
    if (prevTick == 0 /* first use */) {
        // needs a new insertion
        auto newNode = new TreeNode<uint64_t, uint32_t, uint64_t>(tData->numCacheLines, numInsInCacheLine);
        tData->CLRBTree.Insert(newNode);
        
        if (numInsInCacheLine > 1) {
            // The rest of the instructions on the same cacheline have a zero distance
            tData->clReuseHisto[0] += numInsInCacheLine-1;
        }
    } else {
        uint64_t reuseDistance = ComputeCLReuseDistance(prevTick, tData->numCacheLines, numInsInCacheLine, tData, & tData->CLRBTree);
        assert(FIRST_USE != reuseDistance);
        UpdateCacheLineReuseStats(reuseDistance, numInsInCacheLine, tData);
    }
    *shadowMemAddr = tData->numCacheLines;
    // Update the tick
    tData->numCacheLines++;
}


//instrument the trace, count the number of ins in the trace and instrument each BBL
static void InstrumentTrace(TRACE trace, void* f) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)){
        uint32_t totInsInBbl = BBL_NumIns(bbl);
        ADDRINT insAddr = BBL_Address(bbl);
        BBL_InsertCall(bbl,
                       IPOINT_BEFORE,(AFUNPTR)AnalyzeInsLevelReuse,
                       IARG_ADDRINT, insAddr,
                       IARG_UINT32, totInsInBbl,
                       IARG_THREAD_ID, IARG_END);
    }
    
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)){
        uint32_t numInsInCacheLine = 0;
        uint64_t prevCacheLine = GET_CACHELINE(INS_Address(BBL_InsHead(bbl)));
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins=INS_Next(ins)) {
            // Does instruction straddle two cachelines?
            uint64_t insStartCacheLine = GET_CACHELINE(INS_Address(ins));
            uint64_t insEndCacheLine = GET_CACHELINE(INS_Address(ins) + INS_Size(ins) - 1);
            
            // +1 for the ongoing cacheline
            if(insStartCacheLine == prevCacheLine) {
                numInsInCacheLine ++;
            }
            
            // Assumption: ins can never span more than one CL.
            // Continue adding more to this cacheline
            if (insEndCacheLine == prevCacheLine) {
                continue;
            }
            // either the ins ends in a new cacheline or begins on a new cacheline.
            
            INS_InsertCall(ins,
                           IPOINT_BEFORE,(AFUNPTR)AnalyzeCacheLineLevelReuse,
                           IARG_ADDRINT, prevCacheLine,
                           IARG_UINT32, numInsInCacheLine,
                           IARG_THREAD_ID, IARG_END);
            // Straddlers cacheline
            /*if (insStartCacheLine != insEndCacheLine){
             numInsInCacheLine = 1;
             } else {
             numInsInCacheLine = 1;
             }*/
            numInsInCacheLine = 1;
            prevCacheLine = insEndCacheLine;
        }
        
        INS_InsertCall(BBL_InsTail(bbl),
                       IPOINT_BEFORE, (AFUNPTR)AnalyzeCacheLineLevelReuse,
                       IARG_ADDRINT, prevCacheLine,
                       IARG_UINT32, numInsInCacheLine,
                       IARG_THREAD_ID, IARG_END);
        
    }
}

// On each Unload of a loaded image, the accummulated redundancy information is dumped
static VOID ImageUnload(IMG img, VOID* v) {
    fprintf(gTraceFile, "\n TODO .. Multi-threading is not well supported.");
    THREADID  threadid =  PIN_ThreadId();
    fprintf(gTraceFile, "\nUnloading %s", IMG_Name(img).c_str());
    PIN_LockClient();
    PIN_UnlockClient();
}

static VOID ThreadFiniFunc(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v) {
}

static void DumpHisto(uint64_t * histo){
    for(int i = 0; i < MAX_REUSE_DISTANCE_BINS; i++) {
        fprintf(gTraceFile, "\n %d %lu", i, histo[i]);
    }
}

/*
 static void PrintStats() {
 struct rusage rusage;
 getrusage(RUSAGE_SELF, &rusage);
 size_t peakRSS =  (size_t)(rusage.ru_maxrss);
 }
 
 */

static VOID FiniFunc(INT32 code, VOID *v) {
    THREADID  threadId =  PIN_ThreadId();
    InsReuseThreadData* tData = ClientGetTLS(threadId);
    fprintf(gTraceFile, "\nInstruction-reuse histo");
    DumpHisto(tData->insReuseHisto);
    fprintf(gTraceFile, "\nCL-reuse histo");
    DumpHisto(tData->clReuseHisto);
    
    
    fclose(gTraceFile);
}

static void InitThreadData(InsReuseThreadData* tdata){
    tdata->bytesLoad = 0;
    tdata->sampleFlag = true;
    tdata->numIns = 0;
    tdata->numCacheLines = 0x42; // the start of clock
    tdata->numInsExecuted = 0x42; // the start of clock
    
    memset(tdata->insReuseHisto, 0, sizeof(uint64_t) * MAX_REUSE_DISTANCE_BINS);
    memset(tdata->clReuseHisto, 0, sizeof(uint64_t) * MAX_REUSE_DISTANCE_BINS);
    
    /*    for (int i = 0; i < THREAD_MAX; ++i) {
     RedMap[i].set_empty_key(0);
     ApproxRedMap[i].set_empty_key(0);
     }
     */
}

static VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    InsReuseThreadData* tdata =  new InsReuseThreadData();
    InitThreadData(tdata);
    //    __sync_fetch_and_add(&gClientNumThreads, 1);
#ifdef MULTI_THREADED
    PIN_SetThreadData(client_tls_key, tdata, threadid);
#else
    gSingleThreadedTData = tdata;
#endif
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
    //PinCCTLibInit(INTERESTING_INS_ALL, gTraceFile, InstrumentInsCallback, 0);
    
    // Obtain  a key for TLS storage.
    client_tls_key = PIN_CreateThreadDataKey(0 /*TODO have a destructir*/);
    // Register ThreadStart to be called when a thread starts.
    PIN_AddThreadStartFunction(ThreadStart, 0);
    // fini function for post-mortem analysis
    PIN_AddThreadFiniFunction(ThreadFiniFunc, 0);
    PIN_AddFiniFunction(FiniFunc, 0);
    
    TRACE_AddInstrumentFunction(InstrumentTrace, 0);
    
    // Register ImageUnload to be called when an image is unloaded
    IMG_AddUnloadFunction(ImageUnload, 0);
    
    // Launch program now
    PIN_StartProgram();
    return 0;
}


