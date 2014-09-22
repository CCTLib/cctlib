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
#include "pin.H"
#include "cctlib.H"
using namespace std;
using namespace PinCCTLib;

#include <unordered_set>
#include <vector>
#include <unordered_map>
#include <algorithm>

/* infrastructure for shadow memory */
/* MACROs */
// 64KB shadow pages
#define PAGE_OFFSET_BITS (16LL)
#define PAGE_OFFSET(addr) ( addr & 0xFFFF)
#define PAGE_OFFSET_MASK ( 0xFFFF)

#define PAGE_SIZE (1 << PAGE_OFFSET_BITS)

// 2 level page table
#define PTR_SIZE (sizeof(struct Status *))
#define LEVEL_1_PAGE_TABLE_BITS  (20)
#define LEVEL_1_PAGE_TABLE_ENTRIES  (1 << LEVEL_1_PAGE_TABLE_BITS )
#define LEVEL_1_PAGE_TABLE_SIZE  (LEVEL_1_PAGE_TABLE_ENTRIES * PTR_SIZE )

#define LEVEL_2_PAGE_TABLE_BITS  (12)
#define LEVEL_2_PAGE_TABLE_ENTRIES  (1 << LEVEL_2_PAGE_TABLE_BITS )
#define LEVEL_2_PAGE_TABLE_SIZE  (LEVEL_2_PAGE_TABLE_ENTRIES * PTR_SIZE )

#define LEVEL_1_PAGE_TABLE_SLOT(addr) (((addr) >> (LEVEL_2_PAGE_TABLE_BITS + PAGE_OFFSET_BITS)) & 0xfffff)
#define LEVEL_2_PAGE_TABLE_SLOT(addr) (((addr) >> (PAGE_OFFSET_BITS)) & 0xFFF)



/* Other footprint_client settings */
#define MAX_FOOTPRINT_CONTEXTS_TO_LOG (1000)
#define THREAD_MAX (1024)

#define ENCODE_ADDRESS_AND_ACCESS_LEN(addr, len) ( (addr) | (((uint64_t)(len)) << 48))
#define DECODE_ADDRESS(addrAndLen) ( (addrAndLen) & ((1L<<48) - 1))
#define DECODE_ACCESS_LEN(addrAndLen) ( (addrAndLen) >> 48)

struct RawMetric_t {
    unordered_set<uint64_t> addressSet;
    unordered_set<uint64_t> addressSetDecoded;
    uint64_t accessNum;
    uint64_t dependentNum;
};

struct AnalyzedMetric_t {
    ContextHandle_t handle;
    uint64_t footprint;
    uint64_t accessNum;
    uint64_t dependentNum;
};

static unordered_map<uint32_t, struct RawMetric_t> * hmap_vector;

INT32 Usage2() {
    PIN_ERROR("Pin tool to gather calling context on each load and store.\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

// Main for DeadSpy, initialize the tool, register instrumentation functions and call the target program.
static FILE* gTraceFile;
static uint8_t ** gL1PageTable[LEVEL_1_PAGE_TABLE_SIZE];

// Initialized the needed data structures before launching the target program
static void ClientInit(int argc, char* argv[]) {
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
    // Initialize hmap_vector
    hmap_vector = new unordered_map<uint32_t, struct RawMetric_t>[THREAD_MAX];
    fprintf(gTraceFile, "\n");
}

/* helper functions for shadow memory */
static uint8_t* GetOrCreateShadowBaseAddress(uint64_t address) {
    uint8_t *shadowPage;
    uint8_t ***l1Ptr = &gL1PageTable[LEVEL_1_PAGE_TABLE_SLOT(address)];
    if(*l1Ptr == 0) {
        *l1Ptr = (uint8_t **) calloc(1, LEVEL_2_PAGE_TABLE_SIZE);
        shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] =  (uint8_t *) mmap(0, PAGE_SIZE * (sizeof(bool) + sizeof(uint64_t)), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    } else if((shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)]) == 0 ){
        shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] =  (uint8_t *) mmap(0, PAGE_SIZE * (sizeof(bool) + sizeof(uint64_t)), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    }
    return shadowPage;
}

static inline bool CheckDependence(uint64_t curAddr, uint64_t prevAddr) {
    uint32_t lineNo1, lineNo2;
    string filePath1, filePath2;
    
    PIN_LockClient();
    PIN_GetSourceLocation(prevAddr, NULL, (INT32*) &lineNo1, &filePath1);
    PIN_GetSourceLocation(curAddr, NULL, (INT32*) &lineNo2, &filePath2);
    PIN_UnlockClient();
    
    if((filePath1.compare(filePath2) == 0) && (lineNo1 <= lineNo2)) return true;
    else return false;
}

static VOID MemFunc(THREADID id, void* address, bool rwFlag, UINT32 refSize) {
    uint64_t addr = (uint64_t)address;
    uint8_t* status = GetOrCreateShadowBaseAddress(addr);
    uint64_t *prevAddr = (uint64_t *)(status + PAGE_SIZE +  PAGE_OFFSET(addr) * sizeof(uint64_t));
    // check write-read(true and loop-carried) dependence
    bool *prevFlag = (bool *)(status + PAGE_OFFSET(addr));
    
    uint64_t encodedAddrAndLen = ENCODE_ADDRESS_AND_ACCESS_LEN(addr, refSize);
    
    // at memory instruction record the footprint
    void **metricPtr = GetIPNodeMetric(id, 0);
    RawMetric_t *metric;
    
    if (*metricPtr == NULL) {
        // use ctxthndl as the key to associate footprint with the trace
        ContextHandle_t ctxthndl = GetContextHandle(id, 0);
        *metricPtr = &(hmap_vector[id])[ctxthndl];
    }
    metric = (static_cast<struct RawMetric_t*>(*metricPtr));
    metric->addressSet.insert(encodedAddrAndLen);
    metric->accessNum+=refSize;
    if (!rwFlag && (*prevFlag))// && CheckDependence((uint64_t)addr, *prevAddr))
        metric->dependentNum+=refSize;
    // update the current read write flag
    *prevFlag = rwFlag;
    *prevAddr = addr;
}

template<uint16_t AccessLen>
struct FootPrintAnalysis{
    static inline void UpdateFootPrint(uint64_t address, THREADID threadId){
        uint64_t encodedAddrAndLen = ENCODE_ADDRESS_AND_ACCESS_LEN(address, AccessLen);
        // at memory instruction record the footprint
        void **metricPtr = GetIPNodeMetric(threadId, 0);
        RawMetric_t *metric;
        
        if (*metricPtr == NULL) {
            // use ctxthndl as the key to associate footprint with the trace
            ContextHandle_t ctxthndl = GetContextHandle(threadId, 0);
            *metricPtr = &(hmap_vector[threadId])[ctxthndl];
        }
        metric = (static_cast<struct RawMetric_t*>(*metricPtr));
        metric->addressSet.insert(encodedAddrAndLen);
        metric->accessNum+=AccessLen;
    }
};


template<uint16_t AccessLen>
struct MemAnalysis{
    static inline VOID RecordNByteMemAccess(void* addr,  bool accessType, THREADID threadId){
        FootPrintAnalysis<AccessLen>::UpdateFootPrint((uint64_t)addr, threadId);
        
        /*
        uint8_t* status = GetOrCreateShadowBaseAddress(addr);
        const uint32_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
        // status == 0 if not created.
        if(PAGE_OFFSET((uint64_t)addr) < (PAGE_OFFSET_MASK - 2)) {
            uint32_t* lastIP = (uint32_t*)(status + PAGE_SIZE +  PAGE_OFFSET((uint64_t)addr) * sizeof(uint32_t));
            uint32_t state = *((uint32_t*)(status +  PAGE_OFFSET((uint64_t)addr)));
            
            if(state != FOUR_BYTE_READ_ACTION) {
                DECLARE_HASHVAR(myhash);
                uint32_t ipZero = lastIP[0];
                
                // fast path where all bytes are dead by same context
                if(state == FOUR_BYTE_WRITE_ACTION &&
                   ipZero == lastIP[0] && ipZero == lastIP[1] && ipZero  == lastIP[2] && ipZero  == lastIP[3]) {
                    REPORT_DEAD(curCtxtHandle, ipZero, myhash, 4);
                    // State is already written, so no need to dead write in a tool that detects dead writes
                } else {
                    // slow path
                    // byte 1 dead ?
                    REPORT_IF_DEAD(0x000000ff, curCtxtHandle, ipZero, myhash);
                    // byte 2 dead ?
                    REPORT_IF_DEAD(0x0000ff00, curCtxtHandle, lastIP[1], myhash);
                    // byte 3 dead ?
                    REPORT_IF_DEAD(0x00ff0000, curCtxtHandle, lastIP[2], myhash);
                    // byte 4 dead ?
                    REPORT_IF_DEAD(0xff000000, curCtxtHandle, lastIP[3], myhash);
                    // update state for all
                    *((uint32_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = FOUR_BYTE_WRITE_ACTION;
                }
            } else {
                // record as written
                *((uint32_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = FOUR_BYTE_WRITE_ACTION;
            }
#pragma unroll (AccessLen)
            for(uint16_t i = 0; i < AccessLen; i++) {
                lastIP[i] = curCtxtHandle;
            }
        } else {
#pragma unroll (AccessLen)
            for(uint16_t i = 0; i < AccessLen; i++) {
                MemAnalysis<1>::RecordNByteMemAccess(((char*) addr) + i, accessType, threadId);
            }
        }
*/
    }
};

template<>
struct MemAnalysis<1>{
    inline static VOID RecordNByteMemAccess(void* addr,  bool accessType, THREADID threadId){
        FootPrintAnalysis<1>::UpdateFootPrint((uint64_t)addr, threadId);
/*
        uint8_t* status = GetOrCreateShadowBaseAddress(addr);
        const uint32_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
        // Specialize ... TODO
*/
    }
};

#define HANDLE_CASE(n) case n: {\
                       if(INS_MemoryOperandIsRead(ins, memOp)) {\
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) MemAnalysis<n>::RecordNByteMemAccess, IARG_MEMORYOP_EA, memOp,IARG_BOOL, false, IARG_THREAD_ID, IARG_END);\
                        } else {\
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) MemAnalysis<n>::RecordNByteMemAccess, IARG_MEMORYOP_EA, memOp,IARG_BOOL, true, IARG_THREAD_ID, IARG_END);\
                        }




static VOID InstrumentInsCallback(INS ins, VOID* v, const uint32_t slot) {
    if (!INS_IsMemoryRead(ins) && !INS_IsMemoryWrite(ins)) return;
    if (INS_IsStackRead(ins) || INS_IsStackWrite(ins)) return;
    if (INS_IsBranchOrCall(ins) || INS_IsRet(ins)) return;
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    
    for(UINT32 memOp = 0; memOp < memOperands; memOp++) {
        UINT32 refSize = INS_MemoryOperandSize(ins, memOp);

#ifndef DEV
        if (INS_IsMemoryRead(ins))
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)MemFunc, IARG_THREAD_ID, IARG_MEMORYOP_EA, memOp, IARG_BOOL, false, IARG_UINT32, refSize, IARG_END);
        else
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)MemFunc, IARG_THREAD_ID, IARG_MEMORYOP_EA, memOp, IARG_BOOL, true, IARG_UINT32, refSize, IARG_END);
        
#else
        switch(refSize) {
                
            HANDLE_CASE(1): break;
            HANDLE_CASE(2): break;
            HANDLE_CASE(4): break;
            HANDLE_CASE(8): break;
            HANDLE_CASE(10): break;
            HANDLE_CASE(16): break;
                
            default: {
                // seeing some stupid 512 (fxsave)byte operations. Suspecting REP-instructions.
                if(INS_MemoryOperandIsRead(ins, memOp)) {
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) RecordLargeMemRead, IARG_MEMORYOP_EA, memOp, IARG_MEMORYREAD_SIZE, IARG_THREAD_ID, IARG_END);
                }
                
                if(INS_MemoryOperandIsWritten(ins, memOp)) {
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                             (AFUNPTR) RecordLargeMemWrite,
                                             IARG_MEMORYOP_EA, memOp, IARG_MEMORYWRITE_SIZE,
                                             //IARG_UINT32, opaqueHandle,
                                             IARG_THREAD_ID, IARG_END);
                }
            }
                break;
                //assert( 0 && "BAD refSize");
        }
#endif
    }
}

static void DecodingFootPrint(const THREADID threadid,  ContextHandle_t myHandle, ContextHandle_t parentHandle, void **myMetric, void **parentMetric) {
    if (*myMetric == NULL) return;
    struct RawMetric_t *hset = static_cast<struct RawMetric_t*>(*myMetric);
    unordered_set<uint64_t>::iterator it;
    for (it = hset->addressSet.begin(); it!= hset->addressSet.end(); ++it) {
        uint64_t refSize = DECODE_ACCESS_LEN(*it);
        uint64_t addr = DECODE_ADDRESS(*it);
        assert(refSize != 0);
        for(uint i=0; i<refSize; i++) {
            hset->addressSetDecoded.insert(addr+i);
        }
    }
    hset->addressSet.clear();
}

static void MergeFootPrint(const THREADID threadid,  ContextHandle_t myHandle, ContextHandle_t parentHandle, void **myMetric, void **parentMetric) {
    if (*myMetric == NULL) return;
    struct RawMetric_t *hset = static_cast<struct RawMetric_t*>(*myMetric);
    
    if (*parentMetric == NULL) {
        *parentMetric = &((hmap_vector[threadid])[parentHandle]);
        (hmap_vector[threadid])[parentHandle].addressSetDecoded.insert(hset->addressSetDecoded.begin(), hset->addressSetDecoded.end());
        (hmap_vector[threadid])[parentHandle].accessNum += hset->accessNum;
        (hmap_vector[threadid])[parentHandle].dependentNum += hset->dependentNum;
    } else {
        (static_cast<struct RawMetric_t*>(*parentMetric))->addressSetDecoded.insert(hset->addressSetDecoded.begin(), hset->addressSetDecoded.end());
        (static_cast<struct RawMetric_t*>(*parentMetric))->accessNum += hset->accessNum;
        (static_cast<struct RawMetric_t*>(*parentMetric))->dependentNum += hset->dependentNum;
    }
}


static inline bool FootPrintCompare(const struct AnalyzedMetric_t &first, const struct AnalyzedMetric_t &second) {
    return first.footprint > second.footprint ? true : false;
}

static void PrintTopFootPrintPath(THREADID threadid) {
    uint64_t cntxtNum = 0;
    vector<struct AnalyzedMetric_t> TmpList;
    
    fprintf(gTraceFile, "*************** Dump Data from Thread %d ****************\n", threadid);
    unordered_map<uint32_t, struct RawMetric_t> &hmap = hmap_vector[threadid];
    unordered_map<uint32_t, struct RawMetric_t>::iterator it;
    for (it = hmap.begin(); it != hmap.end(); ++it) {
        struct AnalyzedMetric_t tmp;
        tmp.handle = (*it).first;
        tmp.footprint = (uint64_t)(*it).second.addressSetDecoded.size();
        tmp.accessNum =  (uint64_t)(*it).second.accessNum;
        tmp.dependentNum =  (uint64_t)(*it).second.dependentNum;
        TmpList.emplace_back(tmp);
    }
    sort(TmpList.begin(), TmpList.end(), FootPrintCompare);
    vector<struct AnalyzedMetric_t>::iterator ListIt;
    for (ListIt = TmpList.begin(); ListIt != TmpList.end(); ++ListIt) {
        if (cntxtNum < MAX_FOOTPRINT_CONTEXTS_TO_LOG) {
            fprintf(gTraceFile, "Footprint is %lu, #reuse factor is %lf, true dependence is %lu, context is:", ((*ListIt).footprint), (double)(*ListIt).accessNum/(*ListIt).footprint, (*ListIt).dependentNum);
            PrintFullCallingContext((*ListIt).handle);
            fprintf(gTraceFile, "\n------------------------------------------------\n");
        }
        else {
            break;
        }
        cntxtNum++;
    }
}

static VOID ThreadFiniFunc(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v) {
    // traverse CCT bottom to up
    // decode first
    TraverseCCTBottomUp(threadid, DecodingFootPrint);
    // merge second
    TraverseCCTBottomUp(threadid, MergeFootPrint);
    // print the footprint for functions
    PIN_LockClient();
    PrintTopFootPrintPath(threadid);
    PIN_UnlockClient();
}

static VOID FiniFunc(INT32 code, VOID *v) {
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

