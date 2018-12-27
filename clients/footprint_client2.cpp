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
#include <sys/mman.h>
#include <sys/time.h>
#include <sstream>
#include "pin.H"
#include "cctlib.H"
using namespace std;
using namespace PinCCTLib;

#include <vector>
#include <algorithm>

#if __cplusplus > 199711L
#include <unordered_set>
#include <unordered_map>
#else
#include <hash_map>
#include <hash_set>
#define unordered_map hash_map
#define unordered_set hash_set
#endif //end  __cplusplus > 199711L


/* infrastructure for shadow memory */
/* MACROs */
// 64KB shadow pages
#define PAGE_OFFSET_BITS (16LL)
#define PAGE_OFFSET(addr) ( addr & 0xFFFF)
#define PAGE_OFFSET_MASK ( 0xFFFF)

#define SHADOW_MEM_PAGE_SIZE (1 << PAGE_OFFSET_BITS)

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

uint8_t ** gL1PageTable[LEVEL_1_PAGE_TABLE_SIZE];

/* Other footprint_client settings */
#define MAX_FOOTPRINT_CONTEXTS_TO_LOG (1000)

struct node_metric_t {
  unordered_set<uint64_t> addressSet;
  unordered_set<uint64_t> addressSetDecoded;
  uint64_t accessNum;
  uint64_t dependentNum;
};

struct sort_format_t {
  ContextHandle_t handle;
  uint64_t footprint;
  uint64_t fpNum;
  uint64_t accessNum;
  uint64_t dependentNum;
};

#define THREAD_MAX (1024)
unordered_map<uint32_t, struct node_metric_t> hmap_vector[THREAD_MAX];

static INT32 Usage() {
    PIN_ERROR("Pin tool to gather calling context on each load and store.\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

// Main for DeadSpy, initialize the tool, register instrumentation functions and call the target program.
FILE* gTraceFile;

struct timeval tv1;
__thread struct timeval tv2;
__thread struct timeval tv3;

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

/* helper functions for shadow memory */
uint8_t*
GetOrCreateShadowBaseAddress(uint64_t address)
{
  uint8_t *shadowPage;
  uint8_t ***l1Ptr = &gL1PageTable[LEVEL_1_PAGE_TABLE_SLOT(address)];
  if(*l1Ptr == 0) {
    *l1Ptr = (uint8_t **) calloc(1, LEVEL_2_PAGE_TABLE_SIZE);
    shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] =  (uint8_t *) mmap(0, SHADOW_MEM_PAGE_SIZE * (sizeof(bool) + sizeof(uint64_t)), PROT_WRITE | PROT_READ,  MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  }
  else if((shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)]) == 0 ){
    shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] =  (uint8_t *) mmap(0, SHADOW_MEM_PAGE_SIZE * (sizeof(bool) + sizeof(uint64_t)), PROT_WRITE | PROT_READ,  MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  }
  return shadowPage;
}

inline bool CheckDependence(uint64_t curAddr, uint64_t prevAddr)
{
    uint32_t lineNo1, lineNo2;
    string filePath1, filePath2;

    PIN_LockClient();
    PIN_GetSourceLocation(prevAddr, NULL, (INT32*) &lineNo1, &filePath1);
    PIN_GetSourceLocation(curAddr, NULL, (INT32*) &lineNo2, &filePath2);
    PIN_UnlockClient();
    
    if((filePath1.compare(filePath2) == 0) && (lineNo1 <= lineNo2)) return true;
    else return false;
}

VOID MemFunc(THREADID id, void* addr, bool rwFlag, UINT32 refSize) {
    uint64_t Addr = (uint64_t)addr;
    uint8_t* status = GetOrCreateShadowBaseAddress(Addr);
    uint64_t *prevAddr = (uint64_t *)(status + SHADOW_MEM_PAGE_SIZE +  PAGE_OFFSET(Addr) * sizeof(uint64_t));
    // check write-read(true and loop-carried) dependence
    bool *prevFlag = (bool *)(status + PAGE_OFFSET(Addr));

    // at memory instruction record the footprint
    void **metric = GetIPNodeMetric(id, 0);

    if (*metric == NULL) {
      // use ctxthndl as the key to associate footprint with the trace
      ContextHandle_t ctxthndl = GetContextHandle(id, 0);
      *metric = &(hmap_vector[id])[ctxthndl];
      (hmap_vector[id])[ctxthndl].addressSet.insert(Addr|(((uint64_t)refSize)<<48));
      (hmap_vector[id])[ctxthndl].accessNum+=refSize;
      
      // check how many times write to a shared address
      // shared means that this address is read/write before this write
      if (rwFlag && (*prevFlag))// && CheckDependence((uint64_t)addr, *prevAddr))
        (hmap_vector[id])[ctxthndl].dependentNum+=refSize;
    }
    else {
      (static_cast<struct node_metric_t*>(*metric))->addressSet.insert(Addr|(((uint64_t)refSize)<<48));
      (static_cast<struct node_metric_t*>(*metric))->accessNum+=refSize;
      if (!rwFlag && (*prevFlag))// && CheckDependence((uint64_t)addr, *prevAddr))
        (static_cast<struct node_metric_t*>(*metric))->dependentNum+=refSize;
    }
    // update the current read write flag  
    *prevFlag = true;
    *prevAddr = Addr;
}

VOID InstrumentInsCallback(INS ins, VOID* v, const uint32_t slot) {
    if (!INS_IsMemoryRead(ins) && !INS_IsMemoryWrite(ins)) return;
    if (INS_IsStackRead(ins) || INS_IsStackWrite(ins)) return;
    if (INS_IsBranchOrCall(ins) || INS_IsRet(ins)) return;
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {
        UINT32 refSize = INS_MemoryOperandSize(ins, memOp);
        if (INS_IsMemoryRead(ins))
          INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)MemFunc, IARG_THREAD_ID, IARG_MEMORYOP_EA, memOp, IARG_BOOL, false, IARG_UINT32, refSize, IARG_END);
        else
          INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)MemFunc, IARG_THREAD_ID, IARG_MEMORYOP_EA, memOp, IARG_BOOL, true, IARG_UINT32, refSize, IARG_END);
    }
}

void DecodingFootPrint(const THREADID threadid,  ContextHandle_t myHandle, ContextHandle_t parentHandle, void **myMetric, void **parentMetric)
{
    if (*myMetric == NULL) return;
    struct node_metric_t *hset = static_cast<struct node_metric_t*>(*myMetric);
    unordered_set<uint64_t>::iterator it;
    for (it = hset->addressSet.begin(); it!= hset->addressSet.end(); ++it) {
        uint64_t refSize = (*it)>>48;
        uint64_t addr = (*it) & ((1ULL<<48)-1);
        assert(refSize != 0);
        for(uint i=0; i<refSize; i++) {
          hset->addressSetDecoded.insert(addr+i);
        }
    }
//    hset->addressSet.clear();
}

void MergeFootPrint(const THREADID threadid,  ContextHandle_t myHandle, ContextHandle_t parentHandle, void **myMetric, void **parentMetric)
{
    if (*myMetric == NULL) return;
    struct node_metric_t *hset = static_cast<struct node_metric_t*>(*myMetric);

    if (*parentMetric == NULL) {
      *parentMetric = &((hmap_vector[threadid])[parentHandle]);
      (hmap_vector[threadid])[parentHandle].addressSetDecoded.insert(hset->addressSetDecoded.begin(), hset->addressSetDecoded.end());
      (hmap_vector[threadid])[parentHandle].addressSet.insert(hset->addressSet.begin(), hset->addressSet.end());
      (hmap_vector[threadid])[parentHandle].accessNum += hset->accessNum;
      (hmap_vector[threadid])[parentHandle].dependentNum += hset->dependentNum;
    }
    else {
      (static_cast<struct node_metric_t*>(*parentMetric))->addressSetDecoded.insert(hset->addressSetDecoded.begin(), hset->addressSetDecoded.end());
      (static_cast<struct node_metric_t*>(*parentMetric))->addressSet.insert(hset->addressSet.begin(), hset->addressSet.end());
      (static_cast<struct node_metric_t*>(*parentMetric))->accessNum += hset->accessNum;
      (static_cast<struct node_metric_t*>(*parentMetric))->dependentNum += hset->dependentNum;
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
	tmp.footprint = (uint64_t)(*it).second.addressSetDecoded.size();
	tmp.fpNum = (uint64_t)(*it).second.addressSet.size();
	tmp.accessNum =  (uint64_t)(*it).second.accessNum;
	tmp.dependentNum =  (uint64_t)(*it).second.dependentNum;
        TmpList.push_back(tmp);
    }
    sort(TmpList.begin(), TmpList.end(), FootPrintCompare);
    vector<struct sort_format_t>::iterator ListIt;
    for (ListIt = TmpList.begin(); ListIt != TmpList.end(); ++ListIt) {
      if (cntxtNum < MAX_FOOTPRINT_CONTEXTS_TO_LOG) {
        fprintf(gTraceFile, "Footprint is %llu Bytes, #distinct memory access is %llu, reuse is %llu, write dependence is %llu, context is:", ((*ListIt).footprint), (*ListIt).fpNum, (*ListIt).accessNum - (*ListIt).footprint, (*ListIt).dependentNum);
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
    gettimeofday(&tv2, NULL);
    // traverse CCT bottom to up
    // decode first
    TraverseCCTBottomUp(threadid, DecodingFootPrint);
    // merge second
    TraverseCCTBottomUp(threadid, MergeFootPrint);
    gettimeofday(&tv3, NULL);
    // print the footprint for functions
    PIN_LockClient();
    PrintTopFootPrintPath(threadid);
    fprintf(gTraceFile, "online collection time %lf, offline analysis time %lf\n",tv2.tv_sec-tv1.tv_sec+(tv2.tv_usec-tv1.tv_usec)/1000000.0, tv3.tv_sec-tv2.tv_sec+(tv3.tv_usec-tv2.tv_usec)/1000000.0);
    PIN_UnlockClient();
}

VOID FiniFunc(INT32 code, VOID *v)
{
    // do whatever you want to the full CCT with footpirnt
}

int main(int argc, char* argv[]) {
    
    gettimeofday(&tv1, NULL);
    // Initialize PIN
    if(PIN_Init(argc, argv))
        return Usage();

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

