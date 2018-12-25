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
#include <sstream>
#include <vector>
#include <algorithm>
#include <sys/time.h>
#include <sys/resource.h>
#include "pin.H"

#if __cplusplus > 199711L
#include <functional>
#include <unordered_set>
#include <unordered_map>
#else
#include <hash_map>
#define unordered_map hash_map
#endif //end  __cplusplus > 199711L


using namespace std;

static INT32 Usage() {
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
#define CACHE_LINE_BASE(addr) ((size_t)(addr) & (~CACHE_LINE_MASK)) 

#define CACHE_NUM_LINES (CACHE_SZ/CACHE_LINE_SZ)
#define CACHE_TAG_MASK (~CACHE_LINE_MASK)
#define CACHE_TAG(address) (((size_t)address) & CACHE_TAG_MASK)
#define CACHE_LINE_INDEX(address)  (((size_t)(address) & (CACHE_SZ - 1)) >> CACHE_LINE_BITS)
#define IS_VALID(address) (cache[CACHE_LINE_INDEX(((size_t)address))].isInUse &&  (cache[CACHE_LINE_INDEX(((size_t)address))].tag == CACHE_TAG(((size_t)address))))
#define SET_TAG(address) (cache[CACHE_LINE_INDEX(((size_t)address))].tag = CACHE_TAG(address))
#define SET_INUSE(address) (cache[CACHE_LINE_INDEX(((size_t)address))].isInUse = true)
#define GET_TAG(address) (cache[CACHE_LINE_INDEX(((size_t)address))].tag)
#define WAS_DIFFERENT(address) (cache[CACHE_LINE_INDEX(((size_t)address))].wasDifferent)


#define MAX_WRITE_OP_LENGTH (512)
#define MAX_WRITE_OPS_IN_INS (8)


struct Cache_t{
    size_t tag;
    bool isDirty;
    bool isInUse;
    bool wasDifferent;
    uint8_t value[CACHE_LINE_SZ];
    Cache_t(): tag(0), isDirty(false), isInUse(false), wasDifferent(false) {}
    void Reset(){
        tag = 0;
        isDirty = false;
        isInUse = false;
        wasDifferent = false;
    }
};

struct Stats_t{
    uint64_t sameData;
    uint64_t evicts;
    uint64_t unchanged;
    uint64_t dirtyEvicts;
    Stats_t() : sameData(0), evicts(0), unchanged(0), dirtyEvicts(0) {}
    void Reset() {
        sameData = 0;
        evicts = 0;
        unchanged = 0;
        dirtyEvicts = 0;
    }
    void AtomicMerge(Stats_t & s) {
        __atomic_add_fetch(&sameData, s.sameData, __ATOMIC_RELEASE);
        __atomic_add_fetch(&evicts, s.evicts, __ATOMIC_RELEASE);
        __atomic_add_fetch(&unchanged, s.unchanged, __ATOMIC_RELEASE);
        __atomic_add_fetch(&dirtyEvicts, s.dirtyEvicts, __ATOMIC_RELEASE);
    }
};

static Stats_t globalStats;

struct AddrValPair{
    void * address;
    uint8_t value[MAX_WRITE_OP_LENGTH];
};

struct RedSpyThreadData{
    AddrValPair buffer[MAX_WRITE_OPS_IN_INS];
    uint64_t bytesWritten;
    uint64_t bytesRedundant;
    Stats_t stats;
    Cache_t cache[CACHE_NUM_LINES];
};

static  TLS_KEY client_tls_key;
static RedSpyThreadData* gSingleThreadedTData;

// function to access thread-specific data
inline RedSpyThreadData* ClientGetTLS(const THREADID threadId) {
#ifdef MULTI_THREADED
    RedSpyThreadData* tdata =
    static_cast<RedSpyThreadData*>(PIN_GetThreadData(client_tls_key, threadId));
    return tdata;
#else
    return gSingleThreadedTData;
#endif
}


void CacheFlush(Cache_t *cache){
   #pragma omp simd
   for(int i = 0; i < CACHE_NUM_LINES; i++){
       cache[i].isInUse = false;
   }
}

static inline void OnEvict(void ** addr, RedSpyThreadData * tData) {
    Cache_t * cache = tData->cache;
    Stats_t & stats = tData->stats;

    uint64_t address = (uint64_t)addr;
    uint8_t * newValue = (uint8_t *) (address & (~CACHE_LINE_MASK));
    uint8_t * originalVal = cache[CACHE_LINE_INDEX(address)].value;
    bool isDirty = cache[CACHE_LINE_INDEX(address)].isDirty;
    uint8_t * curValue = (uint8_t *) (GET_TAG(address));

    if (isDirty && cache[CACHE_LINE_INDEX(((size_t)address))].isInUse) {
//        fprintf(stderr, "\n E: address=%lx, newValue=%p, originalVal=%p, curValue=%p, idx=%lx, tag=%lx\n", address, newValue, originalVal, curValue, CACHE_LINE_INDEX(address), GET_TAG(address));
        bool isRedundant = true;
        for(int i = 0; i < CACHE_LINE_SZ; i++){
            if(originalVal[i] != curValue[i]) {
                isRedundant = false;
                break;
            }
        }
    
        if (!WAS_DIFFERENT(address)) {
            stats.unchanged++;
        }
        if (isRedundant) {
            stats.sameData++;
        }
        cache[CACHE_LINE_INDEX(address)].isDirty = false;
        stats.dirtyEvicts++;
    } else {
  //      fprintf(stderr, "\n X: address=%lx, newValue=%p, originalVal=%p, curValue=%p, idx=%lx, tag=%lx\n", address, newValue, originalVal, curValue, CACHE_LINE_INDEX(address), GET_TAG(address));
    }
    #pragma omp simd
    for(int i = 0; i < CACHE_LINE_SZ; i++){
        originalVal[i] = newValue[i];
    }
    stats.evicts++;
    SET_TAG(address);
    WAS_DIFFERENT(address) = false;
}

static inline void HandleOneCacheLine(void ** address, bool isWrite, RedSpyThreadData * tData){
    Cache_t * cache = tData->cache;
    if(!IS_VALID(address)) {
        // cache miss, allocate it.
        OnEvict(address, tData);
    }
    SET_INUSE(address);
   // set dirty if write
   if(isWrite)
        cache[CACHE_LINE_INDEX(address)].isDirty = true;
}

static inline void OnAccess(void ** address, uint64_t accessLen, bool isWrite, THREADID threadId){
    RedSpyThreadData*  tData = ClientGetTLS(threadId);
    // Is within cache line?
    if(CACHE_LINE_INDEX(address) == CACHE_LINE_INDEX((size_t)(address) + accessLen - 1)) {
        HandleOneCacheLine(address, isWrite, tData);
    } else {
        for(void ** cur = address; cur < address + accessLen; cur += CACHE_LINE_SZ){
            HandleOneCacheLine(cur, isWrite, tData);
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
    fprintf(gTraceFile, "CONFIG:\n");
    fprintf(gTraceFile, "CACHE_SZ:%lu\n", CACHE_SZ);
    fprintf(gTraceFile, "---------------\n");
    // print the arguments passed
    fprintf(gTraceFile, "\n");
    
    for(int i = 0 ; i < argc; i++) {
        fprintf(gTraceFile, "%s ", argv[i]);
    }
    
    fprintf(gTraceFile, "\n");
    fflush(gTraceFile);
}



template<uint16_t AccessLen, uint32_t bufferOffset>
struct RedSpyAnalysis{
    static __attribute__((always_inline)) bool IsPartialWriteRedundant(size_t startOffset, size_t length, THREADID threadId){
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        AddrValPair * avPair = & tData->buffer[bufferOffset];
        return memcmp(avPair->value + startOffset, (void **)(avPair->address) + startOffset, length) == 0;
    }

    static __attribute__((always_inline)) bool IsWriteRedundant(void * &addr, THREADID threadId){
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        AddrValPair * avPair = & tData->buffer[bufferOffset];
        addr = avPair->address;
        switch(AccessLen){
            case 1: return *((uint8_t*)(&avPair->value)) == *(static_cast<uint8_t*>(avPair->address));
            case 2: return *((uint16_t*)(&avPair->value)) == *(static_cast<uint16_t*>(avPair->address));
            case 4: return *((uint32_t*)(&avPair->value)) == *(static_cast<uint32_t*>(avPair->address));
            case 8: return *((uint64_t*)(&avPair->value)) == *(static_cast<uint64_t*>(avPair->address));
            default: return memcmp(&avPair->value, avPair->address, AccessLen) == 0;
        }
    }
    static __attribute__((always_inline)) VOID RecordNByteValueBeforeWrite(void* addr, THREADID threadId){
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        AddrValPair * avPair = & tData->buffer[bufferOffset];
        avPair->address = addr;
        switch(AccessLen){
            case 1: *((uint8_t*)(&avPair->value)) = *(static_cast<uint8_t*>(addr)); break;
            case 2: *((uint16_t*)(&avPair->value)) = *(static_cast<uint16_t*>(addr)); break;
            case 4: *((uint32_t*)(&avPair->value)) = *(static_cast<uint32_t*>(addr)); break;
            case 8: *((uint64_t*)(&avPair->value)) = *(static_cast<uint64_t*>(addr)); break;
            default:memcpy(&avPair->value, addr, AccessLen);
        }
    }
    static __attribute__((always_inline)) VOID CheckNByteValueAfterWrite(THREADID threadId){
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        Cache_t * cache = tData->cache;
        void * addr;
        bool isRedundantWrite = IsWriteRedundant(addr, threadId);
        if(isRedundantWrite) {
            tData->bytesRedundant += AccessLen;
            // increment the metric
        } else {
            bool isSameCacheLine = CACHE_LINE_INDEX(addr) == CACHE_LINE_INDEX((size_t)(addr) + AccessLen - 1);
            if(isSameCacheLine){
                if(!WAS_DIFFERENT(addr))
                	WAS_DIFFERENT(addr) = true;
            }else {
                size_t firstCacheLineAccessLength = CACHE_LINE_BASE(addr) + CACHE_LINE_SZ - (size_t)(addr);
                size_t firstCacheLineStart = 0;
                size_t lastCacheLineAccessLength = (size_t) addr + AccessLen - CACHE_LINE_BASE((size_t)addr + AccessLen - 1);
                size_t lastCacheLineStart = CACHE_LINE_BASE((size_t)(addr) + AccessLen - 1) - (size_t)(addr);
                
                if( (!WAS_DIFFERENT(addr)) && IsPartialWriteRedundant(firstCacheLineStart, firstCacheLineAccessLength, threadId)){
                    WAS_DIFFERENT(addr) = true;
                }
                if( (!WAS_DIFFERENT(addr + AccessLen - 1)) && IsPartialWriteRedundant(lastCacheLineStart, lastCacheLineAccessLength, threadId)){
                    WAS_DIFFERENT(addr + AccessLen - 1) = true;
                }
                for(size_t startOffset = firstCacheLineAccessLength ;  startOffset < lastCacheLineStart; startOffset += CACHE_LINE_SZ){
                    if((!WAS_DIFFERENT(addr + startOffset)) && IsPartialWriteRedundant(startOffset, CACHE_LINE_SZ, threadId))
                        WAS_DIFFERENT(addr + startOffset) = true;
                }
            }
        }
    }
};

static inline VOID RecordValueBeforeLargeWrite(void* addr, UINT32 accessLen,  uint32_t bufferOffset, THREADID threadId){
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    memcpy(& (tData->buffer[bufferOffset].value), addr, accessLen);
    tData->buffer[bufferOffset].address = addr;
}

static inline VOID CheckAfterLargeWrite(UINT32 accessLen,  uint32_t bufferOffset, THREADID threadId){
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    Cache_t * cache = tData->cache;

    size_t  addr = (size_t) (tData->buffer[bufferOffset].address);
    if(memcmp(tData->buffer[bufferOffset].value, (void *)addr, accessLen) == 0){
        tData->bytesRedundant += accessLen;
    }else{
        size_t firstCacheLineAccessLength = CACHE_LINE_BASE(addr) + CACHE_LINE_SZ - (size_t)(addr);
        size_t firstCacheLineStart = 0;
        size_t lastCacheLineAccessLength = addr + accessLen - CACHE_LINE_BASE((size_t)(addr) + accessLen - 1);
        size_t lastCacheLineStart = CACHE_LINE_BASE((size_t)(addr) + accessLen - 1) - addr;
        
        if( (!WAS_DIFFERENT(addr)) && (0 == memcmp((void *) (tData->buffer[bufferOffset].value + firstCacheLineStart), (void *) ( addr + firstCacheLineStart), firstCacheLineAccessLength))){
            WAS_DIFFERENT(addr) = true;
        }
        if( (!WAS_DIFFERENT(addr + accessLen - 1)) && (0 == memcmp((void *) (tData->buffer[bufferOffset].value + lastCacheLineStart), (void *) (addr + lastCacheLineStart), lastCacheLineAccessLength))){
            WAS_DIFFERENT(addr + accessLen - 1) = true;
        }
        for(size_t startOffset = firstCacheLineAccessLength ;  startOffset < lastCacheLineStart; startOffset += CACHE_LINE_SZ){
            if((!WAS_DIFFERENT(addr + startOffset)) && (0 == memcmp((void *) (tData->buffer[bufferOffset].value), (void *)(addr + startOffset), CACHE_LINE_SZ)))
                WAS_DIFFERENT(addr + startOffset) = true;
        }
    }
}
#define HANDLE_CASE(NUM, BUFFER_INDEX, HAS_FALLTHRU) \
case (NUM):{INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) RedSpyAnalysis<(NUM), (BUFFER_INDEX)>::RecordNByteValueBeforeWrite, IARG_MEMORYOP_EA, memOp, IARG_THREAD_ID, IARG_END);\
    INS_InsertPredicatedCall(ins, HAS_FALLTHRU? IPOINT_AFTER : IPOINT_TAKEN_BRANCH, (AFUNPTR) RedSpyAnalysis<(NUM), (BUFFER_INDEX)>::CheckNByteValueAfterWrite, IARG_THREAD_ID, IARG_INST_PTR,IARG_END);}break

#define HANDLE_LARGE(HAS_FALLTHRU) \
INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) RecordValueBeforeLargeWrite, IARG_MEMORYOP_EA, memOp, IARG_MEMORYWRITE_SIZE, IARG_UINT32, readBufferSlotIndex, IARG_THREAD_ID, IARG_END);\
INS_InsertPredicatedCall(ins, HAS_FALLTHRU? IPOINT_AFTER : IPOINT_TAKEN_BRANCH, (AFUNPTR) CheckAfterLargeWrite, IARG_MEMORYREAD_SIZE, IARG_UINT32, readBufferSlotIndex, IARG_THREAD_ID, IARG_END)

static int GetNumWriteOperandsInIns(INS ins, UINT32 & whichOp){
    int numWriteOps = 0;
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    for(UINT32 memOp = 0; memOp < memOperands; memOp++) {
        if (INS_MemoryOperandIsWritten(ins, memOp)) {
            numWriteOps++;
            whichOp = memOp;
        }
    }
    return numWriteOps;
}


template<uint32_t readBufferSlotIndex>
struct RedSpyInstrument{
    static __attribute__((always_inline)) void InstrumentReadValueBeforeAndAfterWriting(INS ins, UINT32 memOp, bool hasFallThru){
        UINT32 refSize = INS_MemoryOperandSize(ins, memOp);
        switch(refSize) {
                HANDLE_CASE(1, readBufferSlotIndex, hasFallThru);
                HANDLE_CASE(2, readBufferSlotIndex, hasFallThru);
                HANDLE_CASE(4, readBufferSlotIndex, hasFallThru);
                HANDLE_CASE(8, readBufferSlotIndex, hasFallThru);
                HANDLE_CASE(10, readBufferSlotIndex, hasFallThru);
                HANDLE_CASE(16, readBufferSlotIndex, hasFallThru);
            default: {
                HANDLE_LARGE(hasFallThru);
            }
        }
    }
};



static VOID InstrumentInsCallback(INS ins, VOID* v) {
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    if (memOperands == 0)
        return;

    for(UINT32 memOp = 0; memOp < memOperands; memOp++) {
         if(INS_MemoryOperandIsWritten(ins, memOp)) {
             INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) OnAccess, IARG_MEMORYOP_EA, memOp, IARG_MEMORYWRITE_SIZE, IARG_BOOL, 1, IARG_THREAD_ID, IARG_END);
         } else {
             INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) OnAccess, IARG_MEMORYOP_EA, memOp, IARG_MEMORYREAD_SIZE, IARG_BOOL, 0,  IARG_THREAD_ID, IARG_END);
        }
    }

// Now do the redSpy business

   bool hasFallThu = INS_HasFallThrough(ins);
    
    // Special case, if we have only one write operand
    
    UINT32 whichOp = 0;
    
    if(GetNumWriteOperandsInIns(ins, whichOp) == 1){
        // Read the value at location before and after the instruction
        RedSpyInstrument<0>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, hasFallThu);
    }else{
        
        UINT32 memOperands = INS_MemoryOperandCount(ins);
        
        int readBufferSlotIndex=0;
        
        for(UINT32 memOp = 0; memOp < memOperands; memOp++) {
            if(!INS_MemoryOperandIsWritten(ins, memOp))
                continue;
            switch (readBufferSlotIndex) {
                case 0:
                    // Read the value at location before and after the instruction
                    RedSpyInstrument<0>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, hasFallThu);
                    break;
                case 1:
                    // Read the value at location before and after the instruction
                    RedSpyInstrument<1>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, hasFallThu);
                    break;
                case 2:
                    // Read the value at location before and after the instruction
                    RedSpyInstrument<2>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, hasFallThu);
                    break;
                case 3:
                    // Read the value at location before and after the instruction
                    RedSpyInstrument<3>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, hasFallThu);
                    break;
                case 4:
                    // Read the value at location before and after the instruction
                    RedSpyInstrument<4>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, hasFallThu);
                    break;
                default:
                    assert(0 && "NYI");
                    break;
            }
            // use next slot for the next write operand
            readBufferSlotIndex++;
        }
    }

}

    size_t getPeakRSS() {
#if (PIN_PRODUCT_VERSION_MAJOR >= 3) && (PIN_PRODUCT_VERSION_MINOR >= 7)
        // What a shame
        return (0);
#else
        struct rusage u;
        getrusage(RUSAGE_SELF, &u);
        return (size_t)(u.ru_maxrss);
#endif
    }


static VOID FiniFunc(INT32 code, VOID *v) {
    Stats_t s;
    s.AtomicMerge(globalStats); // So that we get latest;
    fprintf(gTraceFile, "\n Total evict=%lu, dirtyEvicts=%lu, redundant=%lu, unchanged=%lu, waste=%f, cacheFixable=%f, Peak RSS=%zu\n",
            s.evicts, s.dirtyEvicts, s.sameData, s.unchanged, 100.0 * globalStats.sameData/ s.dirtyEvicts, 100.0 * s.unchanged/ s.dirtyEvicts, getPeakRSS());
}

static VOID ImageUnload(IMG img, VOID* v) {
//fprintf(stderr, "\n ImageUnload\n");
    // TODO: Should we flush?    CacheFlush();
}

static void HandleSysCall(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v){
//fprintf(stderr, "\n HandleSysCall\n");
        RedSpyThreadData* tData = ClientGetTLS(threadIndex);
        CacheFlush(tData->cache);
}

inline VOID Update(uint32_t bytes, THREADID threadId){
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    tData->bytesWritten += bytes;
}

//instrument the trace, count the number of ins in the trace, decide to instrument or not
static void InstrumentTrace(TRACE trace, void* f) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        uint32_t totBytes = 0;
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if(INS_IsMemoryWrite(ins)) {
                totBytes += INS_MemoryWriteSize(ins);
            }
        }
        BBL_InsertCall(bbl,IPOINT_ANYWHERE,(AFUNPTR)Update, IARG_UINT32, totBytes, IARG_THREAD_ID, IARG_END);
    }
}


static VOID ThreadFiniFunc(THREADID threadId, const CONTEXT *ctxt, INT32 code, VOID *v) {
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    Stats_t & stats = tData->stats;
    fprintf(gTraceFile, "\n thread = %d, Total evict=%lu, dirtyEvicts=%lu, redundant=%lu, unchanged=%lu, waste=%f, cacheFixable=%f, Bytes written=%lu, Bytes redundant=%lu, redundant=%f\n", threadId, stats.evicts, stats.dirtyEvicts, stats.sameData, stats.unchanged, 100.0 * stats.sameData/ stats.dirtyEvicts, 100.0 * stats.unchanged/ stats.dirtyEvicts, tData->bytesWritten, tData->bytesRedundant, 100.0 * tData->bytesRedundant/ tData->bytesWritten);
    globalStats.AtomicMerge(stats);
}

static void InitThreadData(RedSpyThreadData* tdata){
    tdata->bytesWritten = 0;
    tdata->bytesRedundant = 0;
    tdata->stats.Reset();
    for(int i = 0; i < CACHE_NUM_LINES; i++)
        tdata->cache[i].Reset();
}

static VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    RedSpyThreadData* tdata = new RedSpyThreadData();
    InitThreadData(tdata);
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
     
    // Obtain  a key for TLS storage.
    client_tls_key = PIN_CreateThreadDataKey(0 /*TODO have a destructir*/);
    // Register ThreadStart to be called when a thread starts.
    PIN_AddThreadStartFunction(ThreadStart, 0);
    
    
    // fini function for post-mortem analysis
    PIN_AddThreadFiniFunction(ThreadFiniFunc, 0);
  
    // Register SyscallEntry
    PIN_AddSyscallEntryFunction (HandleSysCall, 0);
    // PIN_AddSyscallExitFunction (HandleSysCall, 0);

    INS_AddInstrumentFunction(InstrumentInsCallback, 0); 
    // fini function for post-mortem analysis
    PIN_AddFiniFunction(FiniFunc, 0);
    
    TRACE_AddInstrumentFunction(InstrumentTrace, 0);


    // Launch program now
    PIN_StartProgram();
    return 0;
}


