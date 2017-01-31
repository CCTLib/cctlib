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
#include <list>
#include <sys/mman.h>
#include <sstream>
#include <functional>
#include <unordered_set>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include "pin.H"
#include "cctlib.H"
extern "C" {
#include "xed-interface.h"
#include "xed-common-hdrs.h"
}

using namespace std;
using namespace PinCCTLib;

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


// have R, W representative macros
#define READ_ACTION (0)
#define WRITE_ACTION (0xff)

#define ONE_BYTE_READ_ACTION (0)
#define TWO_BYTE_READ_ACTION (0)
#define FOUR_BYTE_READ_ACTION (0)
#define EIGHT_BYTE_READ_ACTION (0)

#define ONE_BYTE_WRITE_ACTION (0xff)
#define TWO_BYTE_WRITE_ACTION (0xffff)
#define FOUR_BYTE_WRITE_ACTION (0xffffffff)
#define EIGHT_BYTE_WRITE_ACTION (0xffffffffffffffff)



#define IS_ACCESS_WITHIN_PAGE_BOUNDARY(accessAddr, accessLen)  (PAGE_OFFSET((accessAddr)) <= (PAGE_OFFSET_MASK - (accessLen)))

/* Other footprint_client settings */
#define MAX_REDUNDANT_CONTEXTS_TO_LOG (400)
#define THREAD_MAX (1024)

#define ENCODE_ADDRESS_AND_ACCESS_LEN(addr, len) ( (addr) | (((uint64_t)(len)) << 48))
#define DECODE_ADDRESS(addrAndLen) ( (addrAndLen) & ((1L<<48) - 1))
#define DECODE_ACCESS_LEN(addrAndLen) ( (addrAndLen) >> 48)


#define MAX_WRITE_OP_LENGTH (512)
#define MAX_WRITE_OPS_IN_INS (8)

#ifdef ENABLE_SAMPLING

#define WINDOW_ENABLE 1000000
#define WINDOW_DISABLE 1000000000

#endif

#define DECODE_DEAD(data) static_cast<ContextHandle_t>(((data)  & 0xffffffffffffffff) >> 32 )
#define DECODE_KILL(data) (static_cast<ContextHandle_t>( (data)  & 0x00000000ffffffff))


#define MAKE_CONTEXT_PAIR(a, b) (((uint64_t)(a) << 32) | ((uint64_t)(b)))

#define delta 0.01

struct AddrValPair{
    void * address;
    uint8_t value[MAX_WRITE_OP_LENGTH];
};

struct RedSpyThreadData{
    AddrValPair buffer[MAX_WRITE_OPS_IN_INS];
    uint64_t bytesWritten;
    long NUM_INS;
    bool Sample_flag;
};

// key for accessing TLS storage in the threads. initialized once in main()
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

#ifdef ENABLE_SAMPLING

static ADDRINT IfEnableSample(THREADID threadId){
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    if(tData->Sample_flag){
        return 1;
    }
    return 0;
}

#endif

INT32 Usage2() {
    PIN_ERROR("Pin tool to gather calling context on each load and store.\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

// Main for RedSpy, initialize the tool, register instrumentation functions and call the target program.
static FILE* gTraceFile;
static uint8_t ** gL1PageTable[LEVEL_1_PAGE_TABLE_SIZE];

// Initialized the needed data structures before launching the target program
static void ClientInit(int argc, char* argv[]) {
    // Create output file
    char name[MAX_FILE_PATH] = "redspy_temporal_approx.out.";
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
static uint8_t* GetOrCreateShadowBaseAddress(uint64_t address) {
    uint8_t *shadowPage;
    uint8_t ***l1Ptr = &gL1PageTable[LEVEL_1_PAGE_TABLE_SLOT(address)];
    if(*l1Ptr == 0) {
        *l1Ptr = (uint8_t **) mmap(0, LEVEL_2_PAGE_TABLE_SIZE, PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] =  (uint8_t *) mmap(0, PAGE_SIZE * (sizeof(uint64_t)), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    } else if((shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)]) == 0 ){
        shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] =  (uint8_t *) mmap(0, PAGE_SIZE * (sizeof(uint64_t)), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    }
    return shadowPage;
}



static const uint64_t READ_ACCESS_STATES [] = {/*0 byte */0, /*1 byte */ ONE_BYTE_READ_ACTION, /*2 byte */ TWO_BYTE_READ_ACTION, /*3 byte */ 0, /*4 byte */ FOUR_BYTE_READ_ACTION, /*5 byte */0, /*6 byte */0, /*7 byte */0, /*8 byte */ EIGHT_BYTE_READ_ACTION};
static const uint64_t WRITE_ACCESS_STATES [] = {/*0 byte */0, /*1 byte */ ONE_BYTE_WRITE_ACTION, /*2 byte */ TWO_BYTE_WRITE_ACTION, /*3 byte */ 0, /*4 byte */ FOUR_BYTE_WRITE_ACTION, /*5 byte */0, /*6 byte */0, /*7 byte */0, /*8 byte */ EIGHT_BYTE_WRITE_ACTION};
static const uint8_t OVERFLOW_CHECK [] = {/*0 byte */0, /*1 byte */ 0, /*2 byte */ 0, /*3 byte */ 1, /*4 byte */ 2, /*5 byte */3, /*6 byte */4, /*7 byte */5, /*8 byte */ 6};

static unordered_map<uint64_t, uint64_t> RedMap[THREAD_MAX];

static inline void AddToRedTable(uint64_t key,  uint16_t value, THREADID threadId) {
      #ifdef MULTI_THREADED
      LOCK_RED_MAP();
      #endif

      unordered_map<uint64_t, uint64_t>::iterator it1 = RedMap[threadId].find(key);
      if ( it1  == RedMap[threadId].end()) {
                 RedMap[threadId][key] = value;
      } else {
                 it1->second += value;
      }
      
      #ifdef MULTI_THREADED
      UNLOCK_RED_MAP();
      #endif
}

template<int start, int end, int incr, bool conditional>
struct UnrolledLoop{
    static __attribute__((always_inline)) void Body(function<void (const int)> func){
        func(start); // Real loop body
        UnrolledLoop<start+incr, end, incr, conditional>:: Body(func);   // unroll next iteration
    }
    static __attribute__((always_inline)) void BodySamePage(ContextHandle_t * __restrict__ prevIP, const ContextHandle_t handle, THREADID threadId){
        if(conditional) {
            // report in RedTable
            AddToRedTable(MAKE_CONTEXT_PAIR(prevIP[start], handle), 1, threadId);
        }
        // Update context
        prevIP[start] = handle;
        UnrolledLoop<start+incr, end, incr, conditional>:: BodySamePage(prevIP, handle, threadId);   // unroll next iteration
    }
    static __attribute__((always_inline)) void BodyStraddlePage(uint64_t addr, const ContextHandle_t handle, THREADID threadId){
        uint8_t * status = GetOrCreateShadowBaseAddress((uint64_t)addr + start);
        ContextHandle_t * prevIP = (ContextHandle_t*)(status + PAGE_OFFSET(((uint64_t)addr + start)) * sizeof(ContextHandle_t));
        if (conditional) {
            // report in RedTable
            AddToRedTable(MAKE_CONTEXT_PAIR(prevIP[0 /* 0 is correct*/ ], handle), 1, threadId);
        }
        // Update context
        prevIP[0] = handle;
        UnrolledLoop<start+incr, end, incr, conditional>:: BodyStraddlePage(addr, handle, threadId);   // unroll next iteration
    }
};

template<int end,  int incr, bool conditional>
struct UnrolledLoop<end , end , incr, conditional>{
    static __attribute__((always_inline)) void Body(function<void (const int)> func){}
    static __attribute__((always_inline)) void BodySamePage(ContextHandle_t * __restrict__ prevIP, const ContextHandle_t handle, THREADID threadId){}
    static __attribute__((always_inline)) void BodyStraddlePage(uint64_t addr, const ContextHandle_t handle, THREADID threadId){}
};

template<int start, int end, int incr>
struct UnrolledConjunction{
    static __attribute__((always_inline)) bool Body(function<bool (const int)> func){
        return func(start) && UnrolledConjunction<start+incr, end, incr>:: Body(func);   // unroll next iteration
    }
    static __attribute__((always_inline)) bool BodyContextCheck(ContextHandle_t * __restrict__ prevIP){
        return (prevIP[0] == prevIP[start]) && UnrolledConjunction<start+incr, end, incr>:: BodyContextCheck(prevIP);   // unroll next iteration
    }
};

template<int end,  int incr>
struct UnrolledConjunction<end , end , incr>{
    static __attribute__((always_inline)) bool Body(function<void (const int)> func){
        return true;
    }
    static __attribute__((always_inline)) bool BodyContextCheck(ContextHandle_t * __restrict__ prevIP){
        return true;
    }
};

template<uint16_t AccessLen, uint32_t bufferOffset>
struct RedSpyAnalysis{
    static inline bool IsWriteRedundant(void * &addr, THREADID threadId){
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        AddrValPair * avPair = & tData->buffer[bufferOffset];
        addr = avPair->address;
        if(AccessLen >= 4){
            double newvalue64 = *(static_cast<double*>(avPair->address));
            double oldvalue64 = *((double*)(&avPair->value));
            double rate64 = (newvalue64 - oldvalue64)/oldvalue64;
            *((double*)(&avPair->value)) = newvalue64;
            if( rate64 <= delta || rate64 >= -delta )
                return true;
            else 
                return false;
        }else{
            return 0;
        }
    }
    
    static inline VOID RecordNByteValueBeforeWrite(void* addr, THREADID threadId){
        
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        AddrValPair * avPair = & tData->buffer[bufferOffset];
        avPair->address = addr;
        switch(AccessLen){
            case 1: break;
            case 2: break;
            case 4: *((double*)(&avPair->value)) = *(static_cast<double*>(addr)); break;
            case 8: *((double*)(&avPair->value)) = *(static_cast<double*>(addr)); break;
            default:memcpy(&avPair->value, addr, AccessLen);
        }
    }
    
    static __attribute__((always_inline)) VOID CheckNByteValueAfterWrite(uint32_t opaqueHandle, THREADID threadId){
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        void * addr;
        bool isRedundantWrite = IsWriteRedundant(addr, threadId);
        
        ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
        
        uint8_t* status = GetOrCreateShadowBaseAddress((uint64_t)addr);
        ContextHandle_t * __restrict__ prevIP = (ContextHandle_t*)(status + PAGE_OFFSET((uint64_t)addr) * sizeof(ContextHandle_t));
        const bool isAccessWithinPageBoundary = IS_ACCESS_WITHIN_PAGE_BOUNDARY( (uint64_t)addr, AccessLen);
        if(isRedundantWrite) {
            // detected redundancy
            if(isAccessWithinPageBoundary) {
                // All from same ctxt?
                if (UnrolledConjunction<0, AccessLen, 1>::BodyContextCheck(prevIP)) {
                    // report in RedTable
                    AddToRedTable(MAKE_CONTEXT_PAIR(prevIP[0], curCtxtHandle), AccessLen, threadId);
                    // Update context
                    UnrolledLoop<0, AccessLen, 1, false /* redundancy is updated outside*/>::BodySamePage(prevIP, curCtxtHandle, threadId);
                } else {
                    // different contexts
                    UnrolledLoop<0, AccessLen, 1, true /* redundancy is updated inside*/>::BodySamePage(prevIP, curCtxtHandle, threadId);
                }
            } else {
                // Write across a 64-K page boundary
                // First byte is on this page though
                AddToRedTable(MAKE_CONTEXT_PAIR(prevIP[0], curCtxtHandle), 1, threadId);
                // Update context
                prevIP[0] = curCtxtHandle;
                
                // Remaining bytes [1..AccessLen] somewhere will across a 64-K page boundary
                UnrolledLoop<1, AccessLen, 1, true /* update redundancy */>::BodyStraddlePage( (uint64_t) addr, curCtxtHandle, threadId);
            }
        } else {
            // No redundancy.
            // Just update contexts
            if(isAccessWithinPageBoundary) {
                // Update context
                UnrolledLoop<0, AccessLen, 1, false /* not redundant*/>::BodySamePage(prevIP, curCtxtHandle, threadId);
            } else {
                // Write across a 64-K page boundary
                // Update context
                prevIP[0] = curCtxtHandle;
                
                // Remaining bytes [1..AccessLen] somewhere will across a 64-K page boundary
                UnrolledLoop<1, AccessLen, 1, false /* dont update redundancy */>::BodyStraddlePage( (uint64_t) addr, curCtxtHandle, threadId);
                
            }
        }
    }
};

#ifdef ENABLE_SAMPLING

#define HANDLE_CASE(NUM, BUFFER_INDEX) \
case (NUM):{INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)IfEnableSample, IARG_THREAD_ID,IARG_END);\
INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) RedSpyAnalysis<(NUM), (BUFFER_INDEX)>::RecordNByteValueBeforeWrite, IARG_MEMORYOP_EA, memOp, IARG_THREAD_ID, IARG_END);\
INS_InsertIfPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR)IfEnableSample, IARG_THREAD_ID,IARG_END);\
INS_InsertThenPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) RedSpyAnalysis<(NUM), (BUFFER_INDEX)>::CheckNByteValueAfterWrite, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_INST_PTR,IARG_END);}break

#else

#define HANDLE_CASE(NUM, BUFFER_INDEX) \
case (NUM):{INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) RedSpyAnalysis<(NUM), (BUFFER_INDEX)>::RecordNByteValueBeforeWrite, IARG_MEMORYOP_EA, memOp, IARG_THREAD_ID, IARG_END);\
INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) RedSpyAnalysis<(NUM), (BUFFER_INDEX)>::CheckNByteValueAfterWrite, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_INST_PTR,IARG_END);}break

#endif

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
    static inline void InstrumentReadValueBeforeAndAfterWriting(INS ins, UINT32 memOp, uint32_t opaqueHandle){
        UINT32 refSize = INS_MemoryOperandSize(ins, memOp);
        switch(refSize) {
                HANDLE_CASE(1, readBufferSlotIndex);
                HANDLE_CASE(2, readBufferSlotIndex);
                HANDLE_CASE(4, readBufferSlotIndex);
                HANDLE_CASE(8, readBufferSlotIndex);
                HANDLE_CASE(10, readBufferSlotIndex);
                HANDLE_CASE(16, readBufferSlotIndex);
                
            default: {
                break; 
            }
        }
    }
};

static inline bool IsFloatInstruction(ADDRINT ip) {
    xed_decoded_inst_t  xedd;
    xed_state_t  xed_state;
    xed_decoded_inst_zero_set_mode(&xedd, &xed_state);
    
    if(XED_ERROR_NONE == xed_decode(&xedd, (const xed_uint8_t*)(ip), 15)) {
        unsigned int NumOperands = xed_decoded_inst_noperands(&xedd);
        for(unsigned int i = 0; i < NumOperands; ++i){
            xed_operand_element_type_enum_t TypeOperand = xed_decoded_inst_operand_element_type(&xedd,i);
            if(TypeOperand == XED_OPERAND_ELEMENT_TYPE_SINGLE || TypeOperand == XED_OPERAND_ELEMENT_TYPE_DOUBLE || TypeOperand == XED_OPERAND_ELEMENT_TYPE_FLOAT16 || TypeOperand == XED_OPERAND_ELEMENT_TYPE_LONGDOUBLE)
                return true;
        }
        return false;
    } else {
        assert(0 && "failed to disassemble instruction");
        return false;
    }
}

static VOID InstrumentInsCallback(INS ins, VOID* v, const uint32_t opaqueHandle) {
    if (!INS_IsMemoryRead(ins) && !INS_IsMemoryWrite(ins)) return;
    // if (INS_IsStackRead(ins) || INS_IsStackWrite(ins)) return;
    if (INS_IsBranchOrCall(ins) || INS_IsRet(ins)) return;
   
    if(!IsFloatInstruction(INS_Address(ins)))
        return;
   
    // Special case, if we have only one write operand
    UINT32 whichOp = 0;
    if(GetNumWriteOperandsInIns(ins, whichOp) == 1){
        // Read the value at location before and after the instruction
        RedSpyInstrument<0>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, opaqueHandle);
        return;
    }
    
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    int readBufferSlotIndex=0;
    for(UINT32 memOp = 0; memOp < memOperands; memOp++) {
        
        if(!INS_MemoryOperandIsWritten(ins, memOp))
            continue;
        
        switch (readBufferSlotIndex) {
            case 0:
                // Read the value at location before and after the instruction
                RedSpyInstrument<0>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, opaqueHandle);
                break;
            case 1:
                // Read the value at location before and after the instruction
                RedSpyInstrument<1>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, opaqueHandle);
                break;
            case 2:
                // Read the value at location before and after the instruction
                RedSpyInstrument<2>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, opaqueHandle);
                break;
            case 3:
                // Read the value at location before and after the instruction
                RedSpyInstrument<3>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, opaqueHandle);
                break;
            case 4:
                // Read the value at location before and after the instruction
                RedSpyInstrument<4>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, opaqueHandle);
                break;
            default:
                assert(0 && "NYI");
                break;
        }
        
        // use next slot for the next write operand
        readBufferSlotIndex++;
    }
}

#ifdef ENABLE_SAMPLING

inline VOID UpdateAndCheck(uint32_t count, uint32_t bytes, THREADID threadId) {
    
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    tData->bytesWritten += bytes;
    if(tData->Sample_flag){
        tData->NUM_INS += count;
        if(tData->NUM_INS > WINDOW_ENABLE){
            tData->Sample_flag = false;
            tData->NUM_INS = 0;
            EmptyCtxt(tData);
        }
    }else{
        tData->NUM_INS += count;
        if(tData->NUM_INS > WINDOW_DISABLE){
            tData->Sample_flag = true;
            tData->NUM_INS = 0;
        }
    }
}

inline VOID Update(uint32_t count, uint32_t bytes, THREADID threadId){
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    tData->NUM_INS += count;
    tData->bytesWritten += bytes;
}

//instrument the trace, count the number of ins in the trace, decide to instrument or not
static void InstrumentTrace(TRACE trace, void* f) {
    bool check = false;
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        uint32_t totInsInBbl = BBL_NumIns(bbl);
        uint32_t totBytes = 0;
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            
            if (INS_IsBranchOrCall(ins) || INS_IsRet(ins)) continue;
            if (!IsFloatInstruction(INS_Address(ins))) continue;
            
            if(INS_IsMemoryWrite(ins)) {
                totBytes += INS_MemoryWriteSize(ins);
            }
        }
        
        if (BBL_InsTail(bbl) == BBL_InsHead(bbl)) {
            BBL_InsertCall(bbl,IPOINT_BEFORE,(AFUNPTR)UpdateAndCheck,IARG_UINT32, totInsInBbl, IARG_UINT32,totBytes, IARG_THREAD_ID,IARG_END);
        }else if(INS_IsIndirectBranchOrCall(BBL_InsTail(bbl))){
            BBL_InsertCall(bbl,IPOINT_BEFORE,(AFUNPTR)UpdateAndCheck,IARG_UINT32, totInsInBbl, IARG_UINT32,totBytes, IARG_THREAD_ID,IARG_END);
        }else{
            if (check) {
                BBL_InsertCall(bbl,IPOINT_BEFORE,(AFUNPTR)UpdateAndCheck,IARG_UINT32, totInsInBbl, IARG_UINT32, totBytes, IARG_THREAD_ID,IARG_END);
                check = false;
            } else {
                BBL_InsertCall(bbl,IPOINT_BEFORE,(AFUNPTR)Update,IARG_UINT32, totInsInBbl, IARG_UINT32, totBytes, IARG_THREAD_ID, IARG_END);
                check = true;
            }
        }
    }
}
#else

inline VOID Update(uint32_t bytes, THREADID threadId){
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    tData->bytesWritten += bytes;
}

// Instrument a trace, take the first instruction in the first BBL and insert the analysis function before that
static void InstrumentTrace(TRACE trace, void* f) {
    // Insert counting code
    for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        uint32_t totalBytesWrittenInBBL = 0;
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            
            if (INS_IsBranchOrCall(ins) || INS_IsRet(ins)) continue;
            if (!IsFloatInstruction(INS_Address(ins))) continue;
            
            if(INS_IsMemoryWrite(ins)) {
                totalBytesWrittenInBBL += INS_MemoryWriteSize(ins);
            }
        }
        
        // Insert a call to corresponding count routines before every bbl, passing the number of instructions
        if(totalBytesWrittenInBBL)
            BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR) Update, IARG_UINT32, totalBytesWrittenInBBL, IARG_THREAD_ID, IARG_END);
    }
}

#endif

struct RedundacyData {
    ContextHandle_t dead;
    ContextHandle_t kill;
    uint64_t frequency;
};

static inline bool RedundacyCompare(const struct RedundacyData &first, const struct RedundacyData &second) {
    return first.frequency > second.frequency ? true : false;
}

static void PrintRedundancyPairs(THREADID threadId) {
    vector<RedundacyData> tmpList;
    vector<RedundacyData>::iterator tmpIt;

    uint64_t grandTotalRedundantBytes = 0;
    fprintf(gTraceFile, "*************** Dump Data(delta=%.2f%%) from Thread %d ****************\n", delta*100,threadId);
    
#ifdef MERGING
    for (unordered_map<uint64_t, uint64_t>::iterator it = RedMap[threadId].begin(); it != RedMap[threadId].end(); ++it) {
        ContextHandle_t dead = DECODE_DEAD((*it).first);
        ContextHandle_t kill = DECODE_KILL((*it).first);

        for(tmpIt = tmpList.begin();tmpIt != tmpList.end(); ++tmpIt){
            if(dead == 0 || ((*tmpIt).dead) == 0){
                continue;
            }
            if (!HaveSameCallerPrefix(dead,(*tmpIt).dead)) {
                continue;
            }
            if (!HaveSameCallerPrefix(kill,(*tmpIt).kill)) {
                continue;
            }
            bool ct1 = IsSameSourceLine(dead,(*tmpIt).dead);
            bool ct2 = IsSameSourceLine(kill,(*tmpIt).kill);
            if(ct1 && ct2){
                (*tmpIt).frequency += (*it).second;
                grandTotalRedundantBytes += (*it).second;
                break;
            }
        }
        if(tmpIt == tmpList.end()){
             RedundacyData tmp = { dead, kill, (*it).second};
             tmpList.push_back(tmp);
             grandTotalRedundantBytes += tmp.frequency;
        }
    }
#else
    for (unordered_map<uint64_t, uint64_t>::iterator it = RedMap[threadId].begin(); it != RedMap[threadId].end(); ++it) {
        RedundacyData tmp = { DECODE_DEAD ((*it).first), DECODE_KILL((*it).first), (*it).second};
        tmpList.push_back(tmp);
        grandTotalRedundantBytes += tmp.frequency;
    }
#endif
    
    fprintf(gTraceFile, "\n Total redundant bytes = %f %%\n", grandTotalRedundantBytes * 100.0 / ClientGetTLS(threadId)->bytesWritten);
    
    sort(tmpList.begin(), tmpList.end(), RedundacyCompare);
    vector<struct AnalyzedMetric_t>::iterator listIt;
    int cntxtNum = 0;
    for (vector<RedundacyData>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if (cntxtNum < MAX_REDUNDANT_CONTEXTS_TO_LOG) {
            fprintf(gTraceFile, "\n======= (%f) %% ======\n", (*listIt).frequency * 100.0 / grandTotalRedundantBytes);
            if ((*listIt).dead == 0) {
                fprintf(gTraceFile, "\n Prepopulated with  by OS\n");
            } else {
                PrintFullCallingContext((*listIt).dead);
            }
            fprintf(gTraceFile, "\n---------------------Redundantly written by---------------------------\n");
            PrintFullCallingContext((*listIt).kill);
        }
        else {
            break;
        }
        cntxtNum++;
    }
}

// On each Unload of a loaded image, the accummulated redundancy information is dumped
static VOID ImageUnload(IMG img, VOID* v) {
    fprintf(gTraceFile, "\n TODO .. Multi-threading is not well supported.");    
    THREADID  threadid =  PIN_ThreadId();
    fprintf(gTraceFile, "\nUnloading %s", IMG_Name(img).c_str());
    // Update gTotalInstCount first
    PIN_LockClient();
    PrintRedundancyPairs(threadid);
    PIN_UnlockClient();
    // clear redmap now
    RedMap[threadid].clear();
}  
 
static VOID ThreadFiniFunc(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v) {
}

static VOID FiniFunc(INT32 code, VOID *v) {
    // do whatever you want to the full CCT with footpirnt
}


static void InitThreadData(RedSpyThreadData* tdata){
    tdata->bytesWritten = 0;
    tdata->NUM_INS = 0;
    tdata->Sample_flag = true;
}

static VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    RedSpyThreadData* tdata = new RedSpyThreadData();
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
        return Usage2();
    
    // Initialize Symbols, we need them to report functions and lines
    PIN_InitSymbols();
    
    // Init Client
    ClientInit(argc, argv);
    // Intialize CCTLib
    PinCCTLibInit(INTERESTING_INS_MEMORY_ACCESS, gTraceFile, InstrumentInsCallback, 0);
    
    
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


