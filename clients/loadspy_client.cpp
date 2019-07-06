// @COPYRIGHT@
// Licensed under MIT license.
// See LICENSE.TXT file in the project root for more information.
// ==============================================================

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <malloc.h>
#include <iostream>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <sys/mman.h>
#include <sstream>
#include <vector>
#include <algorithm>
#include <list>
#include "pin.H"
#include "cctlib.H"
#include "shadow_memory.H"
#include <xmmintrin.h>
#include <immintrin.h>

#if __cplusplus > 199711L
#include <functional>
#include <unordered_set>
#include <unordered_map>
#else
#include <hash_set>
#include <hash_map>
#endif //end  __cplusplus > 199711L


extern "C" {
#include "xed-interface.h"
#include "xed-common-hdrs.h"
}

#if __cplusplus > 199711L
#else
#define unordered_map  hash_map
#define unordered_set  hash_set
#endif //end  __cplusplus > 199711L

using namespace std;
using namespace PinCCTLib;


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
#define MAX_REDUNDANT_CONTEXTS_TO_LOG (1000)
#define THREAD_MAX (1024)

#define ENCODE_ADDRESS_AND_ACCESS_LEN(addr, len) ( (addr) | (((uint64_t)(len)) << 48))
#define DECODE_ADDRESS(addrAndLen) ( (addrAndLen) & ((1L<<48) - 1))
#define DECODE_ACCESS_LEN(addrAndLen) ( (addrAndLen) >> 48)


#define MAX_WRITE_OP_LENGTH (512)
#define MAX_WRITE_OPS_IN_INS (8)
#define MAX_REG_LENGTH (64)

#define MAX_SIMD_LENGTH (64)
#define XMM_VEC_LEN (16)
#define YMM_VEC_LEN (32)
#define ZMM_VEC_LEN (64)
#define MAX_SIMD_REGS (32)
// Based on current 64-byte alignment
#define MAX_SIMD_ALIGNMENT (64)


#ifdef ENABLE_SAMPLING

#define WINDOW_ENABLE 1000000
#define WINDOW_DISABLE 100000000
#define WINDOW_CLEAN 10
#endif

#define DECODE_DEAD(data) static_cast<ContextHandle_t>(((data)  & 0xffffffffffffffff) >> 32 )
#define DECODE_KILL(data) (static_cast<ContextHandle_t>( (data)  & 0x00000000ffffffff))


#define MAKE_CONTEXT_PAIR(a, b) (((uint64_t)(a) << 32) | ((uint64_t)(b)))

#define delta 0.01



KNOB<BOOL>   KnobDataCentric(KNOB_MODE_WRITEONCE,    "pintool",
    "dc", "0", "perform data-centric analysis");

KNOB<BOOL>   KnobFlatProfile(KNOB_MODE_WRITEONCE,    "pintool",
    "fp", "0", "Collect flat profile");


/***********************************************
 ******  shadow memory
 ************************************************/
ConcurrentShadowMemory<uint8_t, ContextHandle_t> sm;

static struct{
    char dummy1[128];
    xed_state_t  xedState;
    char dummy2[128];
} LoadSpyGlobals;


#if 0
uint8_t** gL1PageTable[LEVEL_1_PAGE_TABLE_SIZE];


inline uint8_t* GetOrCreateShadowBaseAddress(uint64_t address) {
    // No entries at all ?
    uint8_t* shadowPage;
    uint8_t**  * l1Ptr = &gL1PageTable[LEVEL_1_PAGE_TABLE_SLOT(address)];
    
    if(*l1Ptr == 0) {
        *l1Ptr = (uint8_t**) calloc(1, LEVEL_2_PAGE_TABLE_SIZE);
        shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] = (uint8_t*) mmap(0, SHADOW_PAGE_SIZE * (1 + sizeof(uint32_t)), PROT_WRITE | PROT_READ,  MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    } else if((shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)]) == 0) {
        shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] = (uint8_t*) mmap(0, SHADOW_PAGE_SIZE * (1 + sizeof(uint32_t)), PROT_WRITE | PROT_READ,  MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    }
    
    return shadowPage;
}
#endif

////////////////////////////////////////////////

struct RedSpyThreadData{
    
    uint64_t bytesLoad;
    
    long long numIns;
    bool sampleFlag;
};

// for metric logging
int redload_metric_id = 0;
int redload_approx_metric_id = 0;

//for statistics result
volatile uint32_t gClientNumThreads;

uint64_t grandTotBytesLoad;
uint64_t grandTotBytesRedLoad;
uint64_t grandTotBytesApproxRedLoad;

// key for accessing TLS storage in the threads. initialized once in main()
static  TLS_KEY client_tls_key;
static RedSpyThreadData* gSingleThreadedTData;


#define MULTI_THREADED
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

static INT32 Usage() {
    PIN_ERROR("Pin tool to gather calling context on each load and store.\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

// Main for RedSpy, initialize the tool, register instrumentation functions and call the target program.
static FILE* gTraceFile;

// Initialized the needed data structures before launching the target program
static void ClientInit(int argc, char* argv[]) {
    // Create output file
    char name[MAX_FILE_PATH] = "redLoad.out.";
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

    // Init Xed
    // Init XED for decoding instructions
    xed_state_init(&LoadSpyGlobals.xedState, XED_MACHINE_MODE_LONG_64, (xed_address_width_enum_t) 0, XED_ADDRESS_WIDTH_64b);
}

static unordered_map<uint64_t, uint64_t> RedMap[THREAD_MAX];
static unordered_map<uint64_t, uint64_t> ApproxRedMap[THREAD_MAX];

static inline void AddToRedTable(uint64_t key,  uint16_t value, THREADID threadId) __attribute__((always_inline,flatten));
static inline void AddToRedTable(uint64_t key,  uint16_t value, THREADID threadId) {
#ifdef MULTI_THREADED
    //LOCK_RED_MAP();
#endif
    unordered_map<uint64_t, uint64_t>::iterator it = RedMap[threadId].find(key);
    if ( it  == RedMap[threadId].end()) {
        RedMap[threadId][key] = value;
    } else {
        it->second += value;
    }
#ifdef MULTI_THREADED
    //UNLOCK_RED_MAP();
#endif
}

static inline void AddToApproximateRedTable(uint64_t key,  uint16_t value, THREADID threadId) __attribute__((always_inline,flatten));
static inline void AddToApproximateRedTable(uint64_t key,  uint16_t value, THREADID threadId) {
#ifdef MULTI_THREADED
    //LOCK_RED_MAP();
#endif
    unordered_map<uint64_t, uint64_t>::iterator it = ApproxRedMap[threadId].find(key);
    if ( it  == ApproxRedMap[threadId].end()) {
        ApproxRedMap[threadId][key] = value;
    } else {
        it->second += value;
    }
#ifdef MULTI_THREADED
    //UNLOCK_RED_MAP();
#endif
}


#ifdef ENABLE_SAMPLING

static ADDRINT IfEnableSample(THREADID threadId){
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    return tData->sampleFlag;
}

#endif

// Certain FP instructions should not be approximated
static inline bool IsOkToApproximate(xed_decoded_inst_t & xedd) {
     xed_iclass_enum_t 	iclass = xed_decoded_inst_get_iclass (&xedd);
     switch(iclass) {
	case XED_ICLASS_FLDENV:
	case XED_ICLASS_FNSTENV:
	case XED_ICLASS_FNSAVE:
	case XED_ICLASS_FLDCW:
	case XED_ICLASS_FNSTCW:
        case XED_ICLASS_FNSTSW:
	case XED_ICLASS_FXRSTOR:
	case XED_ICLASS_FXRSTOR64:
	case XED_ICLASS_FXSAVE:
	case XED_ICLASS_FXSAVE64:
		return false;
// These operations work on an integer data type and convert to FP.
// It would be really complicated to get their data type since xed_decoded_inst_operand_element_type() fails.
// Milind: a conscious decion to not approximate these.
        case XED_ICLASS_FIADD:
        case XED_ICLASS_FICOM:
        case XED_ICLASS_FICOMP:
        case XED_ICLASS_FIDIV:
        case XED_ICLASS_FIDIVR:
        case XED_ICLASS_FILD:
        case XED_ICLASS_FIMUL:
        case XED_ICLASS_FINCSTP:
        case XED_ICLASS_FIST:
        case XED_ICLASS_FISTP:
        case XED_ICLASS_FISTTP:
        case XED_ICLASS_FISUB:
        case XED_ICLASS_FISUBR:
	default:
		return true;
     }
}

static inline bool IsFloatInstructionAndOkToApproximate(ADDRINT ip) {
    xed_decoded_inst_t  xedd;
    xed_decoded_inst_zero_set_mode(&xedd, &LoadSpyGlobals.xedState);
    
    if(XED_ERROR_NONE == xed_decode(&xedd, (const xed_uint8_t*)(ip), 15)) {
        xed_category_enum_t cat = xed_decoded_inst_get_category(&xedd);
        switch (cat) {
            case XED_CATEGORY_AES:
            case XED_CATEGORY_CONVERT:
            case XED_CATEGORY_PCLMULQDQ:
            case XED_CATEGORY_SSE:
            case XED_CATEGORY_AVX2:
            case XED_CATEGORY_AVX:
            case XED_CATEGORY_MMX:
            case XED_CATEGORY_DATAXFER: {
                // Get the mem operand
                
                const xed_inst_t* xi = xed_decoded_inst_inst(&xedd);
                int  noperands = xed_inst_noperands(xi);
                int memOpIdx = -1;
                for( int i =0; i < noperands ; i++) {
                    const xed_operand_t* op = xed_inst_operand(xi,i);
                    xed_operand_enum_t op_name = xed_operand_name(op);
                    if(XED_OPERAND_MEM0 == op_name) {
                        memOpIdx = i;
                        break;
                    }
                }
                if(memOpIdx == -1) {
                    return false;
                }
                
                // TO DO MILIND case XED_OPERAND_MEM1:
                xed_operand_element_type_enum_t eType = xed_decoded_inst_operand_element_type(&xedd,memOpIdx);
                switch (eType) {
                    case XED_OPERAND_ELEMENT_TYPE_FLOAT16:
                    case XED_OPERAND_ELEMENT_TYPE_SINGLE:
                    case XED_OPERAND_ELEMENT_TYPE_DOUBLE:
                    case XED_OPERAND_ELEMENT_TYPE_LONGDOUBLE:
                    case XED_OPERAND_ELEMENT_TYPE_LONGBCD:
                        return IsOkToApproximate(xedd);
                    default:
                        return false;
                }
            }
                break;
            case XED_CATEGORY_X87_ALU:
            case XED_CATEGORY_FCMOV:
                //case XED_CATEGORY_LOGICAL_FP:
                // assumption, the access length must be either 4 or 8 bytes else assert!!!
                //assert(*accessLen == 4 || *accessLen == 8);
                return IsOkToApproximate(xedd);
            case XED_CATEGORY_XSAVE:
            case XED_CATEGORY_AVX2GATHER:
            case XED_CATEGORY_STRINGOP:
            default: return false;
        }
    }else {
        assert(0 && "failed to disassemble instruction");
        //	printf("\n Diassembly failure\n");
        return false;
    }
}

/*
 static inline bool IsFloatInstruction(ADDRINT ip, uint32_t oper) {
 xed_decoded_inst_t  xedd;
 xed_decoded_inst_zero_set_mode(&xedd, &LoadSpyGlobals.xedState);
 
 if(XED_ERROR_NONE == xed_decode(&xedd, (const xed_uint8_t*)(ip), 15)) {
 xed_operand_element_type_enum_t TypeOperand = xed_decoded_inst_operand_element_type(&xedd,oper);
 if(TypeOperand == XED_OPERAND_ELEMENT_TYPE_SINGLE || TypeOperand == XED_OPERAND_ELEMENT_TYPE_DOUBLE || TypeOperand == XED_OPERAND_ELEMENT_TYPE_FLOAT16 || TypeOperand == XED_OPERAND_ELEMENT_TYPE_LONGDOUBLE)
 return true;
 return false;
 } else {
 assert(0 && "failed to disassemble instruction");
 return false;
 }
 }*/

static inline uint16_t FloatOperandSize(ADDRINT ip, uint32_t oper) {
    xed_decoded_inst_t  xedd;
    xed_decoded_inst_zero_set_mode(&xedd, &LoadSpyGlobals.xedState);
    
    if(XED_ERROR_NONE == xed_decode(&xedd, (const xed_uint8_t*)(ip), 15)) {
        xed_operand_element_type_enum_t TypeOperand = xed_decoded_inst_operand_element_type(&xedd,oper);
        if(TypeOperand == XED_OPERAND_ELEMENT_TYPE_SINGLE || TypeOperand == XED_OPERAND_ELEMENT_TYPE_FLOAT16)
            return 4;
        if (TypeOperand == XED_OPERAND_ELEMENT_TYPE_DOUBLE) {
            return 8;
        }
        if (TypeOperand == XED_OPERAND_ELEMENT_TYPE_LONGDOUBLE) {
            return 16;
        }
        assert(0 && "float instruction with unknown operand\n");
        return 0;
    } else {
        assert(0 && "failed to disassemble instruction\n");
        return 0;
    }
}

/***************************************************************************************/
/*********************** memory temporal redundancy functions **************************/
/***************************************************************************************/

template<int start, int end, int incr, bool conditional, bool approx>
struct UnrolledLoop{
#if __cplusplus > 199711L
    static __attribute__((always_inline)) void Body(function<void (const int)> func){
        func(start); // Real loop body
        UnrolledLoop<start+incr, end, incr, conditional, approx>:: Body(func);   // unroll next iteration
    }
#endif
    static __attribute__((always_inline)) void BodySamePage(ContextHandle_t * __restrict__ prevIP, const ContextHandle_t handle, THREADID threadId){
        if(conditional) {
            // report in RedTable
            if(approx)
                AddToApproximateRedTable(MAKE_CONTEXT_PAIR(prevIP[start], handle), 1, threadId);
            else
                AddToRedTable(MAKE_CONTEXT_PAIR(prevIP[start], handle), 1, threadId);
        }
        // Update context
        prevIP[start] = handle;
        UnrolledLoop<start+incr, end, incr, conditional, approx>:: BodySamePage(prevIP, handle, threadId);   // unroll next iteration
    }
    static __attribute__((always_inline)) void BodyStraddlePage(uint64_t addr, const ContextHandle_t handle, THREADID threadId){
#if __cplusplus > 199711L
        tuple<uint8_t[SHADOW_PAGE_SIZE], ContextHandle_t[SHADOW_PAGE_SIZE]> &t = sm.GetOrCreateShadowBaseAddress((uint64_t)addr+start);
        ContextHandle_t * prevIP = &(get<1>(t)[PAGE_OFFSET(((uint64_t)addr+start))]);
#else
        tuple<uint8_t, ContextHandle_t> &t = sm.GetOrCreateShadowBaseAddress((uint64_t)addr+start);
        ContextHandle_t * prevIP = &(t.b[PAGE_OFFSET(((uint64_t)addr+start))]);
#endif
        if (conditional) {
            // report in RedTable
            if(approx)
                AddToApproximateRedTable(MAKE_CONTEXT_PAIR(prevIP[0 /* 0 is correct*/ ], handle), 1, threadId);
            else
                AddToRedTable(MAKE_CONTEXT_PAIR(prevIP[0 /* 0 is correct*/ ], handle), 1, threadId);
        }
        // Update context
        prevIP[0] = handle;
        UnrolledLoop<start+incr, end, incr, conditional, approx>:: BodyStraddlePage(addr, handle, threadId);   // unroll next iteration
    }
};

template<int end,  int incr, bool conditional, bool approx>
struct UnrolledLoop<end , end , incr, conditional, approx>{
#if __cplusplus > 199711L
    static __attribute__((always_inline)) void Body(function<void (const int)> func){}
#endif
    static __attribute__((always_inline)) void BodySamePage(ContextHandle_t * __restrict__ prevIP, const ContextHandle_t handle, THREADID threadId){}
    static __attribute__((always_inline)) void BodyStraddlePage(uint64_t addr, const ContextHandle_t handle, THREADID threadId){}
};

template<int start, int end, int incr>
struct UnrolledConjunction{
#if __cplusplus > 199711L
    static __attribute__((always_inline)) bool Body(function<bool (const int)> func){
        return func(start) && UnrolledConjunction<start+incr, end, incr>:: Body(func);   // unroll next iteration
    }
#endif
    static __attribute__((always_inline)) bool BodyContextCheck(ContextHandle_t * __restrict__ prevIP){
        return (prevIP[0] == prevIP[start]) && UnrolledConjunction<start+incr, end, incr>:: BodyContextCheck(prevIP);   // unroll next iteration
    }
};

template<int end,  int incr>
struct UnrolledConjunction<end , end , incr>{
#if __cplusplus > 199711L
    static __attribute__((always_inline)) bool Body(function<void (const int)> func){
        return true;
    }
#endif
    static __attribute__((always_inline)) bool BodyContextCheck(ContextHandle_t * __restrict__ prevIP){
        return true;
    }
};


template<class T, uint32_t AccessLen, bool isApprox>
struct RedSpyAnalysis{
    static __attribute__((always_inline)) bool IsReadRedundant(void * addr, uint8_t * prev){
        
        if(isApprox){
            if(AccessLen == ZMM_VEC_LEN || AccessLen == YMM_VEC_LEN || AccessLen == XMM_VEC_LEN){
                T * __restrict__ oldValue = reinterpret_cast<T*> (prev);
                T * __restrict__ newValue = reinterpret_cast<T*> (addr);
                int redCount = 0;
#pragma omp simd reduction(+: redCount)
                for(uint32_t i = 0; i < AccessLen/ sizeof(T); i++) {
                    T tmp = (newValue[i]-oldValue[i])/oldValue[i];
                    if (tmp < ((T) 0))
                        tmp = -tmp;
                    redCount += tmp <= ((T)delta);
                    oldValue[i] = newValue[i];
                }
                if(redCount != AccessLen/ sizeof(T)) {
                    return false;
                }
                return true;
            }else if(AccessLen == 10){
                UINT8 newValue[10];
                memcpy(newValue, addr, AccessLen);
                
                uint64_t * upperOld = (uint64_t*)&(prev[2]);
                uint64_t * upperNew = (uint64_t*)&(newValue[2]);
                
                uint16_t * lowOld = (uint16_t*)&(prev[0]);
                uint16_t * lowNew = (uint16_t*)&(newValue[0]);
                
                memcpy(prev, addr, AccessLen);
                
                if((*lowOld & 0xfff0) == (*lowNew & 0xfff0) && *upperNew == *upperOld){
                    return true;
                }
                return false;
            }else{
                assert (AccessLen < 10);
                T newValue = *(static_cast<T*>(addr));
                T oldValue = *((T*)(prev));
                
                *((T*)(prev)) = *(static_cast<T*>(addr));
                
                T rate = (newValue - oldValue)/oldValue;
                if( rate <= delta && rate >= -delta ) return true;
                else return false;
            }
        } else {
            bool isRed = (*((T*)(prev)) == *(static_cast<T*>(addr)));
            *((T*)(prev)) = *(static_cast<T*>(addr));
            return isRed;
        }
        return false;
    }
    
    static __attribute__((always_inline)) VOID CheckNByteValueAfterRead(void* addr, uint32_t opaqueHandle, THREADID threadId){
        ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
#if __cplusplus > 199711L
        tuple<uint8_t[SHADOW_PAGE_SIZE], ContextHandle_t[SHADOW_PAGE_SIZE]> &t = sm.GetOrCreateShadowBaseAddress((uint64_t)addr);
        ContextHandle_t * __restrict__ prevIP = &(get<1>(t)[PAGE_OFFSET((uint64_t)addr)]);
        uint8_t* prevValue = &(get<0>(t)[PAGE_OFFSET((uint64_t)addr)]);
#else
        tuple<uint8_t, ContextHandle_t> &t = sm.GetOrCreateShadowBaseAddress((uint64_t)addr);
        ContextHandle_t * __restrict__ prevIP = &(t.b[PAGE_OFFSET((uint64_t)addr)]);
        uint8_t* prevValue = &(t.a[PAGE_OFFSET((uint64_t)addr)]);
#endif
        bool isRedundantRead = IsReadRedundant(addr, prevValue);
        
        const bool isAccessWithinPageBoundary = IS_ACCESS_WITHIN_PAGE_BOUNDARY( (uint64_t)addr, AccessLen);
        if(isRedundantRead) {
            // detected redundancy
            if(isAccessWithinPageBoundary) {
                // All from same ctxt?
                if (UnrolledConjunction<0, AccessLen, 1>::BodyContextCheck(prevIP)) {
                    // report in RedTable
                    if(isApprox)
                        AddToApproximateRedTable(MAKE_CONTEXT_PAIR(prevIP[0], curCtxtHandle), AccessLen, threadId);
                    else
                        AddToRedTable(MAKE_CONTEXT_PAIR(prevIP[0], curCtxtHandle), AccessLen, threadId);
                    // Update context
                    UnrolledLoop<0, AccessLen, 1, false, /* redundancy is updated outside*/ isApprox>::BodySamePage(prevIP, curCtxtHandle, threadId);
                } else {
                    // different contexts
                    UnrolledLoop<0, AccessLen, 1, true, /* redundancy is updated inside*/ isApprox>::BodySamePage(prevIP, curCtxtHandle, threadId);
                }
            } else {
                // Read across a 64-K page boundary
                // First byte is on this page though
                if(isApprox)
                    AddToApproximateRedTable(MAKE_CONTEXT_PAIR(prevIP[0], curCtxtHandle), 1, threadId);
                else
                    AddToRedTable(MAKE_CONTEXT_PAIR(prevIP[0], curCtxtHandle), 1, threadId);
                // Update context
                prevIP[0] = curCtxtHandle;
                
                // Remaining bytes [1..AccessLen] somewhere will across a 64-K page boundary
                UnrolledLoop<1, AccessLen, 1, true, /* update redundancy */ isApprox>::BodyStraddlePage( (uint64_t) addr, curCtxtHandle, threadId);
            }
        } else {
            // No redundancy.
            // Just update contexts
            if(isAccessWithinPageBoundary) {
                // Update context
                UnrolledLoop<0, AccessLen, 1, false, /* not redundant*/ isApprox>::BodySamePage(prevIP, curCtxtHandle, threadId);
            } else {
                // Read across a 64-K page boundary
                // Update context
                prevIP[0] = curCtxtHandle;
                
                // Remaining bytes [1..AccessLen] somewhere will across a 64-K page boundary
                UnrolledLoop<1, AccessLen, 1, false, /* not redundant*/ isApprox>::BodyStraddlePage( (uint64_t) addr, curCtxtHandle, threadId);
            }
        }
    }
};


static inline VOID CheckAfterLargeRead(void* addr, UINT32 accessLen, uint32_t opaqueHandle, THREADID threadId){
    ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);

#if __cplusplus > 199711L
    tuple<uint8_t[SHADOW_PAGE_SIZE], ContextHandle_t[SHADOW_PAGE_SIZE]> &t = sm.GetOrCreateShadowBaseAddress((uint64_t)addr);
    ContextHandle_t * __restrict__ prevIP = &(get<1>(t)[PAGE_OFFSET((uint64_t)addr)]);
    uint8_t* prevValue = &(get<0>(t)[PAGE_OFFSET((uint64_t)addr)]);
    // This assumes that a large read cannot straddle a page boundary -- strong assumption, but lets go with it for now.
    sm.GetOrCreateShadowBaseAddress((uint64_t)addr); // just to have a side effect?
#else
    tuple<uint8_t, ContextHandle_t> &t = sm.GetOrCreateShadowBaseAddress((uint64_t)addr);
    ContextHandle_t * __restrict__ prevIP = &(t.b[PAGE_OFFSET((uint64_t)addr)]);
    uint8_t* prevValue = &(t.a[PAGE_OFFSET((uint64_t)addr)]);
    // This assumes that a large read cannot straddle a page boundary -- strong assumption, but lets go with it for now.
    sm.GetOrCreateShadowBaseAddress((uint64_t)addr); // just to have a side effect?
#endif
    if(memcmp(prevValue, addr, accessLen) == 0){
        // redundant
        for(UINT32 index = 0 ; index < accessLen; index++){
            // report in RedTable
            AddToRedTable(MAKE_CONTEXT_PAIR(prevIP[index], curCtxtHandle), 1, threadId);
            // Update context
            prevIP[index] = curCtxtHandle;
        }
    }else{
        // Not redundant
        for(UINT32 index = 0 ; index < accessLen; index++){
            // Update context
            prevIP[index] = curCtxtHandle;
        }
    }
    
    memcpy(prevValue,addr,accessLen);
}

#ifdef ENABLE_SAMPLING

#define HANDLE_CASE(T, ACCESS_LEN, IS_APPROX) \
INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)IfEnableSample, IARG_THREAD_ID,IARG_END);\
INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) RedSpyAnalysis<T, (ACCESS_LEN), (IS_APPROX)>::CheckNByteValueAfterRead, IARG_MEMORYOP_EA, memOp, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_INST_PTR,IARG_END)

#define HANDLE_LARGE() \
INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)IfEnableSample, IARG_THREAD_ID,IARG_END);\
INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) CheckAfterLargeRead, IARG_MEMORYOP_EA, memOp, IARG_MEMORYREAD_SIZE, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_END)

#else

#define HANDLE_CASE(T, ACCESS_LEN, IS_APPROX) \
INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) RedSpyAnalysis<T, (ACCESS_LEN), (IS_APPROX)>::CheckNByteValueAfterRead, IARG_MEMORYOP_EA, memOp, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_INST_PTR,IARG_END)

#define HANDLE_LARGE() \
INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) CheckAfterLargeRead, IARG_MEMORYOP_EA, memOp, IARG_MEMORYREAD_SIZE, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_END)

#endif


static int GetNumReadOperandsInIns(INS ins, UINT32 & whichOp){
    int numReadOps = 0;
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    for(UINT32 memOp = 0; memOp < memOperands; memOp++) {
        if (INS_MemoryOperandIsRead(ins, memOp)) {
            numReadOps++;
            whichOp = memOp;
        }
    }
    return numReadOps;
}


struct LoadSpyInstrument{
    static __attribute__((always_inline)) void InstrumentReadValueBeforeAndAfterLoading(INS ins, UINT32 memOp, uint32_t opaqueHandle){
        UINT32 refSize = INS_MemoryOperandSize(ins, memOp);
        
        if (IsFloatInstructionAndOkToApproximate(INS_Address(ins))) {
            unsigned int operSize = FloatOperandSize(INS_Address(ins),INS_MemoryOperandIndexToOperandIndex(ins,memOp));
            switch(refSize) {
                case 1:
                case 2: assert(0 && "memory read floating data with unexptected small size");
                case 4: HANDLE_CASE(float, 4, true); break;
                case 8: HANDLE_CASE(double, 8, true); break;
                case 10: HANDLE_CASE(uint8_t, 10, true); break;
                case 16: {
                    switch (operSize) {
                        case 4: HANDLE_CASE(float, 16, true); break;
                        case 8: HANDLE_CASE(double, 16, true); break;
                        default: assert(0 && "handle large mem read with unexpected operand size\n"); break;
                    }
                }break;
                case 32: {
                    switch (operSize) {
                        case 4: HANDLE_CASE(float, 32, true); break;
                        case 8: HANDLE_CASE(double, 32, true); break;
                        default: assert(0 && "handle large mem read with unexpected operand size\n"); break;
                    }
                }break;
                case 64: {
                    switch (operSize) {
                        case 4: HANDLE_CASE(float, 64, true); break;
                        case 8: HANDLE_CASE(double, 64, true); break;
                        default: assert(0 && "handle large mem read with unexpected operand size\n"); break;
                    }
                }break;
                default: assert(0 && "unexpected large memory read\n"); break;
            }
        }else{
            switch(refSize) {
                case 1: HANDLE_CASE(uint8_t, 1, false); break;
                case 2: HANDLE_CASE(uint16_t, 2, false); break;
                case 4: HANDLE_CASE(uint32_t, 4, false); break;
                case 8: HANDLE_CASE(uint64_t, 8, false); break;
                    
                default: {
                    HANDLE_LARGE();
                }
            }
        }
    }
};

/*********************  instrument analysis  ************************/

static inline bool INS_IsIgnorable(INS ins){
    if( INS_IsFarJump(ins) || INS_IsDirectFarJump(ins)
#if (PIN_PRODUCT_VERSION_MAJOR >= 3) && (PIN_PRODUCT_VERSION_MINOR >= 7)
       // INS_IsMaskedJump has disappeared in 3,7
#else
       //|| INS_IsMaskedJump(ins)
#endif
       )
        return true;
    else if(INS_IsRet(ins) || INS_IsIRet(ins))
        return true;
    else if(INS_IsCall(ins) || INS_IsSyscall(ins))
        return true;
    else if(INS_IsBranch(ins) || INS_IsRDTSC(ins) || INS_IsNop(ins))
        return true;
    else if(INS_IsPrefetch(ins)) // Prefetch instructions might access addresses which are invalid.
        return true;
    return false;
}

static VOID InstrumentInsCallback(INS ins, VOID* v, const uint32_t opaqueHandle) {
    if (!INS_HasFallThrough(ins)) return;
    if (INS_IsIgnorable(ins))return;
    if (INS_IsControlFlow(ins)) return;
    
    //Instrument memory reads to find redundancy
    // Special case, if we have only one read operand
    UINT32 whichOp = 0;
    if(GetNumReadOperandsInIns(ins, whichOp) == 1){
        // Read the value at location before and after the instruction
        LoadSpyInstrument::InstrumentReadValueBeforeAndAfterLoading(ins, whichOp, opaqueHandle);
    }else{
        UINT32 memOperands = INS_MemoryOperandCount(ins);
        for(UINT32 memOp = 0; memOp < memOperands; memOp++) {
            
            if(!INS_MemoryOperandIsRead(ins, memOp))
                continue;
            LoadSpyInstrument::InstrumentReadValueBeforeAndAfterLoading(ins, memOp, opaqueHandle);
        }
    }
}

/**********************************************************************************/

#ifdef ENABLE_SAMPLING

inline VOID UpdateAndCheck(uint32_t count, uint32_t bytes, THREADID threadId) {
    
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    
    if(tData->sampleFlag){
        tData->numIns += count;
        if(tData->numIns > WINDOW_ENABLE){
            tData->sampleFlag = false;
            tData->numIns = 0;
        }
    }else{
        tData->numIns += count;
        if(tData->numIns > WINDOW_DISABLE){
            tData->sampleFlag = true;
            tData->numIns = 0;
        }
    }
    if (tData->sampleFlag) {
        tData->bytesLoad += bytes;
    }
}

inline VOID Update(uint32_t count, uint32_t bytes, THREADID threadId){
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    tData->numIns += count;
    if (tData->sampleFlag) {
        tData->bytesLoad += bytes;
    }
}

//instrument the trace, count the number of ins in the trace, decide to instrument or not
static void InstrumentTrace(TRACE trace, void* f) {
    bool check = false;
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        uint32_t totInsInBbl = BBL_NumIns(bbl);
        uint32_t totBytes = 0;
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            
            if (!INS_HasFallThrough(ins)) continue;
            if (INS_IsIgnorable(ins)) continue;
            if (INS_IsControlFlow(ins)) continue;
            
            if(INS_IsMemoryRead(ins)) {
                totBytes += INS_MemoryReadSize(ins);
            }
        }
        
        if (BBL_InsTail(bbl) == BBL_InsHead(bbl)) {
            BBL_InsertCall(bbl,IPOINT_BEFORE,(AFUNPTR)UpdateAndCheck,IARG_UINT32, totInsInBbl, IARG_UINT32,totBytes, IARG_THREAD_ID, IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
        }else if(INS_IsIndirectBranchOrCall(BBL_InsTail(bbl))){
            BBL_InsertCall(bbl,IPOINT_BEFORE,(AFUNPTR)UpdateAndCheck,IARG_UINT32, totInsInBbl, IARG_UINT32,totBytes, IARG_THREAD_ID,IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
        }else{
            if (check) {
                BBL_InsertCall(bbl,IPOINT_BEFORE,(AFUNPTR)UpdateAndCheck,IARG_UINT32, totInsInBbl, IARG_UINT32, totBytes, IARG_THREAD_ID,IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
                check = false;
            } else {
                BBL_InsertCall(bbl,IPOINT_BEFORE,(AFUNPTR)Update,IARG_UINT32, totInsInBbl, IARG_UINT32, totBytes, IARG_THREAD_ID, IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
                check = true;
            }
        }
    }
}

#else

inline VOID Update(uint32_t bytes, THREADID threadId){
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    tData->bytesLoad += bytes;
}

//instrument the trace, count the number of ins in the trace, decide to instrument or not
static void InstrumentTrace(TRACE trace, void* f) {
    
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        uint32_t totBytes = 0;
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            
            if (!INS_HasFallThrough(ins)) continue;
            if (INS_IsIgnorable(ins)) continue;
            if (INS_IsControlFlow(ins)) continue;
            
            if(INS_IsMemoryRead(ins)) {
                totBytes += INS_MemoryReadSize(ins);
            }
        }
        BBL_InsertCall(bbl,IPOINT_BEFORE,(AFUNPTR)Update, IARG_UINT32, totBytes, IARG_THREAD_ID, IARG_END);
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
    
    uint64_t grandTotalRedundantBytes = 0;
    fprintf(gTraceFile, "*************** Dump Data from Thread %d ****************\n", threadId);
    
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
    
    __sync_fetch_and_add(&grandTotBytesRedLoad,grandTotalRedundantBytes);
    
     fprintf(gTraceFile, "\n Total redundant bytes = (%.2e / %.2e) %f  %%\n", (double) grandTotalRedundantBytes, (double) ClientGetTLS(threadId)->bytesLoad, grandTotalRedundantBytes * 100.0 / ClientGetTLS(threadId)->bytesLoad);
    
    sort(tmpList.begin(), tmpList.end(), RedundacyCompare);
    int cntxtNum = 0;
    for (vector<RedundacyData>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if (cntxtNum < MAX_REDUNDANT_CONTEXTS_TO_LOG) {
            fprintf(gTraceFile, "\n======= (%f) %% ======\n", (*listIt).frequency * 100.0 / grandTotalRedundantBytes);
            if ((*listIt).dead == 0) {
                fprintf(gTraceFile, "\n Prepopulated with  by OS\n");
            } else {
                PrintFullCallingContext((*listIt).dead);
            }
            fprintf(gTraceFile, "\n---------------------Redundant load with---------------------------\n");
            PrintFullCallingContext((*listIt).kill);
        }
        else {
            break;
        }
        cntxtNum++;
    }
}

static void PrintApproximationRedundancyPairs(THREADID threadId) {
    vector<RedundacyData> tmpList;
    uint64_t grandTotalRedundantBytes = 0;
    fprintf(gTraceFile, "*************** Dump Data(delta=%.2f%%) from Thread %d ****************\n", delta*100,threadId);
    
#ifdef MERGING
    for (unordered_map<uint64_t, uint64_t>::iterator it = ApproxRedMap[threadId].begin(); it != ApproxRedMap[threadId].end(); ++it) {
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
                grandTotalRedundantIns += 1;
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
    for (unordered_map<uint64_t, uint64_t>::iterator it = ApproxRedMap[threadId].begin(); it != ApproxRedMap[threadId].end(); ++it) {
        RedundacyData tmp = { DECODE_DEAD ((*it).first), DECODE_KILL((*it).first), (*it).second};
        tmpList.push_back(tmp);
        grandTotalRedundantBytes += tmp.frequency;
    }
#endif
    
    __sync_fetch_and_add(&grandTotBytesApproxRedLoad,grandTotalRedundantBytes);
    
    fprintf(gTraceFile, "\n Total appx redundant bytes = (%.2e / %.2e) %f  %%\n", (double)grandTotalRedundantBytes,  (double) ClientGetTLS(threadId)->bytesLoad, grandTotalRedundantBytes * 100.0 / ClientGetTLS(threadId)->bytesLoad);
    
    sort(tmpList.begin(), tmpList.end(), RedundacyCompare);
    int cntxtNum = 0;
    for (vector<RedundacyData>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if (cntxtNum < MAX_REDUNDANT_CONTEXTS_TO_LOG) {
            fprintf(gTraceFile, "\n======= (%f) %% ======\n", (*listIt).frequency * 100.0 / grandTotalRedundantBytes);
            if ((*listIt).dead == 0) {
                fprintf(gTraceFile, "\n Prepopulated with  by OS\n");
            } else {
                PrintFullCallingContext((*listIt).dead);
            }
            fprintf(gTraceFile, "\n---------------------Redundant load with---------------------------\n");
            PrintFullCallingContext((*listIt).kill);
        }
        else {
            break;
        }
        cntxtNum++;
    }
}

static void HPCRunRedundancyPairs(THREADID threadId) {
    vector<RedundacyData> tmpList;
    for (unordered_map<uint64_t, uint64_t>::iterator it = RedMap[threadId].begin(); it != RedMap[threadId].end(); ++it) {
        RedundacyData tmp = { DECODE_DEAD ((*it).first), DECODE_KILL((*it).first), (*it).second};
        tmpList.push_back(tmp);
    }
    
    sort(tmpList.begin(), tmpList.end(), RedundacyCompare);
    vector<HPCRunCCT_t*> HPCRunNodes;
    int cntxtNum = 0;
    for (vector<RedundacyData>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if (cntxtNum < MAX_REDUNDANT_CONTEXTS_TO_LOG) {
            HPCRunCCT_t *HPCRunNode = new HPCRunCCT_t();
            HPCRunNode->ctxtHandle1 = (*listIt).dead;
            HPCRunNode->ctxtHandle2 = (*listIt).kill;
            HPCRunNode->metric = (*listIt).frequency;
            HPCRunNode->metric_id = redload_metric_id;
            HPCRunNodes.push_back(HPCRunNode);
        }
        else {
            break;
        }
        cntxtNum++;
    }
    newCCT_hpcrun_build_cct(HPCRunNodes, threadId);
}

static void HPCRunApproxRedundancyPairs(THREADID threadId) {
    vector<RedundacyData> tmpList;
    for (unordered_map<uint64_t, uint64_t>::iterator it = ApproxRedMap[threadId].begin(); it != ApproxRedMap[threadId].end(); ++it) {
        RedundacyData tmp = { DECODE_DEAD ((*it).first), DECODE_KILL((*it).first), (*it).second};
        tmpList.push_back(tmp);
    }
    
    sort(tmpList.begin(), tmpList.end(), RedundacyCompare);
    vector<HPCRunCCT_t*> HPCRunNodes;
    int cntxtNum = 0;
    for (vector<RedundacyData>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if (cntxtNum < MAX_REDUNDANT_CONTEXTS_TO_LOG) {
            HPCRunCCT_t *HPCRunNode = new HPCRunCCT_t();
            HPCRunNode->ctxtHandle1 = (*listIt).dead;
            HPCRunNode->ctxtHandle2 = (*listIt).kill;
            HPCRunNode->metric = (*listIt).frequency;
            HPCRunNode->metric_id = redload_approx_metric_id;
            HPCRunNodes.push_back(HPCRunNode);
        }
        else {
            break;
        }
        cntxtNum++;
    }
    newCCT_hpcrun_build_cct(HPCRunNodes, threadId);
}

// On each Unload of a loaded image, the accummulated redundancy information is dumped
static VOID ImageUnload(IMG img, VOID* v) {
    fprintf(gTraceFile, "\n TODO .. Multi-threading is not well supported.");
    //THREADID  threadid =  PIN_ThreadId();
    fprintf(gTraceFile, "\nUnloading %s", IMG_Name(img).c_str());
    // Update gTotalInstCount first
    PIN_LockClient();
    for(uint32_t i = 0 ; i < gClientNumThreads; i++) {
	fprintf(gTraceFile, "\n Thread %d of %d \n", i, gClientNumThreads);
        if (!RedMap[i].empty())
            PrintRedundancyPairs(i);
        if(!ApproxRedMap[i].empty())
            PrintApproximationRedundancyPairs(i);
    }
    PIN_UnlockClient();
    // clear redmap now
    for(uint32_t i = 0 ; i < gClientNumThreads; i++) {
        RedMap[i].clear();
        ApproxRedMap[i].clear();
    }
    fprintf(gTraceFile, "\nRunning grandTotBytesLoad : %.2e \n", (double)grandTotBytesLoad);
    fprintf(gTraceFile, "\nRunning grandTotBytesRedLoad: %.2e %f %%\n", (double)grandTotBytesRedLoad, grandTotBytesRedLoad * 100.0/grandTotBytesLoad);
    fprintf(gTraceFile, "\nRunning grandTotBytesApproximateRedLoad: %.2e %f %%\n", (double)grandTotBytesApproxRedLoad, grandTotBytesApproxRedLoad * 100.0/grandTotBytesLoad);
}

static VOID ThreadFiniFunc(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v) {
    
    __sync_fetch_and_add(&grandTotBytesLoad, ClientGetTLS(threadid)->bytesLoad);
    
    // output the CCT for hpcviewer format
    HPCRunRedundancyPairs(threadid);
    HPCRunApproxRedundancyPairs(threadid);
    newCCT_hpcrun_selection_write(threadid);
}

static VOID FiniFunc(INT32 code, VOID *v) {
    // do whatever you want to the full CCT with footpirnt
    uint64_t redReadTmp = 0;
    uint64_t approxRedReadTmp = 0;
    for(uint32_t i = 0; i < THREAD_MAX; ++i){
        unordered_map<uint64_t, uint64_t>::iterator it;
        if(!RedMap[i].empty()){
            for (it = RedMap[i].begin(); it != RedMap[i].end(); ++it) {
                redReadTmp += (*it).second;
            }
        }
        if(!ApproxRedMap[i].empty()){
            for (it = ApproxRedMap[i].begin(); it != ApproxRedMap[i].end(); ++it) {
                approxRedReadTmp += (*it).second;
            }
        }
    }
    grandTotBytesRedLoad += redReadTmp;
    grandTotBytesApproxRedLoad += approxRedReadTmp;
    
    fprintf(gTraceFile, "\n#Redundant Read:");
    fprintf(gTraceFile, "\nTotalBytesLoad: %" PRIu64 "\n",grandTotBytesLoad);
    fprintf(gTraceFile, "\nRedundantBytesLoad: %" PRIu64 " %.2f\n",grandTotBytesRedLoad, grandTotBytesRedLoad * 100.0/grandTotBytesLoad);
    fprintf(gTraceFile, "\nApproxRedundantBytesLoad: %" PRIu64 " %.2f\n",grandTotBytesApproxRedLoad, grandTotBytesApproxRedLoad * 100.0/grandTotBytesLoad);
}

static void InitThreadData(RedSpyThreadData* tdata){
    tdata->bytesLoad = 0;
    tdata->sampleFlag = true;
    tdata->numIns = 0;
/*    for (int i = 0; i < THREAD_MAX; ++i) {
        RedMap[i].set_empty_key(0);
        ApproxRedMap[i].set_empty_key(0);
    }
*/
}

static VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    RedSpyThreadData* tdata = (RedSpyThreadData*)memalign(32,sizeof(RedSpyThreadData));
    InitThreadData(tdata);
    __sync_fetch_and_add(&gClientNumThreads, 1);
#ifdef MULTI_THREADED
    PIN_SetThreadData(client_tls_key, tdata, threadid);
#else
    gSingleThreadedTData = tdata;
#endif
}

// user-defined function for metric computation
// hpcviewer can only show the numbers for the metric
uint64_t computeMetricVal(void *metric)
{
    if (!metric) return 0;
    return (uint64_t)metric;
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
    PinCCTLibInit(INTERESTING_INS_ALL, gTraceFile, InstrumentInsCallback, 0, KnobDataCentric, KnobFlatProfile);
    
    // Init hpcrun format output
    init_hpcrun_format(argc, argv, NULL, NULL, false);
    // Create new metrics
    redload_metric_id = hpcrun_create_metric("RED_LOAD");
    redload_approx_metric_id = hpcrun_create_metric("RED_LOAD_APPROX");
    
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



