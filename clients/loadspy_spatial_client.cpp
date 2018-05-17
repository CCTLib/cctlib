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
#include <xmmintrin.h>
#include <immintrin.h>
#include "pin.H"
#include "shadow_memory.H"
#include "loop_extraction.h"

extern "C" {
#include "xed-interface.h"
#include "xed-common-hdrs.h"
}

// enable Data-centric
#define USE_TREE_BASED_FOR_DATA_CENTRIC
#define USE_TREE_WITH_ADDR
#include "cctlib.H"

using namespace std;
using namespace PinCCTLib;


#define IS_ACCESS_WITHIN_PAGE_BOUNDARY(accessAddr, accessLen)  (PAGE_OFFSET((accessAddr)) <= (PAGE_OFFSET_MASK - (accessLen)))

#define DECODE_DEAD(data) (static_cast<ContextHandle_t>(((data)  & 0xffffffffffffffff) >> 32))
#define DECODE_KILL(data) (static_cast<ContextHandle_t>( (data)  & 0x00000000ffffffff))

#define MAKE_CONTEXT_PAIR(a, b) (((uint64_t)(a) << 32) | ((uint64_t)(b)))
#define MAKE_OBJ_ID(a, b) (((uint64_t)(a) << 32) | ((uint64_t)(b)))

#define MAX_OBJS_TO_LOG 100
#define MAX_REDUNDANT_CONTEXTS_PER_OBJ_TO_LOG 10
#define THREAD_MAX 1024
#define delta 0.01

#ifdef ENABLE_SAMPLING
#define WINDOW_ENABLE 1000000    // 1   million 
#define WINDOW_DISABLE 100000000 // 100 million
#endif


/***********************************************
 ******  shadow memory
 ************************************************/
ConcurrentShadowMemory<uint8_t, uint64_t, ContextHandle_t, uint64_t> sm; // <shadow address, address previously accessed in the data object, calling context, timestamp counter>
ConcurrentShadowMemory<LoopNode *> instSM; // shadow memory storing pointers to loop nodes

struct {
    char dummy1[128];
    xed_state_t  xedState;
    char dummy2[128];
} LoadSpyGlobals;
////////////////////////////////////////////////

struct LoadSpyThreadData {
    
    uint64_t bytesLoad;
    
    long long numIns;
    bool sampleFlag;
};


#ifdef ENABLE_VISUALIZATION
// for metric logging
int redload_metric_id = 0;
int redload_approx_metric_id = 0;
#endif

// for statistics result
uint64_t grandTotBytesLoad;
uint64_t grandTotBytesRedLoad;
uint64_t grandTotBytesApproxRedLoad;

// key for accessing TLS storage in the threads. initialized once in main()
static TLS_KEY client_tls_key;
static LoadSpyThreadData* gSingleThreadedTData;

// function to access thread-specific data
inline LoadSpyThreadData* ClientGetTLS(const THREADID threadId) {
#ifdef MULTI_THREADED
    LoadSpyThreadData* tdata =
    static_cast<LoadSpyThreadData*>(PIN_GetThreadData(client_tls_key, threadId));
    return tdata;
#else
    return gSingleThreadedTData;
#endif
}

uint64_t globalCounter[THREAD_MAX] = {0}; // thread-local timestamp counter

struct DynamicLoop {
    ADDRINT ip;       // loop header IP
    uint64_t counter; // timestamp counter 
};

struct RedundancyMetric {
    uint64_t bytes;  // redundant bytes
    ADDRINT scopeIP; // loop header IP
}; 

#if 0
uint64_t maxScopeSearchNum = 1;

// user-defined number of carrying scope search
static inline void SetScopeSearchNum () {
    char* envPath = getenv("MAX_CS_SEARCH_NUM");
    
    if (!envPath) {
        maxScopeSearchNum = strtoull(envPath, NULL, 10);
        printf("You export MAX_CS_SEARCH_NUM=%lu\n", maxScopeSearchNum);
    }
    else printf("Warning: Maximum number of searching carrying scope for each redundant pair is %lu by default!!!\n", maxScopeSearchNum);
}
#endif

vector<FuncInfo> Func;
unordered_map<ADDRINT, char[MAX_STRING_LENGTH]> StaticLoopTable; // <IP, absolute path>
bool scopeSwitch = false;

static inline void LoadHPCStructFile() {
    const char* envPath = getenv("HPCSTRUCT_FILE");
    
    if(!envPath) {
        printf("Warning: You do not set HPCSTRUCT_FILE and Loadspy will not show redundancy scopes of redundancy pairs with same calling contexts!!!\n");
        printf("Warning: Please specify HPCSTRUCT_FILE if you need to grab redundancy scopes!!!\n");
        return;
    }
    
    scopeSwitch = true;
    printf("You export HPCSTRUCT_FILE=%s\n", envPath);
    ExtractLoopInfo(envPath, Func, StaticLoopTable); // extract loop information from the hpcstruct file
}


static INT32 Usage() {
    PIN_ERROR("Pin tool to gather calling context on each load and store.\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}


static FILE* gTraceFile;

// initialize the needed data structures before launching the target program
static void ClientInit(int argc, char* argv[]) {
    // Create output file
    char name[MAX_FILE_PATH] = "loadspy_spatial_client.out.";
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
    
    // initialize XED for decoding instructions
    xed_state_init(&LoadSpyGlobals.xedState, XED_MACHINE_MODE_LONG_64, (xed_address_width_enum_t) 0, XED_ADDRESS_WIDTH_64b);
}


unordered_map<ADDRINT, uint64_t> DynamicLoopTable[THREAD_MAX]; // <loop header IP, timestamp counter>

// get the redundancy scope of a redundancy pair with the same dead and killing calling contexts.
static inline ADDRINT ScopeSearch(ContextHandle_t ctxtHandle, uint64_t prevCounter, /* uint64_t curCounter, */ THREADID threadId) {
    vector<ADDRINT> parentIPs;
    GetParentIPs(ctxtHandle, parentIPs);
    
    uint64_t minCounter = UINT64_MAX;
    ADDRINT scopeIP = 0;
    
    // traverse the call path upward towards the root node to find out the loop header instruction that has the minimal timestamp counter 
    for(uint32_t i = 0; i < parentIPs.size(); i++) {
        ADDRINT ip = parentIPs[i];
        tuple<struct LoopNode *[SHADOW_PAGE_SIZE]> *t = instSM.GetShadowBaseAddress((uint64_t)ip);
        if(t == NULL) continue;
        
        LoopNode *loop = get<0>(*t)[PAGE_OFFSET(((uint64_t)ip))];
        if(loop == NULL) continue;
        
        while(loop->parent != NULL) { 
            ADDRINT beginIP = loop->beginIP;
            uint64_t counter = DynamicLoopTable[threadId][beginIP];
            if(counter >= prevCounter && counter < minCounter) {
                minCounter = counter;
                scopeIP = beginIP;
            } 
            loop = loop->parent; 
        }
    }
    
    return scopeIP;
}


static unordered_map<uint64_t, unordered_map<uint64_t, RedundancyMetric>> ObjRedTable[THREAD_MAX]; // <obj ID, <(cxt1, cxt2), (redundant bytes, scope IP)>>
static unordered_map<uint64_t, unordered_map<uint64_t, RedundancyMetric>> ObjApproxRedTable[THREAD_MAX]; // <obj ID, <(cxt1, cxt2), (redundant bytes, scope IP)>>

// record a precise redundancy pair and its object ID into the redundancy table
static inline void AddToObjRedTable(uint64_t objId, uint64_t ctxtPairId, uint16_t bytes, ADDRINT scopeIP, THREADID threadId) __attribute__((always_inline, flatten));
static inline void AddToObjRedTable(uint64_t objId, uint64_t ctxtPairId, uint16_t bytes, ADDRINT scopeIP, THREADID threadId) {
    
    unordered_map<uint64_t, unordered_map<uint64_t, RedundancyMetric>>::iterator it = ObjRedTable[threadId].find(objId);
    
    if(it == ObjRedTable[threadId].end()) {
        ObjRedTable[threadId][objId][ctxtPairId].bytes = bytes;
        ObjRedTable[threadId][objId][ctxtPairId].scopeIP = scopeIP;
    } else {
        unordered_map<uint64_t, RedundancyMetric>::iterator it2 = (it->second).find(ctxtPairId);
        if(it2 == (it->second).end()) {
            (it->second)[ctxtPairId].bytes = bytes;
            (it->second)[ctxtPairId].scopeIP = scopeIP;
        } else { 
            (it2->second).bytes += bytes;
        }
    }

}


// record an approximate redundancy pair and its object ID into the corresponding redudancy table
static inline void AddToObjApproxRedTable(uint64_t objId, uint64_t ctxtPairId, uint16_t bytes, ADDRINT scopeIP, THREADID threadId) __attribute__((always_inline, flatten));
static inline void AddToObjApproxRedTable(uint64_t objId, uint64_t ctxtPairId, uint16_t bytes, ADDRINT scopeIP, THREADID threadId) {
    
    unordered_map<uint64_t, unordered_map<uint64_t, RedundancyMetric>>::iterator it = ObjApproxRedTable[threadId].find(objId);
    
    if(it == ObjApproxRedTable[threadId].end()) {
        ObjApproxRedTable[threadId][objId][ctxtPairId].bytes = bytes;
        ObjApproxRedTable[threadId][objId][ctxtPairId].scopeIP = scopeIP;
    } else {
        unordered_map<uint64_t, RedundancyMetric>::iterator it2 = (it->second).find(ctxtPairId);
        if(it2 == (it->second).end()) {
            (it->second)[ctxtPairId].bytes = bytes;
            (it->second)[ctxtPairId].scopeIP = scopeIP;
        } else { 
            (it2->second).bytes += bytes;
        }
    }

}


// check if the dead and killing calling contexts of a redundancy pair are the same
static inline bool IsSameDeadKill(ContextHandle_t prevCtxtHandle, ContextHandle_t curCtxtHandle) {
    return (scopeSwitch && prevCtxtHandle == curCtxtHandle); 
} 


// check if the number of searching redundancy scope is beyond the upper bound the user set (1 by default)
static inline bool IsRepeatedScopeSearch(uint64_t objId, uint64_t ctxtPairId, bool isApprox, THREADID threadId) {
    unordered_map<uint64_t, unordered_map<uint64_t, RedundancyMetric>>::iterator it;
    unordered_map<uint64_t, RedundancyMetric>::iterator it2;
    
    if(isApprox) {
        it = ObjApproxRedTable[threadId].find(objId);
        if(it == ObjApproxRedTable[threadId].end()) return false;
        else {
            it2 = (it->second).find(ctxtPairId);
            if(it2 == (it->second).end()) return false;
            else return true;
        }
    } else {
        it = ObjRedTable[threadId].find(objId);
        if (it == ObjRedTable[threadId].end()) return false;
        else {
            it2 = (it->second).find(ctxtPairId);
            if(it2 == (it->second).end()) return false;
            else return true;
        }
    }
}


// certain FP instructions should not be approximated
static inline bool IsOkToApproximate(xed_decoded_inst_t & xedd) {
    xed_category_enum_t cat = xed_decoded_inst_get_category(&xedd);
    xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass (&xedd);
    switch(iclass) {
	    case XED_ICLASS_FLDENV:
	    case XED_ICLASS_FNSTENV:
	    case XED_ICLASS_FNSAVE:
	    case XED_ICLASS_FLDCW:
	    case XED_ICLASS_FNSTCW:
	    case XED_ICLASS_FXRSTOR:
	    case XED_ICLASS_FXRSTOR64:
	    case XED_ICLASS_FXSAVE:
	    case XED_ICLASS_FXSAVE64:
		    return false;
	    default:
		    return true;
    }
}


static inline bool IsFloatInstructionAndOkToApproximate(ADDRINT ip) {
    xed_decoded_inst_t  xedd;
    xed_decoded_inst_zero_set_mode(&xedd, &LoadSpyGlobals.xedState);
    
    if(XED_ERROR_NONE == xed_decode(&xedd, (const xed_uint8_t*)(ip), 15)) {
        xed_category_enum_t cat = xed_decoded_inst_get_category(&xedd);
        switch(cat) {
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
                for(int i =0; i < noperands; i++) {
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
                switch(eType) {
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
    } else {
        assert(0 && "failed to disassemble instruction");
        return false;
    }
}


static inline uint16_t FloatOperandSize(ADDRINT ip, uint32_t oper) {
    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd, &LoadSpyGlobals.xedState);
    
    if(XED_ERROR_NONE == xed_decode(&xedd, (const xed_uint8_t*)(ip), 15)) {
        xed_operand_element_type_enum_t TypeOperand = xed_decoded_inst_operand_element_type(&xedd,oper);
        if(TypeOperand == XED_OPERAND_ELEMENT_TYPE_SINGLE || TypeOperand == XED_OPERAND_ELEMENT_TYPE_FLOAT16)
            return 4;
        if(TypeOperand == XED_OPERAND_ELEMENT_TYPE_DOUBLE) {
            return 8;
        }
        if(TypeOperand == XED_OPERAND_ELEMENT_TYPE_LONGDOUBLE) {
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
/************************ Spatial load redundancy functions **************************/
/***************************************************************************************/

template<int start, int end, int incr, bool conditional, bool approx>
struct UnrolledLoop {
    static __attribute__((always_inline)) void Body(function<void (const int)> func) {
        func(start); // real loop body
        UnrolledLoop<start+incr, end, incr, conditional, approx>:: Body(func); // unroll next iteration
    }

    static __attribute__((always_inline)) void BodySamePage(uint64_t objId, ContextHandle_t * __restrict__ objPrevCtxtHandle, const ContextHandle_t curCtxtHandle, uint64_t * __restrict__ objPrevCounter, const uint64_t curCounter, THREADID threadId) {
        if(conditional) {
            ADDRINT scopeIP = 0;
            bool isSameDeadKill = IsSameDeadKill(objPrevCtxtHandle[start], curCtxtHandle);
            // report in RedTable
            if(approx) {
                if(isSameDeadKill) {
                    if(!IsRepeatedScopeSearch(objId, MAKE_CONTEXT_PAIR(objPrevCtxtHandle[start], curCtxtHandle), approx, threadId))
                        scopeIP = ScopeSearch(curCtxtHandle, objPrevCounter[start], threadId);
                }
                AddToObjApproxRedTable(objId, MAKE_CONTEXT_PAIR(objPrevCtxtHandle[start], curCtxtHandle), 1, scopeIP, threadId); 
            } else {
                if(isSameDeadKill) {
                    if(!IsRepeatedScopeSearch(objId, MAKE_CONTEXT_PAIR(objPrevCtxtHandle[start], curCtxtHandle), approx, threadId))
                        scopeIP = ScopeSearch(curCtxtHandle, objPrevCounter[start], threadId);
                }
                AddToObjRedTable(objId, MAKE_CONTEXT_PAIR(objPrevCtxtHandle[start], curCtxtHandle), 1, scopeIP, threadId); 
            }
        }
        // update context and timestamp counter
        objPrevCtxtHandle[start] = curCtxtHandle;
        objPrevCounter[start] = curCounter;
        
        UnrolledLoop<start+incr, end, incr, conditional, approx>:: BodySamePage(objId, objPrevCtxtHandle, curCtxtHandle, objPrevCounter, curCounter, threadId); // unroll next iteration
    }

    static __attribute__((always_inline)) void BodyStraddlePage(uint64_t objId, uint64_t addr, const ContextHandle_t curCtxtHandle, const uint64_t curCounter, THREADID threadId){
        
        tuple<uint8_t[SHADOW_PAGE_SIZE], uint64_t[SHADOW_PAGE_SIZE], ContextHandle_t[SHADOW_PAGE_SIZE], uint64_t[SHADOW_PAGE_SIZE]> &t = sm.GetOrCreateShadowBaseAddress((uint64_t)addr+start);
        ContextHandle_t * objPrevCtxtHandle = &(get<2>(t)[PAGE_OFFSET(((uint64_t)addr+start))]);
        uint64_t * objPrevCounter = &(get<3>(t)[PAGE_OFFSET(((uint64_t)addr+start))]);
        
        if(conditional) {
            ADDRINT scopeIP = 0;
            bool isSameDeadKill = IsSameDeadKill(objPrevCtxtHandle[0], curCtxtHandle);
            // report in RedTable
            if(approx) {
                if(isSameDeadKill) {
                    if(!IsRepeatedScopeSearch(objId, MAKE_CONTEXT_PAIR(objPrevCtxtHandle[0], curCtxtHandle), approx, threadId))
                        scopeIP = ScopeSearch(curCtxtHandle, objPrevCounter[0], threadId);
                }
                AddToObjApproxRedTable(objId, MAKE_CONTEXT_PAIR(objPrevCtxtHandle[0], curCtxtHandle), 1, scopeIP, threadId);
            }
            else {
                if(isSameDeadKill) {
                    if(!IsRepeatedScopeSearch(objId, MAKE_CONTEXT_PAIR(objPrevCtxtHandle[0], curCtxtHandle), approx, threadId))
                        scopeIP = ScopeSearch(curCtxtHandle, objPrevCounter[0], threadId);
                }
                AddToObjRedTable(objId, MAKE_CONTEXT_PAIR(objPrevCtxtHandle[0], curCtxtHandle), 1, scopeIP, threadId);
            }
        }
        // update context and timestamp counter
        objPrevCtxtHandle[0] = curCtxtHandle;
        objPrevCounter[0] = curCounter;
        
        UnrolledLoop<start+incr, end, incr, conditional, approx>:: BodyStraddlePage(objId, addr, curCtxtHandle, curCounter, threadId);   // unroll next iteration
    }
};

template<int end, int incr, bool conditional, bool approx>
struct UnrolledLoop<end , end , incr, conditional, approx> {
    static __attribute__((always_inline)) void Body(function<void (const int)> func) {}
    
    static __attribute__((always_inline)) void BodySamePage(uint64_t objId, ContextHandle_t * __restrict__ objPrevCtxtHandle, const ContextHandle_t curCtxtHandle, uint64_t * __restrict__ objPrevCounter, const uint64_t curCounter, THREADID threadId) {}
    
    static __attribute__((always_inline)) void BodyStraddlePage(uint64_t objId, uint64_t addr, const ContextHandle_t curCtxtHandle, const uint64_t curCounter, THREADID threadId){}
};

template<int start, int end, int incr>
struct UnrolledConjunction {
    static __attribute__((always_inline)) bool Body(function<bool (const int)> func) {
        return func(start) && UnrolledConjunction<start+incr, end, incr>:: Body(func); // unroll next iteration
    }
    static __attribute__((always_inline)) bool BodyContextCheck(ContextHandle_t * __restrict__ ctxtHandle) {
        return (ctxtHandle[0] == ctxtHandle[start]) && UnrolledConjunction<start+incr, end, incr>:: BodyContextCheck(ctxtHandle); // unroll next iteration
    }
};

template<int end,  int incr>
struct UnrolledConjunction<end , end , incr> {
    static __attribute__((always_inline)) bool Body(function<void (const int)> func) {
        return true;
    }
    static __attribute__((always_inline)) bool BodyContextCheck(ContextHandle_t * __restrict__ ctxtHandle) {
        return true;
    }
};

template<class T, uint32_t AccessLen, bool isApprox>
struct LoadSpyAnalysis {
    static __attribute__((always_inline)) bool IsReadRedundant(void * addr, uint8_t * objShadowAddr) {
        
        if(isApprox) {
            if(AccessLen >= 32) {
                if(sizeof(T) == 4) {
                    __m256 oldValue = _mm256_loadu_ps( reinterpret_cast<const float*> (objShadowAddr));
                    __m256 newValue = _mm256_loadu_ps( reinterpret_cast<const float*> (addr));
                    
                    __m256 result = _mm256_sub_ps(newValue, oldValue);
                    result = _mm256_div_ps(result, oldValue);
                    
                    float rates[8] __attribute__((aligned(32)));
                    _mm256_store_ps(rates,result);
                    
                    _mm256_storeu_ps(reinterpret_cast<float*> (objShadowAddr), newValue);
                    
                    for(int i = 0; i < 8; ++i) {
                        if(rates[i] < -delta || rates[i] > delta) {
                            return false;
                        }
                    }
                    return true;
                    
                } else if(sizeof(T) == 8) {
                    __m256d oldValue = _mm256_loadu_pd( reinterpret_cast<const double*> (objShadowAddr));
                    __m256d newValue = _mm256_loadu_pd( reinterpret_cast<const double*> (addr));
                    
                    __m256d result = _mm256_sub_pd(newValue, oldValue);
                    result = _mm256_div_pd(result, oldValue);
                    
                    double rates[4] __attribute__((aligned(32)));
                    _mm256_store_pd(rates, result);
                    
                    _mm256_storeu_pd(reinterpret_cast<double*> (objShadowAddr), newValue);
                    
                    for(int i = 0; i < 4; ++i) {
                        if(rates[i] < -delta || rates[i] > delta) {
                            return false;
                        }
                    }
                    return true;
                }
            } else if(AccessLen == 16) {
                if(sizeof(T) == 4) {
                    __m128 oldValue = _mm_loadu_ps( reinterpret_cast<const float*> (objShadowAddr));
                    __m128 newValue = _mm_loadu_ps( reinterpret_cast<const float*> (addr));
                    
                    __m128 result = _mm_sub_ps(newValue, oldValue);
                    result = _mm_div_ps(result, oldValue);
                    
                    float rates[4] __attribute__((aligned(16)));
                    _mm_store_ps(rates, result);
                    
                    _mm_storeu_ps(reinterpret_cast<float*> (objShadowAddr), newValue);
                    
                    for(int i = 0; i < 4; ++i) {
                        if(rates[i] < -delta || rates[i] > delta) {
                            return false;
                        }
                    }
                    return true;
                } else if(sizeof(T) == 8) {
                    __m128d oldValue = _mm_loadu_pd( reinterpret_cast<const double*> (objShadowAddr));
                    __m128d newValue = _mm_loadu_pd( reinterpret_cast<const double*> (addr));
                    
                    __m128d result = _mm_sub_pd(newValue, oldValue);
                    
                    result = _mm_div_pd(result, oldValue);
                    
                    double rate[2];
                    _mm_storel_pd(&rate[0], result);
                    _mm_storeh_pd(&rate[1], result);
                    
                    _mm_storeu_pd(reinterpret_cast<double*> (objShadowAddr), newValue);
                    
                    if(rate[0] < -delta || rate[0] > delta)
                        return false;
                    if(rate[1] < -delta || rate[1] > delta)
                        return false;
                    return true;
                }
            } else if(AccessLen == 10) {
                UINT8 newValue[10];
                memcpy(newValue, addr, AccessLen);
                
                uint64_t * upperOld = (uint64_t*)&(objShadowAddr[2]);
                uint64_t * upperNew = (uint64_t*)&(newValue[2]);
                
                uint16_t * lowOld = (uint16_t*)&(objShadowAddr[0]);
                uint16_t * lowNew = (uint16_t*)&(newValue[0]);
                
                memcpy(objShadowAddr, addr, AccessLen);
                
                if((*lowOld & 0xfff0) == (*lowNew & 0xfff0) && *upperNew == *upperOld) {
                    return true;
                }
                return false;
            } else {
                T newValue = *(static_cast<T*>(addr));
                T oldValue = *((T*)(objShadowAddr));
                
                *((T*)(objShadowAddr)) = *(static_cast<T*>(addr));
                
                T rate = (newValue - oldValue)/oldValue;
                if(rate <= delta && rate >= -delta) return true;
                else return false;
            }
        } else {
            bool isRed = (*((T*)(objShadowAddr)) == *(static_cast<T*>(addr)));
            *((T*)(objShadowAddr)) = *(static_cast<T*>(addr));
            return isRed;
        }
        return false;
    }
    
    static __attribute__((always_inline)) VOID CheckNByteValueAfterRead(void* addr, uint32_t opaqueHandle, THREADID threadId) {

        uint64_t objId;
        uint64_t objBegAddr;
        DataHandle_t dataHandle = GetDataObjectHandle(addr, threadId);

        if(dataHandle.objectType == DYNAMIC_OBJECT) { // object type
            objId = MAKE_OBJ_ID(dataHandle.objectType, dataHandle.pathHandle); // construct a 64-bit integer as the object ID     
            objBegAddr = dataHandle.beg_addr; 
        }
        else if(dataHandle.objectType == STATIC_OBJECT) {
            objId = MAKE_OBJ_ID(dataHandle.objectType, dataHandle.symName);
            objBegAddr = dataHandle.beg_addr;
        }
        else return; // stack and unknown types
        
        LoadSpyThreadData* const tData = ClientGetTLS(threadId);
        
        ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
        
        // get the call context and shadow memory address of the previous load within the same object  
        tuple<uint8_t[SHADOW_PAGE_SIZE], uint64_t[SHADOW_PAGE_SIZE], ContextHandle_t[SHADOW_PAGE_SIZE], uint64_t[SHADOW_PAGE_SIZE]> &t = sm.GetOrCreateShadowBaseAddress(objBegAddr);
        
        // use the begin address of a data object to represent its address
        uint8_t * __restrict__ objShadowAddr = &(get<0>(t)[PAGE_OFFSET(objBegAddr)]); // the shadow addres of a data object
        uint64_t * __restrict__ objPrevAddr = &(get<1>(t)[PAGE_OFFSET(objBegAddr)]); // the address of the previous load in a data object
        ContextHandle_t * __restrict__ objPrevCtxtHandle = &(get<2>(t)[PAGE_OFFSET(objBegAddr)]); // the calling context of the previous load in a data
        uint64_t * __restrict__ objPrevCounter = &(get<3>(t)[PAGE_OFFSET(objBegAddr)]); // the timestamp counter of the previous load in a data objec
        
        uint64_t curCounter = globalCounter[threadId]++;

        bool isRedundantRead = false;
        if(*objPrevAddr != (uint64_t)addr) { // the previous and current loads must be performed on different memory locations
            objPrevAddr[0] = (uint64_t)addr;
            isRedundantRead = IsReadRedundant(addr, objShadowAddr);
        }        
        
        bool isSameDeadKill;
        ADDRINT scopeIP = 0; 
        const bool isAccessWithinPageBoundary = IS_ACCESS_WITHIN_PAGE_BOUNDARY((uint64_t)addr, AccessLen);
        
        if(isRedundantRead) {
            // all within page boundary?
            if(isAccessWithinPageBoundary) {
                // all from same ctxt?
                if(UnrolledConjunction<0, AccessLen, 1>::BodyContextCheck(objPrevCtxtHandle)) {
                    isSameDeadKill = IsSameDeadKill(objPrevCtxtHandle[0], curCtxtHandle);
                    if(isSameDeadKill) {
                        if(!IsRepeatedScopeSearch(objId, MAKE_CONTEXT_PAIR(objPrevCtxtHandle[0], curCtxtHandle), isApprox, threadId))
                            scopeIP = ScopeSearch(curCtxtHandle, objPrevCounter[0], threadId);
                    }
                    // report in RedTable
                    if(isApprox)
                        AddToObjApproxRedTable(objId, MAKE_CONTEXT_PAIR(objPrevCtxtHandle[0], curCtxtHandle), AccessLen, scopeIP, threadId);
                    else
                        AddToObjRedTable(objId, MAKE_CONTEXT_PAIR(objPrevCtxtHandle[0], curCtxtHandle), AccessLen, scopeIP, threadId);
                    // update context and timestamp counter
                    UnrolledLoop<0, AccessLen, 1, false/* redundancy is updated outside */, isApprox>::BodySamePage(objId, objPrevCtxtHandle, curCtxtHandle, objPrevCounter, curCounter, threadId);
                } else {
                    // different contexts
                    UnrolledLoop<0, AccessLen, 1, true/* redundancy is updated inside */, isApprox>::BodySamePage(objId, objPrevCtxtHandle, curCtxtHandle, objPrevCounter, curCounter, threadId);
                }
            } else { 
                // read across a 64-K page boundary. The first byte is on this page though
                isSameDeadKill = IsSameDeadKill(objPrevCtxtHandle[0], curCtxtHandle);
                if(isSameDeadKill) {
                    if(!IsRepeatedScopeSearch(objId, MAKE_CONTEXT_PAIR(objPrevCtxtHandle[0], curCtxtHandle), isApprox, threadId))
                        scopeIP = ScopeSearch(curCtxtHandle, objPrevCounter[0], threadId);
                }
                if(isApprox)
                    AddToObjApproxRedTable(objId, MAKE_CONTEXT_PAIR(objPrevCtxtHandle[0], curCtxtHandle), 1, scopeIP, threadId);
                else
                    AddToObjRedTable(objId, MAKE_CONTEXT_PAIR(objPrevCtxtHandle[0], curCtxtHandle), 1, scopeIP, threadId);
                // update context and timestamp counter 
                objPrevCtxtHandle[0] = curCtxtHandle;
                objPrevCounter[0] = curCounter;
                // remaining bytes [1..AccessLen] somewhere will across a 64-K page boundary
                UnrolledLoop<1, AccessLen, 1, true/* update redundancy */, isApprox>::BodyStraddlePage(objId, objBegAddr, curCtxtHandle, curCounter, threadId);
            }
        } else {
            // no redundancy
            // just update contexts
            if(isAccessWithinPageBoundary) {
                // update context and timestamp counter
                UnrolledLoop<0, AccessLen, 1, false/* no redundancy */, isApprox>::BodySamePage(objId, objPrevCtxtHandle, curCtxtHandle, objPrevCounter, curCounter, threadId);
            } else {
                // read across a 64-K page boundary
                // update context and timestamp counter
                objPrevCtxtHandle[0] = curCtxtHandle;
                objPrevCounter[0] = curCounter;
                
                // remaining bytes [1..AccessLen] somewhere will across a 64-K page boundary
                UnrolledLoop<1, AccessLen, 1, false/* no redundancy */, isApprox>::BodyStraddlePage(objId, objBegAddr, curCtxtHandle, curCounter, threadId);
            }
        }
    }
};


static inline VOID CheckAfterLargeRead(void* addr, UINT32 accessLen, uint32_t opaqueHandle, THREADID threadId){
    
    uint64_t objId;
    uint64_t objBegAddr;
    DataHandle_t dataHandle = GetDataObjectHandle(addr, threadId);
    
    if(dataHandle.objectType == DYNAMIC_OBJECT) {
        objId = MAKE_OBJ_ID(dataHandle.objectType, dataHandle.pathHandle);      
        objBegAddr = dataHandle.beg_addr;
    }
    else if(dataHandle.objectType == STATIC_OBJECT) {
        objId = MAKE_OBJ_ID(dataHandle.objectType, dataHandle.symName);      
        objBegAddr = dataHandle.beg_addr;
    }
    else return; // stack and unknown types
    
    LoadSpyThreadData* const tData = ClientGetTLS(threadId);
    ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
    
    // This assumes that a large read cannot straddle a page boundary -- strong assumption, but lets go with it for now.
    tuple<uint8_t[SHADOW_PAGE_SIZE], uint64_t[SHADOW_PAGE_SIZE], ContextHandle_t[SHADOW_PAGE_SIZE], uint64_t[SHADOW_PAGE_SIZE]> &t = sm.GetOrCreateShadowBaseAddress(objBegAddr);
    
    uint8_t * __restrict__ objShadowAddr = &(get<0>(t)[PAGE_OFFSET(objBegAddr)]); // the shadow addres of a data object
    uint64_t * __restrict__ objPrevAddr = &(get<1>(t)[PAGE_OFFSET(objBegAddr)]); // the address of the previous load in a data object
    ContextHandle_t * __restrict__ objPrevCtxtHandle = &(get<2>(t)[PAGE_OFFSET((uint64_t)objBegAddr)]); // the calling context of the previous load in a data object
    uint64_t * __restrict__ objPrevCounter = &(get<3>(t)[PAGE_OFFSET((uint64_t)objPrevAddr)]); // the timestamp counter of the previous load in a data objec
    
    uint64_t curCounter = globalCounter[threadId]++;
    ADDRINT scopeIP = 0; 
    
    // the previous and current loads must be performed on different memory locations
    if(*objPrevAddr != (uint64_t)addr) {
        objPrevAddr[0] = (uint64_t)addr;
        // detect redundancy 
        if(memcmp(objShadowAddr, addr, accessLen) == 0) {
        
            bool isSameDeadKill = IsSameDeadKill(objPrevCtxtHandle[0], curCtxtHandle);
            if(isSameDeadKill) {
                if(!IsRepeatedScopeSearch(objId, MAKE_CONTEXT_PAIR(objPrevCtxtHandle[0], curCtxtHandle), false/* precise redundancy */, threadId))
                    scopeIP = ScopeSearch(curCtxtHandle, objPrevCounter[0], threadId);
            }    
        
            ContextHandle_t objPrevCtx = objPrevCtxtHandle[0];
            
            for(UINT32 index = 0; index < accessLen; index++) {
                if(objPrevCtx != objPrevCtxtHandle[index]) { // executed iff the values of adjancent elememts in objPrevCtxtHandle[] are different 
                    objPrevCtx = objPrevCtxtHandle[index]; 
                    
                    isSameDeadKill = IsSameDeadKill(objPrevCtxtHandle[index], curCtxtHandle);
                    if(isSameDeadKill) {
                        if(!IsRepeatedScopeSearch(objId, MAKE_CONTEXT_PAIR(objPrevCtxtHandle[index], curCtxtHandle), false/* precise redundancy */, threadId))
                            scopeIP = ScopeSearch(curCtxtHandle, objPrevCounter[index], threadId);
                    }
                }                                                                                                                  
                
                // report in RedTable
                AddToObjRedTable(objId, MAKE_CONTEXT_PAIR(objPrevCtxtHandle[index], curCtxtHandle), 1, scopeIP, threadId);
                // update context and timestamp counter
                objPrevCtxtHandle[index] = curCtxtHandle;
                objPrevCounter[index] = curCounter;
            }
        } else {
            // no redundancy
            for(UINT32 index = 0; index < accessLen; index++){
                // update context and timestamp counter
                objPrevCtxtHandle[index] = curCtxtHandle;
                objPrevCounter[index] = curCounter;
            }
        }
    } else {
        // no redundancy 
        for(UINT32 index = 0; index < accessLen; index++) {
            // update context and timestamp counter
            objPrevCtxtHandle[index] = curCtxtHandle;
            objPrevCounter[index] = curCounter;
        }   
    }
    
    memcpy(objShadowAddr, addr, accessLen);
}


// update the timestamp counter of the loop that is being instrumented
static inline VOID UpdateDynamicLoopTable(void* ip, THREADID threadId) {
    unordered_map<ADDRINT, uint64_t>::iterator it = DynamicLoopTable[threadId].find((ADDRINT)ip);
    if(it == DynamicLoopTable[threadId].end()) DynamicLoopTable[threadId][(ADDRINT)ip] = globalCounter[threadId]++;
    else it->second = globalCounter[threadId]++;
}


#ifdef ENABLE_SAMPLING
static ADDRINT IfEnableSample(THREADID threadId){
    LoadSpyThreadData* const tData = ClientGetTLS(threadId);
    return tData->sampleFlag;
}

#define HANDLE_CASE(T, ACCESS_LEN, IS_APPROX) \
INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) IfEnableSample, IARG_THREAD_ID,IARG_END);\
INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) LoadSpyAnalysis<T, (ACCESS_LEN), (IS_APPROX)>::CheckNByteValueAfterRead, IARG_MEMORYOP_EA, memOp, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_INST_PTR,IARG_END)

#define HANDLE_LARGE() \
INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) IfEnableSample, IARG_THREAD_ID,IARG_END);\
INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) CheckAfterLargeRead, IARG_MEMORYOP_EA, memOp, IARG_MEMORYREAD_SIZE, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_END)

#define HANDLE_LOOP() \
INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) IfEnableSample, IARG_THREAD_ID,IARG_END);\
INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) UpdateDynamicLoopTable, IARG_INST_PTR, IARG_THREAD_ID, IARG_END)

#else

#define HANDLE_CASE(T, ACCESS_LEN, IS_APPROX) \
INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) LoadSpyAnalysis<T, (ACCESS_LEN), (IS_APPROX)>::CheckNByteValueAfterRead, IARG_MEMORYOP_EA, memOp, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_INST_PTR,IARG_END)

#define HANDLE_LARGE() \
INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) CheckAfterLargeRead, IARG_MEMORYOP_EA, memOp, IARG_MEMORYREAD_SIZE, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_END)

#define HANDLE_LOOP() \
INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) UpdateDynamicLoopTable, IARG_INST_PTR, IARG_THREAD_ID, IARG_END)
#endif


static int GetNumReadOperandsInIns(INS ins, UINT32 & whichOp){
    int numReadOps = 0;
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    for(UINT32 memOp = 0; memOp < memOperands; memOp++) {
        if(INS_MemoryOperandIsRead(ins, memOp)) {
            numReadOps++;
            whichOp = memOp;
        }
    }
    return numReadOps;
}


struct LoadSpyInstrument {
    static __attribute__((always_inline)) void InstrumentReadValueBeforeAndAfterLoading(INS ins, UINT32 memOp, uint32_t opaqueHandle){
        UINT32 refSize = INS_MemoryOperandSize(ins, memOp);
        
        if(IsFloatInstructionAndOkToApproximate(INS_Address(ins))) {
            unsigned int operSize = FloatOperandSize(INS_Address(ins),INS_MemoryOperandIndexToOperandIndex(ins,memOp));
            switch(refSize) {
                case 1:
                case 2: assert(0 && "memory read floating data with unexptected small size");
                case 4: HANDLE_CASE(float, 4, true); break;
                case 8: HANDLE_CASE(double, 8, true); break;
                case 10: HANDLE_CASE(uint8_t, 10, true); break;
                case 16: {
                    switch(operSize) {
                        case 4: HANDLE_CASE(float, 16, true); break;
                        case 8: HANDLE_CASE(double, 16, true); break;
                        default: assert(0 && "handle large mem read with unexpected operand size\n"); break;
                    }
                } break;
                case 32: {
                    switch(operSize) {
                        case 4: HANDLE_CASE(float, 32, true); break;
                        case 8: HANDLE_CASE(double, 32, true); break;
                        default: assert(0 && "handle large mem read with unexpected operand size\n"); break;
                    }
                } break;
                default: assert(0 && "unexpected large memory read\n"); break;
            }
        } else {
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
    
    static __attribute__((always_inline)) void InstrumentLoopIns(INS ins) {
        HANDLE_LOOP();
    }
};


static inline bool INS_IsIgnorable(INS ins){
    if( INS_IsFarJump(ins) || INS_IsDirectFarJump(ins) || INS_IsMaskedJump(ins))
        return true;
    else if(INS_IsRet(ins) || INS_IsIRet(ins))
        return true;
    else if(INS_IsCall(ins) || INS_IsSyscall(ins))
        return true;
    else if (INS_IsBranch(ins) || INS_IsRDTSC(ins) || INS_IsNop(ins))
        return true;
    else if(INS_IsBranchOrCall(ins)) 
        return true;
    else if(INS_IsPrefetch(ins)) // Prefetch instructions might access addresses which are invalid.
        return true;
    return false;
}


// record the innermost loop enclosing the instruction
static void RecordInnerMostLoop(ADDRINT ip) {
    static int prevIndex = 0; // memoize the location index when the search for the previous instruction finishes
    int leftDist = prevIndex;
    int funcCnt = (int)Func.size();
    
    int rightDist = funcCnt - prevIndex;
    int maxDist = leftDist > rightDist ? leftDist : rightDist;
    
    int tmp = 0;

    // locality-friendly search begins at "prevIndex" and alternates the linear search in both directions to the array start and end
    for(int i = 0; i < maxDist; i++) {
        SplayNode *splayRoot = NULL;
        
        tmp = prevIndex - i;
        if(tmp >= 0 && tmp < funcCnt) {
            if(ip >=Func[tmp].beginIP && ip < Func[tmp].endIP) { // function boundary: [beginIP, endIP)
                prevIndex = tmp;
                splayRoot = Func[tmp].splayRoot; 
                if(splayRoot != NULL) {
                    splayRoot = splay(splayRoot, ip); // search the splay tree 
                    Func[tmp].splayRoot = splayRoot;
                    if(ip >= splayRoot->beginIP && ip < splayRoot->endIP) { // loop boundary: [beginIP, endIP)
                        tuple<LoopNode *[SHADOW_PAGE_SIZE]> &t1 = instSM.GetOrCreateShadowBaseAddress((uint64_t)ip);
                        LoopNode **shadowAddr = &(get<0>(t1)[PAGE_OFFSET(((uint64_t)ip))]);
                        shadowAddr[0] = splayRoot->loop;
                        break;
                    }
                }
                break;
            }   
        }
        
        tmp = prevIndex + i + 1; 
        if(tmp < funcCnt) {
            if(ip >=Func[tmp].beginIP && ip < Func[tmp].endIP) { // function boundary: [beginIP, endIP)
                splayRoot = Func[tmp].splayRoot; 
                prevIndex = tmp;
                if(splayRoot != NULL) {
                    splayRoot = splay(splayRoot, ip); // search the splay tree
                    Func[tmp].splayRoot = splayRoot;
                    if(ip >= splayRoot->beginIP && ip < splayRoot->endIP) { // loop boundary: [beginIP, endIP)
                        tuple<LoopNode *[SHADOW_PAGE_SIZE]> &t2 = instSM.GetOrCreateShadowBaseAddress((uint64_t)ip);
                        LoopNode **shadowAddr = &(get<0>(t2)[PAGE_OFFSET(((uint64_t)ip))]);
                        shadowAddr[0] = splayRoot->loop; 
                        break;
                    }
                }
                break;
            }
        }
    }
}


static VOID InstrumentInsCallback(INS ins, VOID* v, const uint32_t opaqueHandle) {
    ADDRINT ip = INS_Address(ins);
    
    if(scopeSwitch) {
        RecordInnerMostLoop(ip);
        if(StaticLoopTable.find(ip) != StaticLoopTable.end()) // check if it is a loop header instruction
            LoadSpyInstrument::InstrumentLoopIns(ins);
    }
    
    if(!INS_HasFallThrough(ins)) return;
    if(INS_IsIgnorable(ins)) return;
    
    xed_decoded_inst_t  xedd;
    xed_state_t  xed_state;
    xed_decoded_inst_zero_set_mode(&xedd, &xed_state);
    if(XED_ERROR_NONE != xed_decode(&xedd, (const xed_uint8_t*)(ip), 15)) return;

    // instrument memory reads to find redundancy
    // special case, if we have only one read operand
    UINT32 whichOp = 0;
    if(GetNumReadOperandsInIns(ins, whichOp) == 1) {
        // read the value at location before and after the instruction
        LoadSpyInstrument::InstrumentReadValueBeforeAndAfterLoading(ins, whichOp, opaqueHandle);
    } else {
        UINT32 memOperands = INS_MemoryOperandCount(ins);
        for(UINT32 memOp = 0; memOp < memOperands; memOp++) {
            if(!INS_MemoryOperandIsRead(ins, memOp)) continue;
            LoadSpyInstrument::InstrumentReadValueBeforeAndAfterLoading(ins, memOp, opaqueHandle);
        }
    }
}


#ifdef ENABLE_SAMPLING
inline VOID UpdateAndCheck(uint32_t count, uint32_t bytes, THREADID threadId) {
    LoadSpyThreadData* const tData = ClientGetTLS(threadId);
    
    if(tData->sampleFlag){
        tData->numIns += count;
        if(tData->numIns > WINDOW_ENABLE){
            tData->sampleFlag = false;
            tData->numIns = 0;
        }
    } else {
        tData->numIns += count;
        if(tData->numIns > WINDOW_DISABLE){
            tData->sampleFlag = true;
            tData->numIns = 0;
        }
    }

    if(tData->sampleFlag) {
        tData->bytesLoad += bytes;
    }
}


inline VOID Update(uint32_t count, uint32_t bytes, THREADID threadId){
    LoadSpyThreadData* const tData = ClientGetTLS(threadId);
    tData->numIns += count;
    
    if(tData->sampleFlag) {
        tData->bytesLoad += bytes;
    }
}


//instrument the trace, count the number of instructions in the trace, decide to instrument or not
static void InstrumentTrace(TRACE trace, void* f) {
    bool check = false;
    for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        uint32_t totInsInBbl = BBL_NumIns(bbl);
        uint32_t totBytes = 0;
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            
            if(!INS_HasFallThrough(ins)) continue;
            if(INS_IsIgnorable(ins)) continue;
            
            if(INS_IsMemoryRead(ins)) {
                totBytes += INS_MemoryReadSize(ins);
            }
        }
        
        if(BBL_InsTail(bbl) == BBL_InsHead(bbl)) {
            BBL_InsertCall(bbl,IPOINT_BEFORE,(AFUNPTR)UpdateAndCheck, IARG_UINT32, totInsInBbl, IARG_UINT32,totBytes, IARG_THREAD_ID, IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
        } else if(INS_IsIndirectBranchOrCall(BBL_InsTail(bbl))) {
            BBL_InsertCall(bbl,IPOINT_BEFORE,(AFUNPTR)UpdateAndCheck, IARG_UINT32, totInsInBbl, IARG_UINT32,totBytes, IARG_THREAD_ID, IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
        } else {
            if(check) {
                BBL_InsertCall(bbl,IPOINT_BEFORE,(AFUNPTR)UpdateAndCheck, IARG_UINT32, totInsInBbl, IARG_UINT32, totBytes, IARG_THREAD_ID, IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
                check = false;
            } else {
                BBL_InsertCall(bbl,IPOINT_BEFORE,(AFUNPTR)Update, IARG_UINT32, totInsInBbl, IARG_UINT32, totBytes, IARG_THREAD_ID, IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
                check = true;
            }
        }
    }
}


#else
inline VOID Update(uint32_t bytes, THREADID threadId) {
    LoadSpyThreadData* const tData = ClientGetTLS(threadId);
    tData->bytesLoad += bytes;
}


//instrument the trace, count the number of ins in the trace, decide to instrument or not
static void InstrumentTrace(TRACE trace, void* f) {
    
    for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        uint32_t totBytes = 0;
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            
            if(!INS_HasFallThrough(ins)) continue;
            if(INS_IsIgnorable(ins)) continue;
            
            if(INS_IsMemoryRead(ins)) {
                totBytes += INS_MemoryReadSize(ins);
            }
        }
        BBL_InsertCall(bbl,IPOINT_BEFORE,(AFUNPTR)Update, IARG_UINT32, totBytes, IARG_THREAD_ID, IARG_END);
    }
}
#endif


// redundant data for a object
struct ObjRedundancy {
    uint64_t objID;
    uint64_t bytes;
    unordered_map<uint64_t, RedundancyMetric> redPair;
};

static inline bool ObjRedundancyCompare(const struct ObjRedundancy &first, const struct ObjRedundancy &second) {
    return first.bytes > second.bytes ? true : false;
}


struct RedundancyPair {
    ContextHandle_t dead;
    ContextHandle_t kill;
    uint64_t bytes;
    ADDRINT scopeIP;
};

static inline bool RedundancyCompare(const struct RedundancyPair &first, const struct RedundancyPair &second) {
    return first.bytes > second.bytes ? true : false;
}


static void PrintRedundancyPairs(THREADID threadId) {
    vector<ObjRedundancy> tmpList;
    uint64_t grandTotalRedundantBytes = 0;
    
    fprintf(gTraceFile, "\n*************** Dump Data from Thread %d ****************\n", threadId);
    
    for(unordered_map<uint64_t, unordered_map<uint64_t, RedundancyMetric>>::iterator it = ObjRedTable[threadId].begin(); it != ObjRedTable[threadId].end(); ++it) {
        uint64_t objRedundantBytes = 0;
        for(unordered_map<uint64_t, RedundancyMetric>::iterator it2 = (*it).second.begin(); it2 != (*it).second.end(); ++it2) {
            grandTotalRedundantBytes += (*it2).second.bytes;
            objRedundantBytes += (*it2).second.bytes;
        }
        ObjRedundancy tmp = {(*it).first, objRedundantBytes, (*it).second};
        tmpList.push_back(tmp); 
    }
    __sync_fetch_and_add(&grandTotBytesRedLoad, grandTotalRedundantBytes);
    
    fprintf(gTraceFile,"\n########## Precise Redundancies ##########\n"); 
    fprintf(gTraceFile, "\n Total redundant bytes = %f %%\n", grandTotalRedundantBytes * 100.0 / ClientGetTLS(threadId)->bytesLoad);

    // sort objects according to their redundant bytes 
    sort(tmpList.begin(), tmpList.end(), ObjRedundancyCompare);
    int objNum = 0; 
    for(vector<ObjRedundancy>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if(objNum++ >= MAX_OBJS_TO_LOG) break;
        if((uint8_t)DECODE_DEAD((*listIt).objID) == DYNAMIC_OBJECT) {
            fprintf(gTraceFile, "\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Dynamic Object: ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
            PrintFullCallingContext(DECODE_KILL((*listIt).objID)); // segfault might happen if the shadow memory based data centric is used
        } else  
            fprintf(gTraceFile, "\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Static Object: %s ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", GetStringFromStringPool((uint32_t)DECODE_KILL((*listIt).objID)));
        
        vector<RedundancyPair> tmpList2;
        for(unordered_map<uint64_t, RedundancyMetric>::iterator it = (*listIt).redPair.begin(); it != (*listIt).redPair.end(); ++it) {
            RedundancyPair tmp = {DECODE_DEAD ((*it).first), DECODE_KILL((*it).first), (*it).second.bytes, (*it).second.scopeIP};
            tmpList2.push_back(tmp);
        }
        // sort redundancy pairs within the same objext according to their redundant bytes
        sort(tmpList2.begin(), tmpList2.end(), RedundancyCompare);
        
        int cntxtNum = 0;
        for(vector<RedundancyPair>::iterator listIt2 = tmpList2.begin(); listIt2 != tmpList2.end(); ++listIt2) {
            if(cntxtNum++ >= MAX_REDUNDANT_CONTEXTS_PER_OBJ_TO_LOG) break;
            
            fprintf(gTraceFile, "\n\n==========================================\n");
            fprintf(gTraceFile, "Redundancy Ratio = %f %%\n", (*listIt2).bytes * 100.0 / grandTotalRedundantBytes);
            
            // check if it is a valid loop header instruction
            ADDRINT scopeIP = (*listIt2).scopeIP;
            if(scopeIP) fprintf(gTraceFile, "Redundancy Scope: 0x%lx:%s\n", scopeIP, StaticLoopTable[scopeIP]);
            
            if((*listIt2).dead == 0) {
                fprintf(gTraceFile, "\n Prepopulated with by OS\n");
            } else {
                PrintFullCallingContext((*listIt2).dead);
            }
            fprintf(gTraceFile, "\n---------------------Redundant load with---------------------------\n");
            PrintFullCallingContext((*listIt2).kill);
        }
    }
}


static void PrintApproxRedundancyPairs(THREADID threadId) {
    vector<ObjRedundancy> tmpList;
    uint64_t grandTotalApproxRedundantBytes = 0;
    
    fprintf(gTraceFile, "\n*************** Dump Data(delta=%.2f%%) from Thread %d ****************\n", delta*100,threadId);
   
    for(unordered_map<uint64_t, unordered_map<uint64_t, RedundancyMetric>>::iterator it = ObjApproxRedTable[threadId].begin(); it != ObjApproxRedTable[threadId].end(); ++it) {
        uint64_t objApproxRedundantBytes = 0;
        for(unordered_map<uint64_t, RedundancyMetric>::iterator it2 = (*it).second.begin(); it2 != (*it).second.end(); ++it2) {
            grandTotalApproxRedundantBytes += (*it2).second.bytes;
            objApproxRedundantBytes += (*it2).second.bytes;
        }
        ObjRedundancy tmp = {(*it).first, objApproxRedundantBytes, (*it).second};
        tmpList.push_back(tmp); 
    }
    __sync_fetch_and_add(&grandTotBytesApproxRedLoad, grandTotalApproxRedundantBytes);
    
    fprintf(gTraceFile,"\n########## Approximate Redundancies ##########\n"); 
    fprintf(gTraceFile, "\n Total redundant bytes = %f %%\n", grandTotalApproxRedundantBytes * 100.0 / ClientGetTLS(threadId)->bytesLoad);

    // sort objects according to their redundant Bytes 
    sort(tmpList.begin(), tmpList.end(), ObjRedundancyCompare);
    int objNum = 0;
    for(vector<ObjRedundancy>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if(objNum++ >= MAX_OBJS_TO_LOG) break;
        
        if((uint8_t)DECODE_DEAD((*listIt).objID) == DYNAMIC_OBJECT) {
            fprintf(gTraceFile, "\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Dynamic Object: ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
            PrintFullCallingContext(DECODE_KILL((*listIt).objID)); // segfault might happen if shadow memory based data centric is used
        } else  
            fprintf(gTraceFile, "\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Static Object: %s ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", GetStringFromStringPool((uint32_t)DECODE_KILL((*listIt).objID)));
        
        vector<RedundancyPair> tmpList2;
        for(unordered_map<uint64_t, RedundancyMetric>::iterator it = (*listIt).redPair.begin(); it != (*listIt).redPair.end(); ++it) {
            RedundancyPair tmp = {DECODE_DEAD((*it).first), DECODE_KILL((*it).first), (*it).second.bytes, (*it).second.scopeIP};
            tmpList2.push_back(tmp);
        }
        // sort redundancy pairs within the same objext according to their redundant bytes
        sort(tmpList2.begin(), tmpList2.end(), RedundancyCompare);
        
        int cntxtNum = 0;
        for(vector<RedundancyPair>::iterator listIt2 = tmpList2.begin(); listIt2 != tmpList2.end(); ++listIt2) {
            if(cntxtNum++ >= MAX_REDUNDANT_CONTEXTS_PER_OBJ_TO_LOG) break;
            
            fprintf(gTraceFile, "\n\n==========================================\n");
            fprintf(gTraceFile, "Redundancy Ratio = %f %%\n", (*listIt2).bytes * 100.0 / grandTotalApproxRedundantBytes);
            
            // check if it is a valid loop header instruction
            ADDRINT scopeIP = (*listIt2).scopeIP;
            if(scopeIP) fprintf(gTraceFile, "Redundancy Scope: 0x%lx:%s\n", scopeIP, StaticLoopTable[scopeIP]);
            
            if((*listIt2).dead == 0) {
                fprintf(gTraceFile, "\n Prepopulated with  by OS\n");
            } else {
                PrintFullCallingContext((*listIt2).dead);
            }
            fprintf(gTraceFile, "\n---------------------Redundant load with---------------------------\n");
            PrintFullCallingContext((*listIt2).kill);
        }
    } 
}


#ifdef ENABLE_VISUALIZATION
struct HPCRedundancyPair {
    ContextHandle_t dead;
    ContextHandle_t kill;
    uint64_t bytes;
};


static inline bool HPCRedundancyCompare(const struct HPCRedundancyPair &first, const struct HPCRedundancyPair &second) {
    return first.bytes > second.bytes ? true : false;
}


static void HPCRunRedundancyPairs(THREADID threadId) {
    vector<HPCRedundancyPair> tmpList;
    vector<HPCRedundancyPair>::iterator tmpIt;
    
    for(unordered_map<uint64_t, unordered_map<uint64_t, RedundancyMetric>>::iterator it = ObjRedTable[threadId].begin(); it != ObjRedTable[threadId].end(); ++it) {
        for(unordered_map<uint64_t, RedundancyMetric>::iterator it2 = (*it).second.begin(); it2 != (*it).second.end(); ++it2) {
            HPCRedundancyPair tmp = {DECODE_DEAD((*it2).first), DECODE_KILL((*it2).first), (*it2).second.bytes};
            tmpList.push_back(tmp);
        } 
    }
    
    sort(tmpList.begin(), tmpList.end(), HPCRedundancyCompare);
    vector<HPCRunCCT_t*> HPCRunNodes;
    int cntxtNum = 0;
    for(vector<HPCRedundancyPair>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if(cntxtNum++ >= MAX_REDUNDANT_CONTEXTS_PER_OBJ_TO_LOG) break;
            
        HPCRunCCT_t *HPCRunNode = new HPCRunCCT_t();
        HPCRunNode->ctxtHandle1 = (*listIt).dead;
        HPCRunNode->ctxtHandle2 = (*listIt).kill;
        HPCRunNode->metric = (*listIt).bytes;
        HPCRunNode->metric_id = redload_metric_id;
        HPCRunNodes.push_back(HPCRunNode);
    }
    newCCT_hpcrun_build_cct(HPCRunNodes, threadId);
}


static void HPCRunApproxRedundancyPairs(THREADID threadId) {
    vector<HPCRedundancyPair> tmpList;
    vector<HPCRedundancyPair>::iterator tmpIt;
    
    for(unordered_map<uint64_t, unordered_map<uint64_t, RedundancyMetric>>::iterator it = ObjApproxRedTable[threadId].begin(); it != ObjApproxRedTable[threadId].end(); ++it) {
        for(unordered_map<uint64_t, RedundancyMetric>::iterator it2 = (*it).second.begin(); it2 != (*it).second.end(); ++it2) {
            HPCRedundancyPair tmp = {DECODE_DEAD((*it2).first), DECODE_KILL((*it2).first), (*it2).second.bytes};
            tmpList.push_back(tmp);
        }
    }
    
    sort(tmpList.begin(), tmpList.end(), HPCRedundancyCompare);
    vector<HPCRunCCT_t*> HPCRunNodes;
    int cntxtNum = 0;
    for(vector<HPCRedundancyPair>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if(cntxtNum++ >= MAX_REDUNDANT_CONTEXTS_PER_OBJ_TO_LOG) break;

        HPCRunCCT_t *HPCRunNode = new HPCRunCCT_t();
        HPCRunNode->ctxtHandle1 = (*listIt).dead;
        HPCRunNode->ctxtHandle2 = (*listIt).kill;
        HPCRunNode->metric = (*listIt).bytes;
        HPCRunNode->metric_id = redload_approx_metric_id;
        HPCRunNodes.push_back(HPCRunNode);
    }
    newCCT_hpcrun_build_cct(HPCRunNodes, threadId);
}
#endif


// On each Unload of a loaded image, the accummulated redundancy information is dumped
static VOID ImageUnload(IMG img, VOID* v) {
    fprintf(gTraceFile, "\n TODO .. Multi-threading is not well supported.");
    THREADID  threadId =  PIN_ThreadId();
    fprintf(gTraceFile, "\nUnloading %s", IMG_Name(img).c_str());
    
    if(ObjRedTable[threadId].empty() && ObjApproxRedTable[threadId].empty()) return;
    
    PIN_LockClient();
    PrintRedundancyPairs(threadId);
    PrintApproxRedundancyPairs(threadId);
    PIN_UnlockClient();
    
    // clear redmap now
    ObjRedTable[threadId].clear();
    ObjApproxRedTable[threadId].clear();
}


static VOID ThreadFiniFunc(THREADID threadId, const CONTEXT *ctxt, INT32 code, VOID *v) {
    
    __sync_fetch_and_add(&grandTotBytesLoad, ClientGetTLS(threadId)->bytesLoad);

#ifdef ENABLE_VISUALIZATION
    // output the CCT for hpcviewer format
    HPCRunRedundancyPairs(threadId);
    HPCRunApproxRedundancyPairs(threadId);
    newCCT_hpcrun_selection_write(threadId);
#endif
}


static VOID FiniFunc(INT32 code, VOID *v) {
    // do whatever you want to the full CCT with footpirnt
    uint64_t redReadTmp = 0;
    uint64_t approxRedReadTmp = 0;
    for(int i = 0; i < THREAD_MAX; ++i) {
        if(!ObjRedTable[i].empty()) {
            for(unordered_map<uint64_t, unordered_map<uint64_t, RedundancyMetric>>::iterator it = ObjRedTable[i].begin(); it != ObjRedTable[i].end(); ++it) {
                for(unordered_map<uint64_t, RedundancyMetric>::iterator it2 = (*it).second.begin(); it2 != (*it).second.end(); ++it2)
                    redReadTmp += (*it2).second.bytes;
            }
        }
        if(!ObjApproxRedTable[i].empty()) {
            for(unordered_map<uint64_t, unordered_map<uint64_t, RedundancyMetric>>::iterator it = ObjApproxRedTable[i].begin(); it != ObjApproxRedTable[i].end(); ++it) {
                for(unordered_map<uint64_t, RedundancyMetric>::iterator it2 = (*it).second.begin(); it2 != (*it).second.end(); ++it2)
                    approxRedReadTmp += (*it2).second.bytes;
            }
        }
    }
    
    grandTotBytesRedLoad += redReadTmp;
    grandTotBytesApproxRedLoad += approxRedReadTmp;
    
    fprintf(gTraceFile, "\n#Redundant Read:");
    fprintf(gTraceFile, "\nTotalBytesLoad: %lu \n",grandTotBytesLoad);
    fprintf(gTraceFile, "\nRedundantBytesLoad: %lu %.2f%%\n",grandTotBytesRedLoad, grandTotBytesRedLoad * 100.0 / grandTotBytesLoad);
    fprintf(gTraceFile, "\nApproxRedundantBytesLoad: %lu %.2f%%\n",grandTotBytesApproxRedLoad, grandTotBytesApproxRedLoad * 100.0 / grandTotBytesLoad);
    
    // delete splay trees
    for(uint32_t i = 0; i < Func.size(); i++) splayDelete(&(Func[i].splayRoot));
}


static void InitThreadData(LoadSpyThreadData* tdata){
    tdata->bytesLoad = 0;
    tdata->sampleFlag = true;
    tdata->numIns = 0;
}


static VOID ThreadStart(THREADID threadId, CONTEXT* ctxt, INT32 flags, VOID* v) {
    LoadSpyThreadData* tdata = (LoadSpyThreadData*)memalign(32,sizeof(LoadSpyThreadData));
    InitThreadData(tdata);
    //    __sync_fetch_and_add(&gClientNumThreads, 1);
#ifdef MULTI_THREADED
    PIN_SetThreadData(client_tls_key, tdata, threadId);
#else
    gSingleThreadedTData = tdata;
#endif
}


#ifdef ENABLE_VISUALIZATION
// user-defined function for metric computation
// hpcviewer can only show the numbers for the metric
uint64_t computeMetricVal(void *metric) {
    if(!metric) return 0;
    return (uint64_t)metric;
}
#endif


// main for LoadSpy, initialize the tool, register instrumentation functions and call the target program.
int main(int argc, char* argv[]) {
    // Load hpcstrct file
    LoadHPCStructFile();
    
    // Initialize PIN
    if(PIN_Init(argc, argv))
        return Usage();
    
    // Initialize Symbols, we need them to report functions and lines
    PIN_InitSymbols();
    
    // Init Client
    ClientInit(argc, argv);
    // Intialize CCTLib
    PinCCTLibInit(INTERESTING_INS_ALL, gTraceFile, InstrumentInsCallback, 0, true);

#ifdef ENABLE_VISUALIZATION
    // Init hpcrun format output
    init_hpcrun_format(argc, argv, NULL, NULL, false);
    // Create new metrics
    redload_metric_id = hpcrun_create_metric("RED_LOAD");
    redload_approx_metric_id = hpcrun_create_metric("RED_LOAD_APPROX");
#endif

    // Obtain  a key for TLS storage.
    client_tls_key = PIN_CreateThreadDataKey(0 /* TODO have a destructir */);
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
