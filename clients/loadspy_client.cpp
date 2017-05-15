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
#include "pin.H"
#include "cctlib.H"
#include "shadow_memory.H"
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
#define MAX_SIMD_REGS (32)


#ifdef ENABLE_SAMPLING

#define WINDOW_ENABLE 1000000
#define WINDOW_DISABLE 100000000
#define WINDOW_CLEAN 10
#endif

#define DECODE_DEAD(data) static_cast<ContextHandle_t>(((data)  & 0xffffffffffffffff) >> 32 )
#define DECODE_KILL(data) (static_cast<ContextHandle_t>( (data)  & 0x00000000ffffffff))


#define MAKE_CONTEXT_PAIR(a, b) (((uint64_t)(a) << 32) | ((uint64_t)(b)))

#define delta 0.01


/***********************************************
 ******  shadow memory
 ************************************************/
ConcurrentShadowMemory<uint8_t, ContextHandle_t> sm;

#if 0
uint8_t** gL1PageTable[LEVEL_1_PAGE_TABLE_SIZE];


inline uint8_t* GetOrCreateShadowBaseAddress(uint64_t address) {
    // No entries at all ?
    uint8_t* shadowPage;
    uint8_t**  * l1Ptr = &gL1PageTable[LEVEL_1_PAGE_TABLE_SLOT(address)];
    
    if(*l1Ptr == 0) {
        *l1Ptr = (uint8_t**) calloc(1, LEVEL_2_PAGE_TABLE_SIZE);
        shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] = (uint8_t*) mmap(0, SHADOW_PAGE_SIZE * (1 + sizeof(uint32_t)), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    } else if((shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)]) == 0) {
        shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] = (uint8_t*) mmap(0, SHADOW_PAGE_SIZE * (1 + sizeof(uint32_t)), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
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
uint64_t grandTotBytesLoad;
uint64_t grandTotBytesRedLoad;
uint64_t grandTotBytesApproxRedLoad;

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
}


static const uint64_t READ_ACCESS_STATES [] = {/*0 byte */0, /*1 byte */ ONE_BYTE_READ_ACTION, /*2 byte */ TWO_BYTE_READ_ACTION, /*3 byte */ 0, /*4 byte */ FOUR_BYTE_READ_ACTION, /*5 byte */0, /*6 byte */0, /*7 byte */0, /*8 byte */ EIGHT_BYTE_READ_ACTION};
static const uint64_t WRITE_ACCESS_STATES [] = {/*0 byte */0, /*1 byte */ ONE_BYTE_WRITE_ACTION, /*2 byte */ TWO_BYTE_WRITE_ACTION, /*3 byte */ 0, /*4 byte */ FOUR_BYTE_WRITE_ACTION, /*5 byte */0, /*6 byte */0, /*7 byte */0, /*8 byte */ EIGHT_BYTE_WRITE_ACTION};
static const uint8_t OVERFLOW_CHECK [] = {/*0 byte */0, /*1 byte */ 0, /*2 byte */ 0, /*3 byte */ 1, /*4 byte */ 2, /*5 byte */3, /*6 byte */4, /*7 byte */5, /*8 byte */ 6};

static dense_hash_map<uint64_t, uint64_t> RedMap[THREAD_MAX];
static dense_hash_map<uint64_t, uint64_t> ApproxRedMap[THREAD_MAX];

static inline void AddToRedTable(uint64_t key,  uint16_t value, THREADID threadId) __attribute__((always_inline,flatten));
static inline void AddToRedTable(uint64_t key,  uint16_t value, THREADID threadId) {
#ifdef MULTI_THREADED
    LOCK_RED_MAP();
#endif
    dense_hash_map<uint64_t, uint64_t>::iterator it = RedMap[threadId].find(key);
    if ( it  == RedMap[threadId].end()) {
        RedMap[threadId][key] = value;
    } else {
        it->second += value;
    }
#ifdef MULTI_THREADED
    UNLOCK_RED_MAP();
#endif
}

static inline void AddToApproximateRedTable(uint64_t key,  uint16_t value, THREADID threadId) __attribute__((always_inline,flatten));
static inline void AddToApproximateRedTable(uint64_t key,  uint16_t value, THREADID threadId) {
#ifdef MULTI_THREADED
    LOCK_RED_MAP();
#endif
    dense_hash_map<uint64_t, uint64_t>::iterator it = ApproxRedMap[threadId].find(key);
    if ( it  == ApproxRedMap[threadId].end()) {
        ApproxRedMap[threadId][key] = value;
    } else {
        it->second += value;
    }
#ifdef MULTI_THREADED
    UNLOCK_RED_MAP();
#endif
}


#ifdef ENABLE_SAMPLING

static ADDRINT IfEnableSample(THREADID threadId){
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    return tData->sampleFlag;
}

#endif


static inline bool IsFloatInstruction(ADDRINT ip) {
    xed_decoded_inst_t  xedd;
    xed_state_t  xed_state;
    xed_decoded_inst_zero_set_mode(&xedd, &xed_state);
    
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
                        return true;
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
                return true;
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

static inline bool IsFloatInstructionOld(ADDRINT ip) {
    xed_decoded_inst_t  xedd;
    xed_state_t  xed_state;
    xed_decoded_inst_zero_set_mode(&xedd, &xed_state);
    
    if(XED_ERROR_NONE == xed_decode(&xedd, (const xed_uint8_t*)(ip), 15)) {
        xed_iclass_enum_t iclassType = xed_decoded_inst_get_iclass(&xedd);
        if (iclassType >= XED_ICLASS_F2XM1 && iclassType <=XED_ICLASS_FYL2XP1) {
            return true;
        }
        if (iclassType >= XED_ICLASS_VBROADCASTSD && iclassType <= XED_ICLASS_VDPPS) {
            return true;
        }
        if (iclassType >= XED_ICLASS_VRCPPS && iclassType <= XED_ICLASS_VSQRTSS) {
            return true;
        }
        if (iclassType >= XED_ICLASS_VSUBPD && iclassType <= XED_ICLASS_VXORPS) {
            return true;
        }
        switch (iclassType) {
            case XED_ICLASS_ADDPD:
            case XED_ICLASS_ADDPS:
            case XED_ICLASS_ADDSD:
            case XED_ICLASS_ADDSS:
            case XED_ICLASS_ADDSUBPD:
            case XED_ICLASS_ADDSUBPS:
            case XED_ICLASS_ANDNPD:
            case XED_ICLASS_ANDNPS:
            case XED_ICLASS_ANDPD:
            case XED_ICLASS_ANDPS:
            case XED_ICLASS_BLENDPD:
            case XED_ICLASS_BLENDPS:
            case XED_ICLASS_BLENDVPD:
            case XED_ICLASS_BLENDVPS:
            case XED_ICLASS_CMPPD:
            case XED_ICLASS_CMPPS:
            case XED_ICLASS_CMPSD:
            case XED_ICLASS_CMPSD_XMM:
            case XED_ICLASS_COMISD:
            case XED_ICLASS_COMISS:
            case XED_ICLASS_CVTDQ2PD:
            case XED_ICLASS_CVTDQ2PS:
            case XED_ICLASS_CVTPD2PS:
            case XED_ICLASS_CVTPI2PD:
            case XED_ICLASS_CVTPI2PS:
            case XED_ICLASS_CVTPS2PD:
            case XED_ICLASS_CVTSD2SS:
            case XED_ICLASS_CVTSI2SD:
            case XED_ICLASS_CVTSI2SS:
            case XED_ICLASS_CVTSS2SD:
            case XED_ICLASS_DIVPD:
            case XED_ICLASS_DIVPS:
            case XED_ICLASS_DIVSD:
            case XED_ICLASS_DIVSS:
            case XED_ICLASS_DPPD:
            case XED_ICLASS_DPPS:
            case XED_ICLASS_HADDPD:
            case XED_ICLASS_HADDPS:
            case XED_ICLASS_HSUBPD:
            case XED_ICLASS_HSUBPS:
            case XED_ICLASS_MAXPD:
            case XED_ICLASS_MAXPS:
            case XED_ICLASS_MAXSD:
            case XED_ICLASS_MAXSS:
            case XED_ICLASS_MINPD:
            case XED_ICLASS_MINPS:
            case XED_ICLASS_MINSD:
            case XED_ICLASS_MINSS:
            case XED_ICLASS_MOVAPD:
            case XED_ICLASS_MOVAPS:
            case XED_ICLASS_MOVD:
            case XED_ICLASS_MOVHLPS:
            case XED_ICLASS_MOVHPD:
            case XED_ICLASS_MOVHPS:
            case XED_ICLASS_MOVLHPS:
            case XED_ICLASS_MOVLPD:
            case XED_ICLASS_MOVLPS:
            case XED_ICLASS_MOVMSKPD:
            case XED_ICLASS_MOVMSKPS:
            case XED_ICLASS_MOVNTPD:
            case XED_ICLASS_MOVNTPS:
            case XED_ICLASS_MOVNTSD:
            case XED_ICLASS_MOVNTSS:
            case XED_ICLASS_MOVSD:
            case XED_ICLASS_MOVSD_XMM:
            case XED_ICLASS_MOVSS:
            case XED_ICLASS_MULPD:
            case XED_ICLASS_MULPS:
            case XED_ICLASS_MULSD:
            case XED_ICLASS_MULSS:
            case XED_ICLASS_ORPD:
            case XED_ICLASS_ORPS:
            case XED_ICLASS_ROUNDPD:
            case XED_ICLASS_ROUNDPS:
            case XED_ICLASS_ROUNDSD:
            case XED_ICLASS_ROUNDSS:
            case XED_ICLASS_SHUFPD:
            case XED_ICLASS_SHUFPS:
            case XED_ICLASS_SQRTPD:
            case XED_ICLASS_SQRTPS:
            case XED_ICLASS_SQRTSD:
            case XED_ICLASS_SQRTSS:
            case XED_ICLASS_SUBPD:
            case XED_ICLASS_SUBPS:
            case XED_ICLASS_SUBSD:
            case XED_ICLASS_SUBSS:
            case XED_ICLASS_VADDPD:
            case XED_ICLASS_VADDPS:
            case XED_ICLASS_VADDSD:
            case XED_ICLASS_VADDSS:
            case XED_ICLASS_VADDSUBPD:
            case XED_ICLASS_VADDSUBPS:
            case XED_ICLASS_VANDNPD:
            case XED_ICLASS_VANDNPS:
            case XED_ICLASS_VANDPD:
            case XED_ICLASS_VANDPS:
            case XED_ICLASS_VBLENDPD:
            case XED_ICLASS_VBLENDPS:
            case XED_ICLASS_VBLENDVPD:
            case XED_ICLASS_VBLENDVPS:
            case XED_ICLASS_VBROADCASTSD:
            case XED_ICLASS_VBROADCASTSS:
            case XED_ICLASS_VCMPPD:
            case XED_ICLASS_VCMPPS:
            case XED_ICLASS_VCMPSD:
            case XED_ICLASS_VCMPSS:
            case XED_ICLASS_VCOMISD:
            case XED_ICLASS_VCOMISS:
            case XED_ICLASS_VCVTDQ2PD:
            case XED_ICLASS_VCVTDQ2PS:
            case XED_ICLASS_VCVTPD2PS:
            case XED_ICLASS_VCVTPH2PS:
            case XED_ICLASS_VCVTPS2PD:
            case XED_ICLASS_VCVTSD2SS:
            case XED_ICLASS_VCVTSI2SD:
            case XED_ICLASS_VCVTSI2SS:
            case XED_ICLASS_VCVTSS2SD:
            case XED_ICLASS_VDIVPD:
            case XED_ICLASS_VDIVPS:
            case XED_ICLASS_VDIVSD:
            case XED_ICLASS_VDIVSS:
            case XED_ICLASS_VDPPD:
            case XED_ICLASS_VDPPS:
            case XED_ICLASS_VMASKMOVPD:
            case XED_ICLASS_VMASKMOVPS:
            case XED_ICLASS_VMAXPD:
            case XED_ICLASS_VMAXPS:
            case XED_ICLASS_VMAXSD:
            case XED_ICLASS_VMAXSS:
            case XED_ICLASS_VMINPD:
            case XED_ICLASS_VMINPS:
            case XED_ICLASS_VMINSD:
            case XED_ICLASS_VMINSS:
            case XED_ICLASS_VMOVAPD:
            case XED_ICLASS_VMOVAPS:
            case XED_ICLASS_VMOVD:
            case XED_ICLASS_VMOVHLPS:
            case XED_ICLASS_VMOVHPD:
            case XED_ICLASS_VMOVHPS:
            case XED_ICLASS_VMOVLHPS:
            case XED_ICLASS_VMOVLPD:
            case XED_ICLASS_VMOVLPS:
            case XED_ICLASS_VMOVMSKPD:
            case XED_ICLASS_VMOVMSKPS:
            case XED_ICLASS_VMOVNTPD:
            case XED_ICLASS_VMOVNTPS:
            case XED_ICLASS_VMOVSD:
            case XED_ICLASS_VMOVSS:
            case XED_ICLASS_VMOVUPD:
            case XED_ICLASS_VMOVUPS:
            case XED_ICLASS_VMULPD:
            case XED_ICLASS_VMULPS:
            case XED_ICLASS_VMULSD:
            case XED_ICLASS_VMULSS:
            case XED_ICLASS_VORPD:
            case XED_ICLASS_VORPS:
            case XED_ICLASS_VPABSD:
            case XED_ICLASS_VPADDD:
            case XED_ICLASS_VPCOMD:
            case XED_ICLASS_VPCOMUD:
            case XED_ICLASS_VPERMILPD:
            case XED_ICLASS_VPERMILPS:
            case XED_ICLASS_VPERMPD:
            case XED_ICLASS_VPERMPS:
            case XED_ICLASS_VPGATHERDD:
            case XED_ICLASS_VPGATHERQD:
            case XED_ICLASS_VPHADDBD:
            case XED_ICLASS_VPHADDD:
            case XED_ICLASS_VPHADDUBD:
            case XED_ICLASS_VPHADDUWD:
            case XED_ICLASS_VPHADDWD:
            case XED_ICLASS_VPHSUBD:
            case XED_ICLASS_VPHSUBWD:
            case XED_ICLASS_VPINSRD:
            case XED_ICLASS_VPMACSDD:
            case XED_ICLASS_VPMACSSDD:
            case XED_ICLASS_VPMASKMOVD:
            case XED_ICLASS_VPMAXSD:
            case XED_ICLASS_VPMAXUD:
            case XED_ICLASS_VPMINSD:
            case XED_ICLASS_VPMINUD:
            case XED_ICLASS_VPROTD:
            case XED_ICLASS_VPSUBD:
            case XED_ICLASS_XORPD:
            case XED_ICLASS_XORPS:
                return true;
                
            default: return false;
        }
    } else {
        assert(0 && "failed to disassemble instruction");
        return false;
    }
}
/*
 static inline bool IsFloatInstruction(ADDRINT ip, uint32_t oper) {
 xed_decoded_inst_t  xedd;
 xed_state_t  xed_state;
 xed_decoded_inst_zero_set_mode(&xedd, &xed_state);
 
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
    xed_state_t  xed_state;
    xed_decoded_inst_zero_set_mode(&xedd, &xed_state);
    
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
    static __attribute__((always_inline)) void Body(function<void (const int)> func){
        func(start); // Real loop body
        UnrolledLoop<start+incr, end, incr, conditional, approx>:: Body(func);   // unroll next iteration
    }
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
        tuple<uint8_t[SHADOW_PAGE_SIZE], ContextHandle_t[SHADOW_PAGE_SIZE]> &t = sm.GetOrCreateShadowBaseAddress((uint64_t)addr+start);
        ContextHandle_t * prevIP = &(get<1>(t)[PAGE_OFFSET(((uint64_t)addr+start))]);
        
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


template<class T, uint32_t AccessLen, bool isApprox>
struct RedSpyAnalysis{
    static __attribute__((always_inline)) bool IsReadRedundant(void * addr, uint8_t * prev){
        
        if(isApprox){
            if(AccessLen>=32){
                if(sizeof(T) == 4){
                    __m256 oldValue = _mm256_loadu_ps( reinterpret_cast<const float*> (prev));
                    __m256 newValue = _mm256_loadu_ps( reinterpret_cast<const float*> (addr));
                    
                    __m256 result = _mm256_sub_ps(newValue,oldValue);
                    
                    result = _mm256_div_ps(result,oldValue);
                    float rates[8] __attribute__((aligned(32)));
                    _mm256_store_ps(rates,result);
                    
                    _mm256_storeu_ps(reinterpret_cast<float*> (prev), newValue);
                    
                    for(int i = 0; i < 8; ++i){
                        if(rates[i] < -delta || rates[i] > delta) {
                            return false;
                        }
                    }
                    return true;
                    
                }else if(sizeof(T) == 8){
                    __m256d oldValue = _mm256_loadu_pd( reinterpret_cast<const double*> (prev));
                    __m256d newValue = _mm256_loadu_pd( reinterpret_cast<const double*> (addr));
                    
                    __m256d result = _mm256_sub_pd(newValue,oldValue);
                    
                    result = _mm256_div_pd(result,oldValue);
                    
                    double rates[4] __attribute__((aligned(32)));
                    _mm256_store_pd(rates,result);
                    
                    _mm256_storeu_pd(reinterpret_cast<double*> (prev), newValue);
                    
                    for(int i = 0; i < 4; ++i){
                        if(rates[i] < -delta || rates[i] > delta) {
                            return false;
                        }
                    }
                    return true;
                }
            }else if(AccessLen == 16){
                if(sizeof(T) == 4){
                    __m128 oldValue = _mm_loadu_ps( reinterpret_cast<const float*> (prev));
                    __m128 newValue = _mm_loadu_ps( reinterpret_cast<const float*> (addr));
                    
                    __m128 result = _mm_sub_ps(newValue,oldValue);
                    
                    result = _mm_div_ps(result,oldValue);
                    float rates[4] __attribute__((aligned(16)));
                    _mm_store_ps(rates,result);
                    
                    _mm_storeu_ps(reinterpret_cast<float*> (prev), newValue);
                    
                    for(int i = 0; i < 4; ++i){
                        if(rates[i] < -delta || rates[i] > delta) {
                            return false;
                        }
                    }
                    return true;
                    
                }else if(sizeof(T) == 8){
                    __m128d oldValue = _mm_loadu_pd( reinterpret_cast<const double*> (prev));
                    __m128d newValue = _mm_loadu_pd( reinterpret_cast<const double*> (addr));
                    
                    __m128d result = _mm_sub_pd(newValue,oldValue);
                    
                    result = _mm_div_pd(result,oldValue);
                    
                    double rate[2];
                    _mm_storel_pd(&rate[0],result);
                    _mm_storeh_pd(&rate[1],result);
                    
                    _mm_storeu_pd(reinterpret_cast<double*> (prev), newValue);
                    
                    if(rate[0] < -delta || rate[0] > delta)
                        return false;
                    if(rate[1] < -delta || rate[1] > delta)
                        return false;
                    return true;
                }
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
                T newValue = *(static_cast<T*>(addr));
                T oldValue = *((T*)(prev));
                
                *((T*)(prev)) = *(static_cast<T*>(addr));
                
                T rate = (newValue - oldValue)/oldValue;
                if( rate <= delta && rate >= -delta ) return true;
                else return false;
            }
        }else{
            bool isRed = (*((T*)(prev)) == *(static_cast<T*>(addr)));
            *((T*)(prev)) = *(static_cast<T*>(addr));
            return isRed;
        }
        return false;
    }
    
    static __attribute__((always_inline)) VOID CheckNByteValueAfterRead(void* addr, uint32_t opaqueHandle, THREADID threadId){
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        
        ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
        tuple<uint8_t[SHADOW_PAGE_SIZE], ContextHandle_t[SHADOW_PAGE_SIZE]> &t = sm.GetOrCreateShadowBaseAddress((uint64_t)addr);
        ContextHandle_t * __restrict__ prevIP = &(get<1>(t)[PAGE_OFFSET((uint64_t)addr)]);
        uint8_t* prevValue = &(get<0>(t)[PAGE_OFFSET((uint64_t)addr)]);
        
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
    
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
    
    tuple<uint8_t[SHADOW_PAGE_SIZE], ContextHandle_t[SHADOW_PAGE_SIZE]> &t = sm.GetOrCreateShadowBaseAddress((uint64_t)addr);
    ContextHandle_t * __restrict__ prevIP = &(get<1>(t)[PAGE_OFFSET((uint64_t)addr)]);
    uint8_t* prevValue = &(get<0>(t)[PAGE_OFFSET((uint64_t)addr)]);
    
    // This assumes that a large read cannot straddle a page boundary -- strong assumption, but lets go with it for now.
    tuple<uint8_t[SHADOW_PAGE_SIZE], ContextHandle_t[SHADOW_PAGE_SIZE]> &tt = sm.GetOrCreateShadowBaseAddress((uint64_t)addr);
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
            prevIP[0] = curCtxtHandle;
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
        
        if (IsFloatInstruction(INS_Address(ins))) {
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
    if( INS_IsFarJump(ins) || INS_IsDirectFarJump(ins) || INS_IsMaskedJump(ins))
        return true;
    else if(INS_IsRet(ins) || INS_IsIRet(ins))
        return true;
    else if(INS_IsCall(ins) || INS_IsSyscall(ins))
        return true;
    else if(INS_IsBranch(ins) || INS_IsRDTSC(ins) || INS_IsNop(ins))
        return true;
    return false;
}

static VOID InstrumentInsCallback(INS ins, VOID* v, const uint32_t opaqueHandle) {
    if (!INS_HasFallThrough(ins)) return;
    if (INS_IsIgnorable(ins))return;
    if (INS_IsBranchOrCall(ins) || INS_IsRet(ins)) return;
    
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
            if (INS_IsBranchOrCall(ins) || INS_IsRet(ins)) continue;
            
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
            if (INS_IsBranchOrCall(ins) || INS_IsRet(ins)) continue;
            
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
    vector<RedundacyData>::iterator tmpIt;
    
    uint64_t grandTotalRedundantBytes = 0;
    fprintf(gTraceFile, "*************** Dump Data from Thread %d ****************\n", threadId);
    
#ifdef MERGING
    for (dense_hash_map<uint64_t, uint64_t>::iterator it = RedMap[threadId].begin(); it != RedMap[threadId].end(); ++it) {
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
    for (dense_hash_map<uint64_t, uint64_t>::iterator it = RedMap[threadId].begin(); it != RedMap[threadId].end(); ++it) {
        RedundacyData tmp = { DECODE_DEAD ((*it).first), DECODE_KILL((*it).first), (*it).second};
        tmpList.push_back(tmp);
        grandTotalRedundantBytes += tmp.frequency;
    }
#endif
    
    __sync_fetch_and_add(&grandTotBytesRedLoad,grandTotalRedundantBytes);
    
    fprintf(gTraceFile, "\n Total redundant bytes = %f %%\n", grandTotalRedundantBytes * 100.0 / ClientGetTLS(threadId)->bytesLoad);
    
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
    vector<RedundacyData>::iterator tmpIt;
    
    uint64_t grandTotalRedundantBytes = 0;
    fprintf(gTraceFile, "*************** Dump Data(delta=%.2f%%) from Thread %d ****************\n", delta*100,threadId);
    
#ifdef MERGING
    for (dense_hash_map<uint64_t, uint64_t>::iterator it = ApproxRedMap[threadId].begin(); it != ApproxRedMap[threadId].end(); ++it) {
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
    for (dense_hash_map<uint64_t, uint64_t>::iterator it = ApproxRedMap[threadId].begin(); it != ApproxRedMap[threadId].end(); ++it) {
        RedundacyData tmp = { DECODE_DEAD ((*it).first), DECODE_KILL((*it).first), (*it).second};
        tmpList.push_back(tmp);
        grandTotalRedundantBytes += tmp.frequency;
    }
#endif
    
    __sync_fetch_and_add(&grandTotBytesApproxRedLoad,grandTotalRedundantBytes);
    
    fprintf(gTraceFile, "\n Total redundant bytes = %f %%\n", grandTotalRedundantBytes * 100.0 / ClientGetTLS(threadId)->bytesLoad);
    
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
    vector<RedundacyData>::iterator tmpIt;
    
    for (dense_hash_map<uint64_t, uint64_t>::iterator it = RedMap[threadId].begin(); it != RedMap[threadId].end(); ++it) {
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
    newCCT_hpcrun_selection_write(threadId);
}

// On each Unload of a loaded image, the accummulated redundancy information is dumped
static VOID ImageUnload(IMG img, VOID* v) {
    fprintf(gTraceFile, "\n TODO .. Multi-threading is not well supported.");
    THREADID  threadid =  PIN_ThreadId();
    fprintf(gTraceFile, "\nUnloading %s", IMG_Name(img).c_str());
    if (RedMap[threadid].empty() && ApproxRedMap[threadid].empty()) return;
    // Update gTotalInstCount first
    PIN_LockClient();
    PrintRedundancyPairs(threadid);
    PrintApproximationRedundancyPairs(threadid);
    PIN_UnlockClient();
    // clear redmap now
    RedMap[threadid].clear();
    ApproxRedMap[threadid].clear();
}

static VOID ThreadFiniFunc(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v) {
    
    __sync_fetch_and_add(&grandTotBytesLoad, ClientGetTLS(threadid)->bytesLoad);
    
    // output the CCT for hpcviewer format
    HPCRunRedundancyPairs(threadid);
}

static VOID FiniFunc(INT32 code, VOID *v) {
    // do whatever you want to the full CCT with footpirnt
    uint64_t redReadTmp = 0;
    uint64_t approxRedReadTmp = 0;
    for(int i = 0; i < THREAD_MAX; ++i){
        dense_hash_map<uint64_t, uint64_t>::iterator it;
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
    fprintf(gTraceFile, "\nTotalBytesLoad: %lu \n",grandTotBytesLoad);
    fprintf(gTraceFile, "\nRedundantBytesLoad: %lu %.2f\n",grandTotBytesRedLoad, grandTotBytesRedLoad * 100.0/grandTotBytesLoad);
    fprintf(gTraceFile, "\nApproxRedundantBytesLoad: %lu %.2f\n",grandTotBytesApproxRedLoad, grandTotBytesApproxRedLoad * 100.0/grandTotBytesLoad);
}

static void InitThreadData(RedSpyThreadData* tdata){
    tdata->bytesLoad = 0;
    tdata->sampleFlag = true;
    tdata->numIns = 0;
    for (int i = 0; i < THREAD_MAX; ++i) {
        RedMap[i].set_empty_key(0);
        ApproxRedMap[i].set_empty_key(0);
    }
}

static VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    RedSpyThreadData* tdata = (RedSpyThreadData*)memalign(32,sizeof(RedSpyThreadData));
    InitThreadData(tdata);
    //    __sync_fetch_and_add(&gClientNumThreads, 1);
#ifdef MULTI_THREADED
    PIN_SetThreadData(client_tls_key, tdata, threadid);
#else
    gSingleThreadedTData = tdata;
#endif
}

// user-defined function for metric merging
void mergeFunc(void *des, void *src)
{
#if 0
    uint64_t *m = (uint64_t *)des;
    uint64_t *n = (uint64_t *)src;
    *m += *n;
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
    PinCCTLibInit(INTERESTING_INS_ALL, gTraceFile, InstrumentInsCallback, 0);
    
    // Init hpcrun format output
    init_hpcrun_format(argc, argv, mergeFunc, computeMetricVal, true);
    redload_metric_id = hpcrun_create_metric("RED_LOAD");
    
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


