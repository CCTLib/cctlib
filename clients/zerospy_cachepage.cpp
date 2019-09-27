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

/***********************************************
 ******  shadow memory
 ************************************************/
//ConcurrentShadowMemory<uint8_t, ContextHandle_t> sm;

struct{
    char dummy1[128];
    xed_state_t  xedState;
    char dummy2[128];
} LoadSpyGlobals;

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

//uint64_t localTotBytesLoad[THREAD_MAX] = {0};

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
    char name[MAX_FILE_PATH] = "zeroLoad.cachepage.out.";
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


static const uint64_t READ_ACCESS_STATES [] = {/*0 byte */0, /*1 byte */ ONE_BYTE_READ_ACTION, /*2 byte */ TWO_BYTE_READ_ACTION, /*3 byte */ 0, /*4 byte */ FOUR_BYTE_READ_ACTION, /*5 byte */0, /*6 byte */0, /*7 byte */0, /*8 byte */ EIGHT_BYTE_READ_ACTION};
static const uint64_t WRITE_ACCESS_STATES [] = {/*0 byte */0, /*1 byte */ ONE_BYTE_WRITE_ACTION, /*2 byte */ TWO_BYTE_WRITE_ACTION, /*3 byte */ 0, /*4 byte */ FOUR_BYTE_WRITE_ACTION, /*5 byte */0, /*6 byte */0, /*7 byte */0, /*8 byte */ EIGHT_BYTE_WRITE_ACTION};
static const uint8_t OVERFLOW_CHECK [] = {/*0 byte */0, /*1 byte */ 0, /*2 byte */ 0, /*3 byte */ 1, /*4 byte */ 2, /*5 byte */3, /*6 byte */4, /*7 byte */5, /*8 byte */ 6};
// 64 Byte Cache line
#define CACHELINE_ALIGNMENT 64
// 4 KB Page
#define PAGE_ALIGNMENT 0x1000
// masks
#define CACHELINE_MASK (~63)
#define PAGE_MASK (~0xfff)
#define ISSAMECACHELINE(addr, accesslen) (((uint64_t)(addr)&(CACHELINE_ALIGNMENT-1))+(uint64_t)(accesslen)<CACHELINE_ALIGNMENT)
// index
#define GET_CACHELINE_INDEX(x) ((x) & CACHELINE_MASK)
#define GET_PAGE_INDEX(x) ((x) & PAGE_MASK)
// inside index
#define GET_CACHELINE_INNER_INDEX(x) ((x) & (CACHELINE_ALIGNMENT-1))
#define GET_PAGE_INNER_INDEX(x) ((x) & (PAGE_ALIGNMENT-1))
// states
#define STATE_NONZERO 0
#define STATE_ZERO 1
#define STATE_NOVISIT 2
#define VAL2STAT(value) (value==0)

// only log for CACHELINE, for page info can be derived from cache line info
struct RedLogs{
    uint64_t zerobytes; // total zero bytes (Byte level)
    uint64_t zeroreads; // total zero reads (Instruction level)
    uint64_t reads; // total reads (Instruction level)
    uint8_t state; // STATE_ZERO, STATE_NONZERO, STATE_NOVISIT
};

//static unordered_map<uint64_t, uint64_t> validMap[THREAD_MAX];
static unordered_map<uint64_t, RedLogs> RedMap[THREAD_MAX];
static inline void AddToRedTable(uint64_t key, uint16_t value, uint16_t zero, THREADID threadId) __attribute__((always_inline,flatten));
static inline void AddToRedTable(uint64_t key, uint16_t value, uint16_t zero, THREADID threadId) {
#ifdef MULTI_THREADED
    LOCK_RED_MAP();
#endif
    unordered_map<uint64_t, RedLogs>::iterator it = RedMap[threadId].find(key);
    if ( it  == RedMap[threadId].end()) {
        RedLogs log;
        log.zerobytes = value;
        log.zeroreads = zero;
        log.reads = 1;
        log.state = zero;
        RedMap[threadId][key] = log;
    } else {
        it->second.zerobytes += value;
        it->second.zeroreads += zero;
        it->second.reads ++;
        it->second.state &= zero;
    }
#ifdef MULTI_THREADED
    UNLOCK_RED_MAP();
#endif
}

// Certain FP instructions should not be approximated
static inline bool IsOkToApproximate(xed_decoded_inst_t & xedd) {
     xed_category_enum_t cat = xed_decoded_inst_get_category(&xedd);
     xed_iclass_enum_t 	iclass = xed_decoded_inst_get_iclass (&xedd);
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

static inline bool IsFloatInstructionOld(ADDRINT ip) {
    xed_decoded_inst_t  xedd;
    xed_decoded_inst_zero_set_mode(&xedd, &LoadSpyGlobals.xedState);
    
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

template<int start, int end, int step>
struct UnrolledCount{
    static __attribute__((always_inline)) uint32_t BodyRedZero(uint8_t* addr){
        return ((addr[end-1]==0) + UnrolledCount<start, end-1, step>:: BodyRedZero(addr));
    }
};
template<int end, int step>
struct UnrolledCount<end, end, step>{
    static __attribute__((always_inline)) uint32_t BodyRedZero(uint8_t* addr){
        return 0;
    }
};

template<class T, uint32_t AccessLen, bool isApprox>
struct ZeroSpyAnalysis{
    static __attribute__((always_inline)) VOID CheckNByteValueAfterRead(void* addr, uint32_t opaqueHandle, THREADID threadId){
#ifdef DEBUG_ZEROSPY
        printf("\nINFO : In Check NBytes Value After Read\n");
#endif
        uint8_t* bytes = static_cast<uint8_t*>(addr);
        if(ISSAMECACHELINE(addr, AccessLen)) {
            uint32_t rednum = UnrolledCount<0,AccessLen,sizeof(T)>::BodyRedZero(bytes);
            if(rednum) {
                uint8_t zero = (rednum==AccessLen);
                AddToRedTable(GET_CACHELINE_INDEX((uint64_t)addr),rednum,zero,threadId);
            } else {
                AddToRedTable(GET_CACHELINE_INDEX((uint64_t)addr),0,0,threadId);
            }
        } else {
            uint8_t i;
            uint8_t zero = bytes[0]==0;
            uint32_t rednum = zero;
            for(i=1;ISSAMECACHELINE(addr, i);++i) {
                zero &= bytes[i]==0;
                rednum += zero;
            }
            AddToRedTable(GET_CACHELINE_INDEX((uint64_t)addr),rednum,zero,threadId);
            uint64_t key = GET_CACHELINE_INDEX((uint64_t)(bytes+i));
            zero = bytes[i]==0;
            rednum = zero;
            for(i=i+1;i<AccessLen;++i) {
                zero &= bytes[i]==0;
                rednum += zero;
            }
            AddToRedTable(key,rednum,zero,threadId);
        }

#ifdef DEBUG_ZEROSPY
        printf("\nINFO : Exit Check NBytes Value After Read\n");
#endif
    }
};

static inline VOID CheckAfterLargeRead(void* addr, UINT32 accessLen, uint32_t opaqueHandle, THREADID threadId){
#ifdef DEBUG_ZEROSPY
    printf("\nINFO : In Check After Large Read\n");
    if(accessLen > 32) {
        printf("ERROR : AccessLen too large : %d\n",accessLen);
        assert(0 && (accessLen <= 32));
    }
#endif
    uint8_t* bytes = static_cast<uint8_t*>(addr);
    uint8_t i;
    uint8_t zero = bytes[0]==0;
    uint32_t rednum = zero;
    for(i=1;ISSAMECACHELINE(addr, i);++i) {
        zero &= bytes[i]==0;
        rednum += zero;
    }
    AddToRedTable(GET_CACHELINE_INDEX((uint64_t)addr),rednum,zero,threadId);
    uint64_t key = GET_CACHELINE_INDEX((uint64_t)(bytes+i));
    zero = bytes[i]==0;
    rednum = zero;
    for(i=i+1;i<accessLen;++i) {
        zero &= bytes[i]==0;
        rednum += zero;
    }
    AddToRedTable(key,rednum,zero,threadId);
#ifdef DEBUG_ZEROSPY
    printf("\nINFO : Exit Check After Large Read\n");
#endif
}

#ifdef ENABLE_SAMPLING

#define HANDLE_CASE(T, ACCESS_LEN, IS_APPROX) \
INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)IfEnableSample, IARG_THREAD_ID,IARG_END);\
INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) ZeroSpyAnalysis<T, (ACCESS_LEN), (IS_APPROX)>::CheckNByteValueAfterRead, IARG_MEMORYOP_EA, memOp, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_INST_PTR,IARG_END)

#define HANDLE_LARGE() \
INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)IfEnableSample, IARG_THREAD_ID,IARG_END);\
INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) CheckAfterLargeRead, IARG_MEMORYOP_EA, memOp, IARG_MEMORYREAD_SIZE, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_END)
#else

#define HANDLE_CASE(T, ACCESS_LEN, IS_APPROX) \
INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) ZeroSpyAnalysis<T, (ACCESS_LEN), (IS_APPROX)>::CheckNByteValueAfterRead, IARG_MEMORYOP_EA, memOp, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_INST_PTR,IARG_END)

// #define HANDLE_CASE_LOWER(T, LOWERT, ACCESS_LEN) 
// INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) ZeroSpyApproxAnalysis<T, LOWERT, (ACCESS_LEN)>::CheckNByteValueAfterRead, IARG_MEMORYOP_EA, memOp, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_INST_PTR,IARG_END)

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
#ifdef DEBUG_ZEROSPY
        printf("\nINFO : In InstrumentReadValueBeforeAndAfterLoading\n");
#endif
        UINT32 refSize = INS_MemoryOperandSize(ins, memOp);
        
        if (IsFloatInstructionAndOkToApproximate(INS_Address(ins))) {
            unsigned int operSize = FloatOperandSize(INS_Address(ins),INS_MemoryOperandIndexToOperandIndex(ins,memOp));
            switch(refSize) {
                case 1:
                case 2: assert(0 && "memory read floating data with unexptected small size");
                case 4: HANDLE_CASE(float, 4, true); break;
                case 8: HANDLE_CASE(double, 8, true); break;
                // case 8: HANDLE_CASE_LOWER(double, float, 8); break;
                case 10: HANDLE_CASE(uint8_t, 10, true); break;
                case 16: {
                    switch (operSize) {
                        case 4: HANDLE_CASE(float, 16, true); break;
                        case 8: HANDLE_CASE(double, 16, true); break;
                        // case 8: HANDLE_CASE_LOWER(double, float, 16); break;
                        default: assert(0 && "handle large mem read with unexpected operand size\n"); break;
                    }
                }break;
                case 32: {
                    switch (operSize) {
                        case 4: HANDLE_CASE(float, 32, true); break;
                        case 8: HANDLE_CASE(double, 32, true); break;
                        // case 8: HANDLE_CASE_LOWER(double, float, 32); break;
                        default: assert(0 && "handle large mem read with unexpected operand size\n"); break;
                    }
                }break;
                default: assert(0 && "unexpected large memory read\n"); break;
            }
        }else{
            switch(refSize) {
#ifdef SKIP_SMALLCASE
                // do nothing when access is small
                case 1: break;
                case 2: break;
#else
                case 1: HANDLE_CASE(uint8_t, 1, false); break;
                case 2: HANDLE_CASE(uint16_t, 2, false); break;
#endif
                case 4: HANDLE_CASE(uint32_t, 4, false); break;
                case 8: HANDLE_CASE(uint64_t, 8, false); break;
                    
                default: {
                    HANDLE_LARGE();
                }
            }
        }
#ifdef DEBUG_ZEROSPY
        printf("\nINFO : Exit InstrumentReadValueBeforeAndAfterLoading\n");
#endif
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
    else if(INS_IsPrefetch(ins)) // Prefetch instructions might access addresses which are invalid.
        return true;
    // XSAVEC and XRSTOR are problematic since its access length is variable. 
    // Execution of XSAVEC is similar to that of XSAVE. XSAVEC differs from XSAVE in that it uses compaction and that it may use the init optimization.
    // It fails with "Cannot use IARG_MEMORYWRITE_SIZE on non-standard memory access of instruction at 0xfoo: xsavec ptr [rsp]" error.
    // A correct solution should use INS_hasKnownMemorySize() which is not available in Pin 2.14.
    if(INS_Mnemonic(ins) == "XSAVEC")
        return true;
    if(INS_Mnemonic(ins) == "XSAVE")
        return true;
    if(INS_Mnemonic(ins) == "XRSTOR")
         return true;
    return false;
}

static VOID InstrumentInsCallback(INS ins, VOID* v, const uint32_t opaqueHandle) {
#ifdef DEBUG_ZEROSPY
    printf("\nINFO : In InstrumentInsCallback\n");
    if (!INS_HasFallThrough(ins)) {printf("\nINFO : Exit InstrumentInsCallback !INS_HasFallThrough\n");return;}
    if (INS_IsIgnorable(ins)){printf("\nINFO : Exit InstrumentInsCallback INS_IsIgnorable\n");return;}
    if (INS_IsBranchOrCall(ins) || INS_IsRet(ins)) {printf("\nINFO : Exit InstrumentInsCallback INS_IsBranchOrCall(ins) || INS_IsRet(ins)\n");return;}
#else
    if (!INS_HasFallThrough(ins)) return;
    if (INS_IsIgnorable(ins))return;
    if (INS_IsBranchOrCall(ins) || INS_IsRet(ins)) return;
#endif
    
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
#ifdef DEBUG_ZEROSPY
    printf("\nINFO : Exit InstrumentInsCallback\n");
#endif
}

inline VOID Update(uint32_t bytes, THREADID threadId){
#ifdef DEBUG_ZEROSPY
    printf("\nINFO : In Update\n");
#endif
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    tData->bytesLoad += bytes;
#ifdef DEBUG_ZEROSPY
    printf("\nINFO : Exit Update\n");
#endif
}

//instrument the trace, count the number of ins in the trace, decide to instrument or not
static void InstrumentTrace(TRACE trace, void* f) {
#ifdef DEBUG_ZEROSPY
    printf("\nINFO : In InstrumentTrace\n");
#endif
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
#ifdef DEBUG_ZEROSPY
    printf("\nINFO : Exit InstrumentTrace\n");
#endif
}

struct DRedData {
    uint64_t index;
    uint64_t frequency;
    uint64_t all0freq;
    uint64_t ltot;
    uint8_t state;
};

static inline bool DRedundacyCompare(const struct DRedData &first, const struct DRedData &second) {
    return first.frequency > second.frequency ? true : false;
}

#define LEVEL_1_RED_THRESHOLD 0.90
#define LEVEL_2_RED_THRESHOLD 0.70
#define LEVEL_3_RED_THRESHOLD 0.50
#define PRINT_ALL_PAGE_INFO

static void PrintPageRedundancy(THREADID threadId) {
    vector<DRedData> tmpList;
    vector<DRedData>::iterator tmpIt;
    unordered_map<uint64_t, DRedData> tmpMap;
    unordered_map<uint64_t, DRedData>::iterator tmpMapIt;
    
    uint64_t grandTotalRedundantBytes = 0;
    uint64_t grandTotalRedundantPage_level1 = 0;
    uint64_t grandTotalRedundantPage_level2 = 0;
    uint64_t grandTotalRedundantPage_level3 = 0;
    uint64_t grandTotalPage = 0;
    uint64_t all0page = 0;
    float maxrate = 0;
    float minrate = 100;
    fprintf(gTraceFile, "\n--------------- Dumping PAGE Redundancy Info ----------------\n");
    fprintf(gTraceFile, "\n*************** Dump Data from Thread %d ****************\n", threadId);
    
    for (unordered_map<uint64_t, RedLogs>::iterator it = RedMap[threadId].begin(); it != RedMap[threadId].end(); ++it) {
        uint64_t key = GET_PAGE_INDEX((*it).first);
        tmpMapIt = tmpMap.find(key);
        if(tmpMapIt==tmpMap.end()) {
            DRedData tmp = { key, (*it).second.zerobytes, (*it).second.zeroreads, (*it).second.reads, (*it).second.state};
            tmpMap[key]=tmp;
        } else {
            (*tmpMapIt).second.frequency += (*it).second.zerobytes;
            (*tmpMapIt).second.all0freq += (*it).second.zeroreads;
            (*tmpMapIt).second.ltot += (*it).second.reads;
            (*tmpMapIt).second.state &= (*it).second.state;
        }
    }
    for (unordered_map<uint64_t, DRedData>::iterator it = tmpMap.begin(); it != tmpMap.end(); ++it) {
        DRedData tmp = (*it).second;
        tmpList.push_back(tmp);
        grandTotalRedundantBytes += tmp.frequency;
        if(maxrate < (float)tmp.all0freq/(float)tmp.ltot) {
            maxrate = (float)tmp.all0freq/(float)tmp.ltot;
        }
        if(minrate > (float)tmp.all0freq/(float)tmp.ltot) {
            minrate = (float)tmp.all0freq/(float)tmp.ltot;
        }
        grandTotalPage++;
        if(tmp.state==STATE_ZERO) ++all0page;
        if((float)tmp.all0freq/(float)tmp.ltot > LEVEL_1_RED_THRESHOLD) {
            grandTotalRedundantPage_level1++;
        }
        if((float)tmp.all0freq/(float)tmp.ltot > LEVEL_2_RED_THRESHOLD) {
            grandTotalRedundantPage_level2++;
        }
        if((float)tmp.all0freq/(float)tmp.ltot > LEVEL_3_RED_THRESHOLD) {
            grandTotalRedundantPage_level3++;
        }
    }
    
    //__sync_fetch_and_add(&grandTotBytesRedLoad,grandTotalRedundantBytes);
    
    fprintf(gTraceFile, "\n Total redundant bytes = %f %%, rate range from [%f, %f] %%\n", grandTotalRedundantBytes * 100.0 / ClientGetTLS(threadId)->bytesLoad, minrate*100, maxrate*100);
    
    fprintf(gTraceFile, "\n Total redundant Pages (Only Reading 0s) = %f %%\n", all0page * 100.0 / grandTotalPage);
    fprintf(gTraceFile, "\n Total redundant Pages (local redundant rate > %f %%) = %f %%\n", LEVEL_1_RED_THRESHOLD * 100.0, grandTotalRedundantPage_level1 * 100.0 / grandTotalPage);
    fprintf(gTraceFile, "\n Total redundant Pages (local redundant rate > %f %%) = %f %%\n", LEVEL_2_RED_THRESHOLD * 100.0, grandTotalRedundantPage_level2 * 100.0 / grandTotalPage);
    fprintf(gTraceFile, "\n Total redundant Pages (local redundant rate > %f %%) = %f %%\n", LEVEL_3_RED_THRESHOLD * 100.0, grandTotalRedundantPage_level3 * 100.0 / grandTotalPage);
#ifdef PRINT_ALL_PAGE_INFO
    sort(tmpList.begin(), tmpList.end(), DRedundacyCompare);
    int cntxtNum = 0;
    for (vector<DRedData>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if (cntxtNum < MAX_REDUNDANT_CONTEXTS_TO_LOG) {
            fprintf(gTraceFile, "\n\n======= PAGE %lx : (%f) %% of total Redundant (%ld Bytes), all zero ratio %f %% (%ld Zeros / %ld Reads) ======\n", 
                (*listIt).index, 
                (*listIt).frequency * 100.0 / grandTotalRedundantBytes,
                (*listIt).frequency,
                (*listIt).all0freq * 100.0 / (*listIt).ltot,
                (*listIt).all0freq,(*listIt).ltot);
        }
        else {
            break;
        }
        cntxtNum++;
    }
#endif
    fprintf(gTraceFile, "\n------------ Dumping Page Redundancy Info Finish -------------\n");
}

static void PrintCacheRedundancy(THREADID threadId) {
    vector<DRedData> tmpList;
    vector<DRedData>::iterator tmpIt;
    
    uint64_t grandTotalRedundantBytes = 0;
    uint64_t grandTotalRedundantPage_level1 = 0;
    uint64_t grandTotalRedundantPage_level2 = 0;
    uint64_t grandTotalRedundantPage_level3 = 0;
    uint64_t grandTotalPage = 0;
    uint64_t all0page = 0;
    float maxrate = 0;
    float minrate = 100;
    fprintf(gTraceFile, "\n--------------- Dumping CACHE Redundancy Info ----------------\n");
    fprintf(gTraceFile, "\n*************** Dump Data from Thread %d ****************\n", threadId);
    
    for (unordered_map<uint64_t, RedLogs>::iterator it = RedMap[threadId].begin(); it != RedMap[threadId].end(); ++it) {
        DRedData tmp = { (*it).first, (*it).second.zerobytes, (*it).second.zeroreads, (*it).second.reads, (*it).second.state};
        tmpList.push_back(tmp);
        grandTotalRedundantBytes += tmp.frequency;
        if(maxrate < (float)tmp.all0freq/(float)tmp.ltot) {
            maxrate = (float)tmp.all0freq/(float)tmp.ltot;
        }
        if(minrate > (float)tmp.all0freq/(float)tmp.ltot) {
            minrate = (float)tmp.all0freq/(float)tmp.ltot;
        }
        grandTotalPage++;
        if(tmp.state==STATE_ZERO) ++all0page;
        if((float)tmp.all0freq/(float)tmp.ltot > LEVEL_1_RED_THRESHOLD) {
            grandTotalRedundantPage_level1++;
        }
        if((float)tmp.all0freq/(float)tmp.ltot > LEVEL_2_RED_THRESHOLD) {
            grandTotalRedundantPage_level2++;
        }
        if((float)tmp.all0freq/(float)tmp.ltot > LEVEL_3_RED_THRESHOLD) {
            grandTotalRedundantPage_level3++;
        }
    }
    
    __sync_fetch_and_add(&grandTotBytesRedLoad,grandTotalRedundantBytes);
    
    fprintf(gTraceFile, "\n Total redundant bytes = %f %%, rate range from [%f, %f] %%\n", grandTotalRedundantBytes * 100.0 / ClientGetTLS(threadId)->bytesLoad, minrate*100, maxrate*100);

    fprintf(gTraceFile, "\n Total redundant Caches (Only Reading 0s) = %f %%\n", all0page * 100.0 / grandTotalPage);
    fprintf(gTraceFile, "\n Total redundant Caches (local redundant rate > %f %%) = %f %%\n", LEVEL_1_RED_THRESHOLD * 100.0, grandTotalRedundantPage_level1 * 100.0 / grandTotalPage);
    fprintf(gTraceFile, "\n Total redundant Caches (local redundant rate > %f %%) = %f %%\n", LEVEL_2_RED_THRESHOLD * 100.0, grandTotalRedundantPage_level2 * 100.0 / grandTotalPage);
    fprintf(gTraceFile, "\n Total redundant Caches (local redundant rate > %f %%) = %f %%\n", LEVEL_3_RED_THRESHOLD * 100.0, grandTotalRedundantPage_level3 * 100.0 / grandTotalPage);
#ifdef PRINT_ALL_PAGE_INFO
    sort(tmpList.begin(), tmpList.end(), DRedundacyCompare);
    int cntxtNum = 0;
    for (vector<DRedData>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if (cntxtNum < MAX_REDUNDANT_CONTEXTS_TO_LOG) {
            fprintf(gTraceFile, "\n\n======= CACHE %lx : (%f) %% of total Redundant (%ld Bytes), all zero ratio %f %% (%ld Zeros / %ld Reads) ======\n", 
                (*listIt).index, 
                (*listIt).frequency * 100.0 / grandTotalRedundantBytes,
                (*listIt).frequency,
                (*listIt).all0freq * 100.0 / (*listIt).ltot,
                (*listIt).all0freq,(*listIt).ltot);
        }
        else {
            break;
        }
        cntxtNum++;
    }
#endif
    fprintf(gTraceFile, "\n------------ Dumping CACHE Redundancy Info Finish -------------\n");
}

/*
static void HPCRunRedundancyPairs(THREADID threadId) {
    vector<RedundacyData> tmpList;
    vector<RedundacyData>::iterator tmpIt;
    
    for (unordered_map<uint64_t, RedLogs>::iterator it = RedMap[threadId].begin(); it != RedMap[threadId].end(); ++it) {
        RedundacyData tmp = { DECODE_DEAD ((*it).first), DECODE_KILL((*it).first), (*it).second.red, (*it).second.tot};
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
    vector<RedundacyData>::iterator tmpIt;
    
    for (unordered_map<uint64_t, RedLogs>::iterator it = ApproxRedMap[threadId].begin(); it != ApproxRedMap[threadId].end(); ++it) {
        RedundacyData tmp = { DECODE_DEAD ((*it).first), DECODE_KILL((*it).first), (*it).second.red, (*it).second.tot};
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
*/
// On each Unload of a loaded image, the accummulated redundancy information is dumped
static VOID ImageUnload(IMG img, VOID* v) {
    printf("\nImage %s Unloading...\n", IMG_Name(img).c_str());
    fflush(stdout);
    fprintf(gTraceFile, "\n TODO .. Multi-threading is not well supported.");
    THREADID  threadid =  PIN_ThreadId();
    fprintf(gTraceFile, "\nUnloading %s", IMG_Name(img).c_str());
    if (RedMap[threadid].empty()) return;
    PIN_LockClient();
    PrintCacheRedundancy(threadid);
    PrintPageRedundancy(threadid);
    PIN_UnlockClient();
    printf("Unlocked\n");
    fflush(stdout);
    // clear redmap now
    RedMap[threadid].clear();
    printf("...Finish\n");
    fflush(stdout);
}

static VOID ThreadFiniFunc(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v) {
    
    __sync_fetch_and_add(&grandTotBytesLoad, ClientGetTLS(threadid)->bytesLoad);
    /*
    // output the CCT for hpcviewer format
    HPCRunRedundancyPairs(threadid);
    HPCRunApproxRedundancyPairs(threadid);
    newCCT_hpcrun_selection_write(threadid);*/
}

static VOID FiniFunc(INT32 code, VOID *v) {
    // do whatever you want to the full CCT with footpirnt
    uint64_t redReadTmp = 0;
    uint64_t approxRedReadTmp = 0;
    for(int i = 0; i < THREAD_MAX; ++i){
        unordered_map<uint64_t, RedLogs>::iterator it;
        if(!RedMap[i].empty()){
            for (it = RedMap[i].begin(); it != RedMap[i].end(); ++it) {
                redReadTmp += (*it).second.zerobytes;
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
/*    for (int i = 0; i < THREAD_MAX; ++i) {
        RedMap[i].set_empty_key(0);
        ApproxRedMap[i].set_empty_key(0);
    }
*/
}

static VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    RedSpyThreadData* tdata = (RedSpyThreadData*)memalign(32,sizeof(RedSpyThreadData));
    InitThreadData(tdata);
    RedMap[threadid].reserve(10000000);
    //    __sync_fetch_and_add(&gClientNumThreads, 1);
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
    PinCCTLibInit(INTERESTING_INS_ALL, gTraceFile, InstrumentInsCallback, 0);
    /*
    // Init hpcrun format output
    init_hpcrun_format(argc, argv, NULL, NULL, false);
    // Create new metrics
    redload_metric_id = hpcrun_create_metric("RED_LOAD");
    redload_approx_metric_id = hpcrun_create_metric("RED_LOAD_APPROX");
    */
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

