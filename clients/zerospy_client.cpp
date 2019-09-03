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

#define PAGE_MASK (~0xfff)
#define GET_PAGE_INDEX(x) ((x) & PAGE_MASK)

#define CACHELINE_MASK (~63)
#define GET_CACHELINE_INDEX(x) ((x) & CACHELINE_MASK)

//#define MERGING
// #define NO_APPROXMAP
// #define SKIP_SMALLCASE

#ifdef ENABLE_SAMPLING

#define WINDOW_ENABLE 1000000
#define WINDOW_DISABLE 100000000
#define WINDOW_CLEAN 10
#endif

#define DECODE_DEAD(data) static_cast<uint8_t>(((data)  & 0xffffffffffffffff) >> 32 )
#define DECODE_KILL(data) (static_cast<ContextHandle_t>( (data)  & 0x00000000ffffffff))


#define MAKE_CONTEXT_PAIR(a, b) (((uint64_t)(a) << 32) | ((uint64_t)(b)))

#define delta 0.01


/***********************************************
 ******  shadow memory
 ************************************************/
//ConcurrentShadowMemory<uint8_t, ContextHandle_t> sm;

struct{
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
    char name[MAX_FILE_PATH] = "zeroLoad.out.";
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

struct RedLogs{
    uint64_t tot;
    uint64_t red;
    uint64_t fred; // full redundancy
    uint32_t redByteMap;
    //uint8_t AccessLen;
};
struct ApproxRedLogs{
    //uint64_t tot;
    //uint64_t red;
    uint64_t fred; // full redundancy
    uint64_t ftot;
    uint32_t redByteMapMan;
    uint32_t redByteMapExp;
    uint32_t redByteMapSign;
    uint8_t AccessLen;
    uint8_t size;
    //uint8_t down;
};
//static unordered_map<uint64_t, uint64_t> validMap[THREAD_MAX];
static unordered_map<uint64_t, RedLogs> RedMap[THREAD_MAX];
static unordered_map<uint64_t, ApproxRedLogs> ApproxRedMap[THREAD_MAX];
#ifdef USE_COLLECT_PAGE_CACHE
struct DataLogs {
    uint64_t red;
    uint64_t tot;
};

static unordered_map<uint64_t, DataLogs> PageRedMap[THREAD_MAX];
static unordered_map<uint64_t, DataLogs> CacheRedMap[THREAD_MAX];
static inline void AddToPageRedTable(uint64_t key,  uint16_t value, uint16_t total, THREADID threadId) __attribute__((always_inline,flatten));
static inline void AddToPageRedTable(uint64_t key,  uint16_t value, uint16_t total, THREADID threadId) {
#ifdef MULTI_THREADED
    LOCK_RED_MAP();
#endif
    unordered_map<uint64_t, DataLogs>::iterator it = PageRedMap[threadId].find(key);
    if ( it  == PageRedMap[threadId].end()) {
        DataLogs log;
        log.red = value;
        log.tot = total;
        PageRedMap[threadId][key] = log;
    } else {
        it->second.red += value;
        it->second.tot += total;
    }
#ifdef MULTI_THREADED
    UNLOCK_RED_MAP();
#endif
}

static inline void AddToCacheRedTable(uint64_t key,  uint16_t value, uint16_t total, THREADID threadId) __attribute__((always_inline,flatten));
static inline void AddToCacheRedTable(uint64_t key,  uint16_t value, uint16_t total, THREADID threadId) {
#ifdef MULTI_THREADED
    LOCK_RED_MAP();
#endif
    unordered_map<uint64_t, DataLogs>::iterator it = CacheRedMap[threadId].find(key);
    if ( it  == CacheRedMap[threadId].end()) {
        DataLogs log;
        log.red = value;
        log.tot = total;
        CacheRedMap[threadId][key] = log;
    } else {
        it->second.red += value;
        it->second.tot += total;
    }
#ifdef MULTI_THREADED
    UNLOCK_RED_MAP();
#endif
}
#endif
static inline void AddToRedTable(uint64_t key,  uint16_t value, uint32_t byteMap, uint16_t total, THREADID threadId) __attribute__((always_inline,flatten));
static inline void AddToRedTable(uint64_t key,  uint16_t value, uint32_t byteMap, uint16_t total, THREADID threadId) {
#ifdef MULTI_THREADED
    LOCK_RED_MAP();
#endif
    unordered_map<uint64_t, RedLogs>::iterator it = RedMap[threadId].find(key);
    if ( it  == RedMap[threadId].end()) {
        RedLogs log;
        log.red = value;
        log.tot = total;
        log.fred= (value==total);
        log.redByteMap = byteMap;
        //log.AccessLen = total;
        //if(total < value) cerr << "ERROR : total " << total << " < value " << value << endl;
        RedMap[threadId][key] = log;
        //printf("Bucket size : %ld\n",RedMap[threadId].bucket_count());
    } else {
        it->second.red += value;
        it->second.tot += total;
        it->second.fred+= (value==total);
        it->second.redByteMap &= byteMap;
        //if(total < value) cerr << "ERROR : total " << total << " < value " << value << endl;
        //assert(it->second.AccessLen == total && "AccessLen not match");
    }
    //localTotBytesLoad[threadId] += total;
#ifdef MULTI_THREADED
    UNLOCK_RED_MAP();
#endif
}

static inline void AddToApproximateRedTable(uint64_t key, uint32_t byteMapMan, uint32_t byteMapExp, uint32_t byteMapSign, uint16_t total, uint16_t zeros, uint16_t nums, uint8_t size, THREADID threadId) __attribute__((always_inline,flatten));
static inline void AddToApproximateRedTable(uint64_t key, uint32_t byteMapMan, uint32_t byteMapExp, uint32_t byteMapSign, uint16_t total, uint16_t zeros, uint16_t nums, uint8_t size, THREADID threadId) {
#ifdef MULTI_THREADED
    LOCK_RED_MAP();
#endif
    unordered_map<uint64_t, ApproxRedLogs>::iterator it = ApproxRedMap[threadId].find(key);
    if ( it  == ApproxRedMap[threadId].end()) {
        ApproxRedLogs log;
        //log.red = value;
        //log.tot = total;
        log.fred= zeros;
        log.ftot= nums;
        log.redByteMapMan = byteMapMan;
        log.redByteMapExp = byteMapExp;
        log.redByteMapSign = byteMapSign;
        log.AccessLen = total;
        log.size = size;
        //log.down = down;
        //if(total < value) cerr << "ERROR : total " << total << " < value " << value << endl;
        ApproxRedMap[threadId][key] = log;
    } else {
        //it->second.red += value;
        //it->second.tot += total;
        it->second.fred+= zeros;
        it->second.ftot+= nums;
        it->second.redByteMapMan &= byteMapMan;
        it->second.redByteMapExp &= byteMapExp;
        it->second.redByteMapSign &= byteMapSign;
        //it->second.down &= down;
        //if(total < value) cerr << "ERROR : total " << total << " < value " << value << endl;
        //assert(it->second.AccessLen == total && "AccessLen not match");
    }
    //localTotBytesLoad[threadId] += total;
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

// template<int start, int end, int incr, bool conditional, bool approx>
// struct UnrolledLoop{
//     static __attribute__((always_inline)) void Body(function<void (const int)> func){
//         func(start); // Real loop body
//         UnrolledLoop<start+incr, end, incr, conditional, approx>:: Body(func);   // unroll next iteration
//     }
//     static __attribute__((always_inline)) void BodySamePage(ContextHandle_t * __restrict__ prevIP, const ContextHandle_t handle, THREADID threadId){
//         if(conditional) {
//             // report in RedTable
//             if(approx)
//                 AddToApproximateRedTable((uint64_t)handle, 0, 0, 1, false, threadId);
//             else
//                 AddToRedTable((uint64_t)handle, 0, 0, 1, threadId);
//         }
//         // Update context
//         //prevIP[start] = handle;
//         UnrolledLoop<start+incr, end, incr, conditional, approx>:: BodySamePage(prevIP, handle, threadId);   // unroll next iteration
//     }
//     static __attribute__((always_inline)) void BodyStraddlePage(uint64_t addr, const ContextHandle_t handle, THREADID threadId){
//         //tuple<uint8_t[SHADOW_PAGE_SIZE], ContextHandle_t[SHADOW_PAGE_SIZE]> &t = sm.GetOrCreateShadowBaseAddress((uint64_t)addr+start);
//         //ContextHandle_t * prevIP = &(get<1>(t)[PAGE_OFFSET(((uint64_t)addr+start))]);
        
//         if (conditional) {
//             // report in RedTable
//             if(approx)
//                 AddToApproximateRedTable((uint64_t)handle, 0, 0, 1, false, threadId);
//             else
//                 AddToRedTable((uint64_t)handle, 0, 0, 1, threadId);
//         }
//         // Update context
//         //prevIP[0] = handle;
//         UnrolledLoop<start+incr, end, incr, conditional, approx>:: BodyStraddlePage(addr, handle, threadId);   // unroll next iteration
//     }
// #ifdef USE_COLLECT_PAGE_CACHE
//     static __attribute__((always_inline)) void BodyStraddleCacheline(uint64_t addr, uint32_t map, THREADID threadId){
//         if (conditional) {
//             // report in RedTable
//             AddToCacheRedTable(GET_CACHELINE_INDEX(addr),(map&(1<<start))!=0?1:0,1,threadId);
//         }
//         UnrolledLoop<start+incr, end, incr, conditional, approx>:: BodyStraddleCacheline(addr, map, threadId);   // unroll next iteration
//     }
//     static __attribute__((always_inline)) void BodyStraddlePageRedTable(uint64_t addr, uint32_t map, THREADID threadId){
//         if (conditional) {
//             // report in RedTable
//             AddToPageRedTable(GET_PAGE_INDEX(addr),(map&(1<<start))!=0?1:0,1,threadId);
//         }
//         UnrolledLoop<start+incr, end, incr, conditional, approx>:: BodyStraddlePageRedTable(addr, map, threadId);   // unroll next iteration
//     }
// #endif
// };

// template<int end,  int incr, bool conditional, bool approx>
// struct UnrolledLoop<end , end , incr, conditional, approx>{
//     static __attribute__((always_inline)) void Body(function<void (const int)> func){}
//     static __attribute__((always_inline)) void BodySamePage(ContextHandle_t * __restrict__ prevIP, const ContextHandle_t handle, THREADID threadId){}
//     static __attribute__((always_inline)) void BodyStraddlePage(uint64_t addr, const ContextHandle_t handle, THREADID threadId){}
// #ifdef USE_COLLECT_PAGE_CACHE
//     static __attribute__((always_inline)) void BodyStraddleCacheline(uint64_t addr, uint32_t map, THREADID threadId){}
//     static __attribute__((always_inline)) void BodyStraddlePageRedTable(uint64_t addr, uint32_t map, THREADID threadId){}
// #endif
// };

template<int start, int end, int incr>
struct UnrolledConjunction{
    static __attribute__((always_inline)) bool Body(function<bool (const int)> func){
        return func(start) && UnrolledConjunction<start+incr, end, incr>:: Body(func);   // unroll next iteration
    }
    static __attribute__((always_inline)) bool BodyContextCheck(ContextHandle_t * __restrict__ prevIP){
        return (prevIP[0] == prevIP[start]) && UnrolledConjunction<start+incr, end, incr>:: BodyContextCheck(prevIP);   // unroll next iteration
    }
    static __attribute__((always_inline)) uint32_t BodyIsZero(uint8_t* addr){
        return ((addr[end-1]!=0)? 0 : 1 + UnrolledConjunction<start, end-incr, incr>:: BodyIsZero(addr));   // unroll next iteration
    }
    static __attribute__((always_inline)) uint32_t BodyByteMap(uint8_t* addr){
        return (start==0?(addr[start]==0):((addr[start]==0)<<start)) | UnrolledConjunction<start+incr, end, incr>:: BodyByteMap(addr);   // unroll next iteration
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
    static __attribute__((always_inline)) uint32_t BodyIsZero(uint8_t* addr){
        return 0;
    }
    static __attribute__((always_inline)) uint32_t BodyByteMap(uint8_t* addr){
        return 0;
    }
};

template<int start, int end, int step>
struct UnrolledCount{
    static __attribute__((always_inline)) uint32_t BodyRedZero(uint8_t* addr){
        return start>end ? 0 : UnrolledConjunction<start,start+step,1>::BodyIsZero(addr) + UnrolledCount<start+step,end,step>::BodyRedZero(addr);
    }
};
template<int end, int step>
struct UnrolledCount<end, end, step>{
    static __attribute__((always_inline)) uint32_t BodyRedZero(uint8_t* addr){
        return 0;
    }
};

#ifdef BIG_ENDIAN
typedef union {
  float f;
  struct {
    uint32_t sign : 1;
    uint32_t exponent : 8;
    uint32_t mantisa : 23;
  } parts;
  struct {
    uint32_t sign : 1;
    uint32_t value : 31;
  } vars;
} float_cast;

typedef union {
  double f;
  struct {
    uint64_t sign : 1;
    uint64_t exponent : 11;
    uint64_t mantisa : 52;
  } parts;
  struct {
    uint64_t sign : 1;
    uint64_t value : 63;
  } vars;
} double_cast;
#else
typedef union {
  float f;
  struct {
    uint32_t mantisa : 23;
    uint32_t exponent : 8;
    uint32_t sign : 1;
  } parts;
  struct {
    uint32_t value : 31;
    uint32_t sign : 1;
  } vars;
} float_cast;

typedef union {
  double f;
  struct {
    uint64_t mantisa : 52;
    uint64_t exponent : 11;
    uint64_t sign : 1;
  } parts;
  struct {
    uint64_t value : 63;
    uint64_t sign : 1;
  } vars;
} double_cast;
#endif

template<int start, int end, int step>
struct UnrolledCountApprox{
    // floating point : sign, exponent, mantissa
    static __attribute__((always_inline)) uint32_t BodyRedZero(uint8_t* addr){
        if(step==4) {
            uint32_t man = (*(reinterpret_cast<float_cast*>(&addr[start]))).parts.mantisa;
            uint8_t exp = (*(reinterpret_cast<float_cast*>(&addr[start]))).parts.exponent;
            return UnrolledCountApprox<start+step,end,step>::BodyRedZero(addr) + (UnrolledCount<0,3,1>::BodyRedZero((uint8_t*)&man) + UnrolledCount<0,1,1>::BodyRedZero((uint8_t*)&exp));
        } else if(step==8) {
            uint64_t man = (*(reinterpret_cast<double_cast*>(&addr[start]))).parts.mantisa;
            uint32_t exp = (*(reinterpret_cast<double_cast*>(&addr[start]))).parts.exponent;
            return UnrolledCountApprox<start+step,end,step>::BodyRedZero(addr) + (UnrolledCount<0,7,1>::BodyRedZero((uint8_t*)&man) + UnrolledCount<0,2,1>::BodyRedZero((uint8_t*)&exp));
        } else {
            assert(0 && "Not Supportted floating size! now only support for FP32 or FP64.");
            return UnrolledCount<start,end,step>::BodyRedZero(addr);
        }
        return 0;
    }
};
template<int end, int step>
struct UnrolledCountApprox<end, end, step>{
    static __attribute__((always_inline)) uint32_t BodyRedZero(uint8_t* addr){
        return 0;
    }
};

template<int start, int end, int incr>
struct UnrolledConjunctionApprox{
    static __attribute__((always_inline)) uint64_t BodyByteMapMan(uint8_t* addr){
        // from low to high : 32 mantisa map, 31 exponent map, 1 sign map 
        if(incr==4) {
            uint32_t man = (*(reinterpret_cast<float_cast*>(&addr[start]))).parts.mantisa;
            return ((UnrolledConjunctionApprox<start+incr,end,incr>::BodyByteMapMan(addr))<<3) | (UnrolledConjunction<0,3,1>::BodyByteMap((uint8_t*)&man));
        } else if(incr==8) {
            uint64_t man = (*(reinterpret_cast<double_cast*>(&addr[start]))).parts.mantisa;
            return ((UnrolledConjunctionApprox<start+incr,end,incr>::BodyByteMapMan(addr))<<7) | (UnrolledConjunction<0,7,1>::BodyByteMap((uint8_t*)&man));
        } else {
            assert(0 && "Not Supportted floating size! now only support for FP32 or FP64.");
            return UnrolledConjunction<start,end,incr>::BodyByteMap(addr);
        }
        return 0;
    }
    static __attribute__((always_inline)) uint64_t BodyByteMapExp(uint8_t* addr){
        // from low to high : 32 mantisa map, 31 exponent map, 1 sign map 
        if(incr==4) {
            uint8_t exp = (*(reinterpret_cast<float_cast*>(&addr[start]))).parts.exponent;
            return ((UnrolledConjunctionApprox<start+incr,end,incr>::BodyByteMapExp(addr))<<1) | (exp==0);
        } else if(incr==8) {
            uint32_t exp = (*(reinterpret_cast<double_cast*>(&addr[start]))).parts.exponent;
            return ((UnrolledConjunctionApprox<start+incr,end,incr>::BodyByteMapExp(addr))<<2) | ((exp&0xF)==0) | (((exp&0x70)==0)<<1);
        } else {
            assert(0 && "Not Supportted floating size! now only support for FP32 or FP64.");
            return UnrolledConjunction<start,end,incr>::BodyByteMap(addr);
        }
        return 0;
    }
    static __attribute__((always_inline)) uint64_t BodyByteMapSign(uint8_t* addr){
        // from low to high : 32 mantisa map, 31 exponent map, 1 sign map 
        if(incr==4) {
            uint8_t sign= (*(reinterpret_cast<float_cast*>(&addr[start]))).parts.sign;
            return ((UnrolledConjunctionApprox<start+incr,end,incr>::BodyByteMapSign(addr))<<1) | (sign==0);
        } else if(incr==8) {
            uint8_t sign = (*(reinterpret_cast<double_cast*>(&addr[start]))).parts.sign;
            return ((UnrolledConjunctionApprox<start+incr,end,incr>::BodyByteMapSign(addr))<<1) | (sign==0);
        } else {
            assert(0 && "Not Supportted floating size! now only support for FP32 or FP64.");
            return UnrolledConjunction<start,end,incr>::BodyByteMap(addr);
        }
        return 0;
    }
    // if the mantisa is 0, the value of the double/float var must be 0
    static __attribute__((always_inline)) uint64_t BodyZeros(uint8_t* addr){
        if(incr==4)
            return ((*(reinterpret_cast<float_cast*>(&addr[start]))).vars.value==0) + (UnrolledConjunctionApprox<start+incr,end,incr>::BodyZeros(addr));
        else if(incr==8)
            return ((*(reinterpret_cast<double_cast*>(&addr[start]))).vars.value==0) + (UnrolledConjunctionApprox<start+incr,end,incr>::BodyZeros(addr));
        return 0;
    }
    static __attribute__((always_inline)) uint64_t BodyMap(uint8_t* addr){
        if(incr==4)
            return (*(reinterpret_cast<uint32_t*>(&addr[start]))) | (UnrolledConjunctionApprox<start+incr,end,incr>::BodyMap(addr));
        else if(incr==8)
            return (*(reinterpret_cast<uint64_t*>(&addr[start]))) | (UnrolledConjunctionApprox<start+incr,end,incr>::BodyMap(addr));
        return 0;
    }
};

template<int end,  int incr>
struct UnrolledConjunctionApprox<end , end , incr>{
    static __attribute__((always_inline)) uint64_t BodyByteMapMan(uint8_t* addr){
        return 0;
    }
    static __attribute__((always_inline)) uint64_t BodyByteMapExp(uint8_t* addr){
        return 0;
    }
    static __attribute__((always_inline)) uint64_t BodyByteMapSign(uint8_t* addr){
        return 0;
    }
    static __attribute__((always_inline)) uint64_t BodyZeros(uint8_t* addr){
        return 0;
    }
    static __attribute__((always_inline)) uint64_t BodyMap(uint8_t* addr){
        return 0;
    }
};

template<class T, uint32_t AccessLen, bool isApprox>
struct ZeroSpyAnalysis{
    static __attribute__((always_inline)) uint64_t getRedMap(void * addr){
        uint8_t* bytes = static_cast<uint8_t*>(addr);
        uint32_t redmap = UnrolledConjunction<0,AccessLen,1>::BodyByteMap(bytes);
        return redmap;
    }
    static __attribute__((always_inline)) uint64_t getRedNum(void * addr){
        if(isApprox){
            uint8_t* bytes = static_cast<uint8_t*>(addr);
            uint32_t rednum = UnrolledCountApprox<0,AccessLen,sizeof(T)>::BodyRedZero(bytes);
            return rednum;
        }else{
            uint8_t* bytes = static_cast<uint8_t*>(addr);
            uint32_t rednum = UnrolledCount<0,AccessLen,sizeof(T)>::BodyRedZero(bytes);
            return rednum;
        }
        return 0;
    }
    static __attribute__((always_inline)) VOID CheckNByteValueAfterRead(void* addr, uint32_t opaqueHandle, THREADID threadId){
#ifdef DEBUG_ZEROSPY
        printf("\nINFO : In Check NBytes Value After Read\n");
#endif
        //RedSpyThreadData* const tData = ClientGetTLS(threadId);
        ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
        if(isApprox) {
            uint32_t redbyteNum = getRedNum(addr);
            if(redbyteNum) {
                uint8_t* bytes = static_cast<uint8_t*>(addr);
                uint32_t man = UnrolledConjunctionApprox<0,AccessLen,sizeof(T)>::BodyByteMapMan(bytes);
                uint32_t exp = UnrolledConjunctionApprox<0,AccessLen,sizeof(T)>::BodyByteMapExp(bytes);
                uint32_t sign= UnrolledConjunctionApprox<0,AccessLen,sizeof(T)>::BodyByteMapSign(bytes);
                uint32_t zeros = UnrolledConjunctionApprox<0,AccessLen,sizeof(T)>::BodyZeros(bytes);         
                AddToApproximateRedTable((uint64_t)curCtxtHandle, man, exp, sign, AccessLen, zeros, AccessLen/sizeof(T), sizeof(T), threadId);
            } else {
                AddToApproximateRedTable((uint64_t)curCtxtHandle, 0, 0, 0, AccessLen, 0, AccessLen/sizeof(T), sizeof(T), threadId);
            }
        } else {
            uint32_t redbyteNum = getRedNum(addr);
            if(redbyteNum) {
                uint32_t redbyteMap = getRedMap(addr);
                AddToRedTable((uint64_t)MAKE_CONTEXT_PAIR(AccessLen, curCtxtHandle), redbyteNum, redbyteMap, AccessLen, threadId);
            } else {
                AddToRedTable((uint64_t)MAKE_CONTEXT_PAIR(AccessLen, curCtxtHandle), 0, 0, AccessLen, threadId);
            }
        }

#ifdef DEBUG_ZEROSPY
        printf("\nINFO : Exit Check NBytes Value After Read\n");
#endif
    }
};

// // Approx
// template<class T, class LOWERT, uint32_t AccessLen>
// struct ZeroSpyApproxAnalysis{
//     static __attribute__((always_inline)) VOID CheckNByteValueAfterRead(void* addr, uint32_t opaqueHandle, THREADID threadId){
// #ifdef DEBUG_ZEROSPY
//         printf("\nINFO : In Check NBytes Value After Read\n");
// #endif
//         RedSpyThreadData* const tData = ClientGetTLS(threadId);
//         ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
//         uint32_t redbyteNum = ZeroSpyAnalysis<T,AccessLen,true>::getRedNum(addr);
//         // Check if the value can be downgrade
//         bool down = ((*(static_cast<T*>(addr)))==(T)((LOWERT)(*(static_cast<T*>(addr)))));
//         if(redbyteNum) {
//             uint32_t redbyteMap = ZeroSpyAnalysis<T,AccessLen,true>::getRedMap(addr);
//             // detected redundancy
//             AddToApproximateRedTable((uint64_t)curCtxtHandle, redbyteNum, redbyteMap, AccessLen, down, threadId);
//         } else {
//             AddToApproximateRedTable((uint64_t)curCtxtHandle, 0, 0, AccessLen, down, threadId);
//         }
// #ifdef DEBUG_ZEROSPY
//         printf("\nINFO : Exit Check NBytes Value After Read\n");
// #endif
//     }
// };

static inline VOID CheckAfterLargeRead(void* addr, UINT32 accessLen, uint32_t opaqueHandle, THREADID threadId){
#ifdef DEBUG_ZEROSPY
    printf("\nINFO : In Check After Large Read\n");
    if(accessLen > 32) {
        printf("ERROR : AccessLen too large : %d\n",accessLen);
        assert(0 && (accessLen <= 32));
    }
#endif
    //RedSpyThreadData* const tData = ClientGetTLS(threadId);
    ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
    
    //tuple<uint8_t[SHADOW_PAGE_SIZE], ContextHandle_t[SHADOW_PAGE_SIZE]> &t = sm.GetOrCreateShadowBaseAddress((uint64_t)addr);
    //ContextHandle_t * __restrict__ prevIP = &(get<1>(t)[PAGE_OFFSET((uint64_t)addr)]);
    //const uint8_t prevValue = 0;
    
    // This assumes that a large read cannot straddle a page boundary -- strong assumption, but lets go with it for now.
    //tuple<uint8_t[SHADOW_PAGE_SIZE], ContextHandle_t[SHADOW_PAGE_SIZE]> &tt = sm.GetOrCreateShadowBaseAddress((uint64_t)addr);
    uint8_t* bytes = static_cast<uint8_t*>(addr);
    uint32_t redbytesNum = 0;
    for(int i=accessLen-1;i>=0;--i) {
        if(bytes[i]!=0) {
            break;
        }
        ++redbytesNum;
    }

    if(redbytesNum) {
        uint32_t redbyteMap = 0;
        if(bytes[0]==0) {
            redbyteMap |= 1;
        }
        for(UINT32 i=1;i<accessLen;++i) {
            if(bytes[i]==0) {
                redbyteMap |= (1<<i);
            }
        }
/*#ifdef USE_COLLECT_PAGE_CACHE
    for(UINT32 i=0;i<accessLen;++i) {
        if(bytes[i]==0) {
            AddToPageRedTable(GET_PAGE_INDEX((uint64_t)(bytes+i)),1,1,threadId);
            AddToCacheRedTable(GET_CACHELINE_INDEX((uint64_t)(bytes+i)),1,1,threadId);
        } else {
            AddToPageRedTable(GET_PAGE_INDEX((uint64_t)(bytes+i)),0,1,threadId);
            AddToCacheRedTable(GET_CACHELINE_INDEX((uint64_t)(bytes+i)),0,1,threadId);
        }
    }
#endif*/
        // report in RedTable
        AddToRedTable((uint64_t)MAKE_CONTEXT_PAIR(accessLen, curCtxtHandle), redbytesNum, redbyteMap, accessLen, threadId);
    }
    else {
        AddToRedTable((uint64_t)MAKE_CONTEXT_PAIR(accessLen, curCtxtHandle), 0, 0, accessLen, threadId);
    }
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

/**********************************************************************************/

#ifdef ENABLE_SAMPLING
#error Sampling should not be enabled as it has not been tested yet!
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

#endif

struct RedundacyData {
    ContextHandle_t cntxt;
    uint64_t frequency;
    uint64_t all0freq;
    uint64_t ltot;
    uint32_t byteMap;
    uint8_t accessLen;
};

struct ApproxRedundacyData {
    ContextHandle_t cntxt;
    uint64_t all0freq;
    uint64_t ftot;
    uint32_t byteMapMan;
    uint32_t byteMapExp;
    uint32_t byteMapSign;
    uint8_t accessLen;
    uint8_t size;
};
#ifdef USE_COLLECT_PAGE_CACHE
struct DRedData {
    uint64_t index;
    uint64_t frequency;
    uint64_t ltot;
};

static inline bool DRedundacyCompare(const struct DRedData &first, const struct DRedData &second) {
    return first.frequency > second.frequency ? true : false;
}

#define LEVEL_1_RED_THRESHOLD 0.90
#define LEVEL_2_RED_THRESHOLD 0.70
#define LEVEL_3_RED_THRESHOLD 0.50

static void PrintPageRedundancy(THREADID threadId) {
    vector<DRedData> tmpList;
    vector<DRedData>::iterator tmpIt;
    
    uint64_t grandTotalRedundantBytes = 0;
    uint64_t grandTotalRedundantPage_level1 = 0;
    uint64_t grandTotalRedundantPage_level2 = 0;
    uint64_t grandTotalRedundantPage_level3 = 0;
    uint64_t grandTotalPage = 0;
    float maxrate = 0;
    float minrate = 100;
    fprintf(gTraceFile, "\n--------------- Dumping PAGE Redundancy Info ----------------\n");
    fprintf(gTraceFile, "\n*************** Dump Data from Thread %d ****************\n", threadId);
    
    for (unordered_map<uint64_t, DataLogs>::iterator it = PageRedMap[threadId].begin(); it != PageRedMap[threadId].end(); ++it) {
        DRedData tmp = { (*it).first, (*it).second.red, (*it).second.tot};
        tmpList.push_back(tmp);
        grandTotalRedundantBytes += tmp.frequency;
        if(maxrate < (float)tmp.frequency/(float)tmp.ltot) {
            maxrate = (float)tmp.frequency/(float)tmp.ltot;
        }
        if(minrate > (float)tmp.frequency/(float)tmp.ltot) {
            minrate = (float)tmp.frequency/(float)tmp.ltot;
        }
        grandTotalPage++;
        if((float)tmp.frequency/(float)tmp.ltot > LEVEL_1_RED_THRESHOLD) {
            grandTotalRedundantPage_level1++;
        }
        if((float)tmp.frequency/(float)tmp.ltot > LEVEL_2_RED_THRESHOLD) {
            grandTotalRedundantPage_level2++;
        }
        if((float)tmp.frequency/(float)tmp.ltot > LEVEL_3_RED_THRESHOLD) {
            grandTotalRedundantPage_level3++;
        }
    }
    
    __sync_fetch_and_add(&grandTotBytesRedLoad,grandTotalRedundantBytes);
    
    fprintf(gTraceFile, "\n Total redundant bytes = %f %%, rate range from [%f, %f] %%\n", grandTotalRedundantBytes * 100.0 / ClientGetTLS(threadId)->bytesLoad, minrate*100, maxrate*100);
    
    fprintf(gTraceFile, "\n Total redundant bytes (local redundant rate > %f %%) = %f %%\n", LEVEL_1_RED_THRESHOLD * 100.0, grandTotalRedundantPage_level1 * 100.0 / grandTotalPage);
    fprintf(gTraceFile, "\n Total redundant bytes (local redundant rate > %f %%) = %f %%\n", LEVEL_2_RED_THRESHOLD * 100.0, grandTotalRedundantPage_level2 * 100.0 / grandTotalPage);
    fprintf(gTraceFile, "\n Total redundant bytes (local redundant rate > %f %%) = %f %%\n", LEVEL_3_RED_THRESHOLD * 100.0, grandTotalRedundantPage_level3 * 100.0 / grandTotalPage);
#ifdef PRINT_ALL_PAGE_INFO
    sort(tmpList.begin(), tmpList.end(), DRedundacyCompare);
    int cntxtNum = 0;
    for (vector<DRedData>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if (cntxtNum < MAX_REDUNDANT_CONTEXTS_TO_LOG) {
            fprintf(gTraceFile, "\n\n======= PAGE %lx : (%f) %% of total Redundant, with local redundant %f %% (%ld Bytes / %ld Bytes) ======\n", 
                (*listIt).index,
                (*listIt).frequency * 100.0 / grandTotalRedundantBytes,
                (*listIt).frequency * 100.0 / (*listIt).ltot,
                (*listIt).frequency,(*listIt).ltot);
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
    float maxrate = 0;
    float minrate = 100;
    fprintf(gTraceFile, "\n--------------- Dumping CACHE Redundancy Info ----------------\n");
    fprintf(gTraceFile, "\n*************** Dump Data from Thread %d ****************\n", threadId);
    
    for (unordered_map<uint64_t, DataLogs>::iterator it = CacheRedMap[threadId].begin(); it != CacheRedMap[threadId].end(); ++it) {
        DRedData tmp = { (*it).first, (*it).second.red, (*it).second.tot};
        tmpList.push_back(tmp);
        grandTotalRedundantBytes += tmp.frequency;
        if(maxrate < (float)tmp.frequency/(float)tmp.ltot) {
            maxrate = (float)tmp.frequency/(float)tmp.ltot;
        }
        if(minrate > (float)tmp.frequency/(float)tmp.ltot) {
            minrate = (float)tmp.frequency/(float)tmp.ltot;
        }
        grandTotalPage++;
        if((float)tmp.frequency/(float)tmp.ltot > LEVEL_1_RED_THRESHOLD) {
            grandTotalRedundantPage_level1++;
        }
        if((float)tmp.frequency/(float)tmp.ltot > LEVEL_2_RED_THRESHOLD) {
            grandTotalRedundantPage_level2++;
        }
        if((float)tmp.frequency/(float)tmp.ltot > LEVEL_3_RED_THRESHOLD) {
            grandTotalRedundantPage_level3++;
        }
    }
    
    __sync_fetch_and_add(&grandTotBytesRedLoad,grandTotalRedundantBytes);
    
    fprintf(gTraceFile, "\n Total redundant bytes = %f, rate range from [%f, %f] %%\n", grandTotalRedundantBytes * 100.0 / ClientGetTLS(threadId)->bytesLoad, minrate*100, maxrate*100);

    fprintf(gTraceFile, "\n Total redundant bytes (local redundant rate > %f %%) = %f %%\n", LEVEL_1_RED_THRESHOLD * 100.0, grandTotalRedundantPage_level1 * 100.0 / grandTotalPage);
    fprintf(gTraceFile, "\n Total redundant bytes (local redundant rate > %f %%) = %f %%\n", LEVEL_2_RED_THRESHOLD * 100.0, grandTotalRedundantPage_level2 * 100.0 / grandTotalPage);
    fprintf(gTraceFile, "\n Total redundant bytes (local redundant rate > %f %%) = %f %%\n", LEVEL_3_RED_THRESHOLD * 100.0, grandTotalRedundantPage_level3 * 100.0 / grandTotalPage);
#ifdef PRINT_ALL_PAGE_INFO
    sort(tmpList.begin(), tmpList.end(), DRedundacyCompare);
    int cntxtNum = 0;
    for (vector<DRedData>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if (cntxtNum < MAX_REDUNDANT_CONTEXTS_TO_LOG) {
            fprintf(gTraceFile, "\n\n======= CACHE %lx : (%f) %% of total Redundant, with local redundant %f %% (%ld Bytes / %ld Bytes) ======\n", 
                (*listIt).index,
                (*listIt).frequency * 100.0 / grandTotalRedundantBytes,
                (*listIt).frequency * 100.0 / (*listIt).ltot,
                (*listIt).frequency,(*listIt).ltot);
        }
        else {
            break;
        }
        cntxtNum++;
    }
#endif
    fprintf(gTraceFile, "\n------------ Dumping CACHE Redundancy Info Finish -------------\n");
}
#endif
static inline bool RedundacyCompare(const struct RedundacyData &first, const struct RedundacyData &second) {
    return first.frequency > second.frequency ? true : false;
}
static inline bool ApproxRedundacyCompare(const struct ApproxRedundacyData &first, const struct ApproxRedundacyData &second) {
    return first.all0freq > second.all0freq ? true : false;
}
//#define SKIP_SMALLACCESS
#ifdef SKIP_SMALLACCESS
#define LOGGING_THRESHOLD 100
#endif
static void PrintRedundancyPairs(THREADID threadId) {
    vector<RedundacyData> tmpList;
    vector<RedundacyData>::iterator tmpIt;
    
    uint64_t grandTotalRedundantBytes = 0;
    uint64_t grandTotalRedundantIns = 0;
    tmpList.reserve(RedMap[threadId].size());
    printf("Dumping INTEGER Redundancy Info... Total num : %ld\n",RedMap[threadId].size());
    fflush(stdout);
    fprintf(gTraceFile, "\n--------------- Dumping INTEGER Redundancy Info ----------------\n");
    fprintf(gTraceFile, "\n*************** Dump Data from Thread %d ****************\n", threadId);
    uint64_t count = 0; uint64_t rep = -1;
#ifdef MERGING
    fprintf(gTraceFile, "\n*************** Merging Redundancy Info, The Caller Prefix Printed is useless ****************\n");
    for (unordered_map<uint64_t, RedLogs>::iterator it = RedMap[threadId].begin(); it != RedMap[threadId].end(); ++it) {
        ++count;
        if(100 * count / RedMap[threadId].size()!=rep) {
            rep = 100 * count / RedMap[threadId].size();
            printf("%ld%%  Finish, current list size = %ld\n",rep, tmpList.size());
            fflush(stdout);
        }
        grandTotalRedundantBytes += (*it).second.red;
#ifdef SKIP_SMALLACCESS
        if((*it).second.tot>LOGGING_THRESHOLD*((*it).second.AccessLen)) continue;
#endif
        ContextHandle_t cur = static_cast<ContextHandle_t>((*it).first);

        if(cur!=0) {
            for(tmpIt = tmpList.begin();tmpIt != tmpList.end(); ++tmpIt){
                if((*tmpIt).cntxt == 0){
                    continue;
                }
                if (!HaveSameCallerPrefix(cur,(*tmpIt).cntxt)) {
                    continue;
                }
                bool ct1 = IsSameSourceLine(cur,(*tmpIt).cntxt);
                if(ct1){
                    (*tmpIt).frequency += (*it).second.red;
                    (*tmpIt).all0freq += (*it).second.fred;
                    (*tmpIt).ltot += (*it).second.tot;
                    (*tmpIt).byteMap &= (*it).second.redByteMap;
                    // (*tmpIt).down &= (*it).second.down;
                    grandTotalRedundantIns += 1;
                    break;
                }
            }
        }
        if(tmpIt == tmpList.end()){
            // RedundacyData tmp = { static_cast<ContextHandle_t>((*it).first), (*it).second.red,(*it).second.fred,(*it).second.tot,(*it).second.redByteMap,(*it).second.AccessLen, (*it).second.down};
            RedundacyData tmp = { DECODE_KILL((*it).first), (*it).second.red,(*it).second.fred,(*it).second.tot,(*it).second.redByteMap,DECODE_DEAD((*it).first)};
            tmpList.push_back(tmp);
        }
    }
#else
    for (unordered_map<uint64_t, RedLogs>::iterator it = RedMap[threadId].begin(); it != RedMap[threadId].end(); ++it) {
        ++count;
        if(100 * count / RedMap[threadId].size()!=rep) {
            rep = 100 * count / RedMap[threadId].size();
            printf("%ld%%  Finish\n",rep);
            fflush(stdout);
        }
        RedundacyData tmp = { DECODE_KILL((*it).first), (*it).second.red,(*it).second.fred,(*it).second.tot,(*it).second.redByteMap,DECODE_DEAD((*it).first)};
        tmpList.push_back(tmp);
        grandTotalRedundantBytes += tmp.frequency;
    }
#endif
    
    __sync_fetch_and_add(&grandTotBytesRedLoad,grandTotalRedundantBytes);
    printf("Extracted Raw data, now sorting...\n");
    fflush(stdout);
    
    fprintf(gTraceFile, "\n Total redundant bytes = %f %%\n", grandTotalRedundantBytes * 100.0 / ClientGetTLS(threadId)->bytesLoad);
    fprintf(gTraceFile, "\n INFO : Total redundant bytes = %f %% (%ld / %ld) \n", grandTotalRedundantBytes * 100.0 / ClientGetTLS(threadId)->bytesLoad, grandTotalRedundantBytes, ClientGetTLS(threadId)->bytesLoad);
    
    sort(tmpList.begin(), tmpList.end(), RedundacyCompare);
    printf("Sorted, Now generating reports...\n");
    fflush(stdout);
    int cntxtNum = 0;
    for (vector<RedundacyData>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if (cntxtNum < MAX_REDUNDANT_CONTEXTS_TO_LOG) {
            fprintf(gTraceFile, "\n\n======= (%f) %% of total Redundant, with local redundant %f %% (%ld Bytes / %ld Bytes) ======\n", 
                (*listIt).frequency * 100.0 / grandTotalRedundantBytes,
                (*listIt).frequency * 100.0 / (*listIt).ltot,
                (*listIt).frequency,(*listIt).ltot);
            fprintf(gTraceFile, "\n\n======= with All Zero Redundant %f %% (%ld / %ld) ======\n", 
                (*listIt).all0freq * (*listIt).accessLen * 100.0 / (*listIt).ltot,
                (*listIt).all0freq,(*listIt).ltot/(*listIt).accessLen);
            fprintf(gTraceFile, "\n======= Redundant byte map : [0] ");
            for(uint32_t i=0;i<(*listIt).accessLen;++i) {
                if((*listIt).byteMap & (1<<i)) {
                    fprintf(gTraceFile, "00 ");
                }
                else {
                    fprintf(gTraceFile, "XX ");
                }
            }
            fprintf(gTraceFile, " [AccessLen=%d] =======\n", (*listIt).accessLen);
            fprintf(gTraceFile, "\n---------------------Redundant load with---------------------------\n");
            PrintFullCallingContext((*listIt).cntxt);
        }
        else {
            break;
        }
        cntxtNum++;
    }
    fprintf(gTraceFile, "\n------------ Dumping INTEGER Redundancy Info Finish -------------\n");
    printf("INTEGER Report dumped\n");
    fflush(stdout);
}

static void PrintApproximationRedundancyPairs(THREADID threadId) {
    vector<ApproxRedundacyData> tmpList;
    vector<ApproxRedundacyData>::iterator tmpIt;
    
    uint64_t grandTotalRedundantBytes = 0;
    uint64_t grandTotalRedundantIns = 0;
    fprintf(gTraceFile, "\n--------------- Dumping Approximation Redundancy Info ----------------\n");
    fprintf(gTraceFile, "\n*************** Dump Data(delta=%.2f%%) from Thread %d ****************\n", delta*100,threadId);
// #ifdef MERGING
    fprintf(gTraceFile, "\n*************** Merging Approximation Redundancy Info, The Caller Prefix Printed is useless ****************\n");
    for (unordered_map<uint64_t, ApproxRedLogs>::iterator it = ApproxRedMap[threadId].begin(); it != ApproxRedMap[threadId].end(); ++it) {
        grandTotalRedundantBytes += (*it).second.fred * (*it).second.AccessLen;
#ifdef SKIP_SMALLACCESS
        // only merging logs access more than LOGGING_THRESHOLD times
        if((*it).second.ftot>LOGGING_THRESHOLD) continue;
#endif
        ContextHandle_t cur = static_cast<ContextHandle_t>((*it).first);
        
        for(tmpIt = tmpList.begin();tmpIt != tmpList.end(); ++tmpIt){
            if(cur == 0 || ((*tmpIt).cntxt) == 0){
                continue;
            }
            if (!HaveSameCallerPrefix(cur,(*tmpIt).cntxt)) {
                continue;
            }
            bool ct1 = IsSameSourceLine(cur,(*tmpIt).cntxt);
            if(ct1){
                //(*tmpIt).frequency += (*it).second.red;
                (*tmpIt).all0freq += (*it).second.fred;
                //(*tmpIt).ltot += (*it).second.tot;
                (*tmpIt).ftot += (*it).second.ftot;
#ifndef NO_APPROXMAP
                (*tmpIt).byteMapMan &= (*it).second.redByteMapMan;
                (*tmpIt).byteMapExp &= (*it).second.redByteMapExp;
                (*tmpIt).byteMapSign&= (*it).second.redByteMapSign;
#endif
                grandTotalRedundantIns += 1;
                break;
            }
        }
        if(tmpIt == tmpList.end()){
            ApproxRedundacyData tmp = { static_cast<ContextHandle_t>((*it).first), (*it).second.fred,(*it).second.ftot, (*it).second.redByteMapMan, (*it).second.redByteMapExp, (*it).second.redByteMapSign,(*it).second.AccessLen, (*it).second.size};
            tmpList.push_back(tmp);
        }
    }
// #else
//     // for (unordered_map<uint64_t, RedLogs>::iterator it = ApproxRedMap[threadId].begin(); it != ApproxRedMap[threadId].end(); ++it) {
//     //     RedundacyData tmp = { static_cast<ContextHandle_t>((*it).first), (*it).second.red, (*it).second.fred, (*it).second.tot, (*it).second.redByteMap, (*it).second.AccessLen, (*it).second.down};
//     //     tmpList.push_back(tmp);
//     //     grandTotalRedundantZeros += tmp.all0freq;
//     // }
// #endif
    
    __sync_fetch_and_add(&grandTotBytesApproxRedLoad,grandTotalRedundantBytes);
    
    fprintf(gTraceFile, "\n Total redundant bytes = %f %%\n", grandTotalRedundantBytes * 100.0 / ClientGetTLS(threadId)->bytesLoad);
    fprintf(gTraceFile, "\n INFO : Total redundant bytes = %f %% (%ld / %ld) \n", grandTotalRedundantBytes * 100.0 / ClientGetTLS(threadId)->bytesLoad, grandTotalRedundantBytes, ClientGetTLS(threadId)->bytesLoad);
    
    sort(tmpList.begin(), tmpList.end(), ApproxRedundacyCompare);
    int cntxtNum = 0;
    for (vector<ApproxRedundacyData>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if (cntxtNum < MAX_REDUNDANT_CONTEXTS_TO_LOG) {
            //fprintf(gTraceFile, "\n======= (%f) %% ======\n", (*listIt).frequency * 100.0 / grandTotalRedundantBytes);
            fprintf(gTraceFile, "\n======= (%f) %% of total Redundant, with local redundant %f %% (%ld Zeros / %ld Reads) ======\n",
                (*listIt).all0freq * 100.0 / grandTotalRedundantBytes,
                (*listIt).all0freq * 100.0 / (*listIt).ftot,
                (*listIt).all0freq,(*listIt).ftot); 
                // (*listIt).frequency * 100.0 / grandTotalRedundantBytes,
                // (*listIt).frequency * 100.0 / (*listIt).ltot,
                // (*listIt).frequency,(*listIt).ltot);
            // fprintf(gTraceFile, "\n\n======= with All Zero Redundant %f %% (%ld / %ld) ======\n", 
            //     (*listIt).all0freq * 100.0 / (*listIt).ftot,
            //     (*listIt).all0freq,(*listIt).ftot);
#ifndef NO_APPROXMAP
            fprintf(gTraceFile, "\n======= Redundant byte map : [mantiss | exponent | sign] ========\n");
#ifdef BIG_ENDIAN
            if((*listIt).size==4) {
                fprintf(gTraceFile, ((*listIt).byteMapMan & (4))?"00 ":"XX ");
                fprintf(gTraceFile, ((*listIt).byteMapMan & (2))?"00 ":"XX ");
                fprintf(gTraceFile, ((*listIt).byteMapMan & (1))?"00 | ":"XX | ");
                fprintf(gTraceFile, ((*listIt).byteMapExp & (1))?"00 | ":"XX | ");
                fprintf(gTraceFile, ((*listIt).byteMapSign & (1))?"0 ":"X ");
                for(uint32_t i=1;i<(*listIt).accessLen/4;i++) {
                    fprintf(gTraceFile, " , ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (4<<(3*i)))?"00 ":"XX ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (2<<(3*i)))?"00 ":"XX ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (1<<(3*i)))?"00 | ":"XX | ");
                    fprintf(gTraceFile, ((*listIt).byteMapExp & (1<<(i)))?"00 | ":"XX | ");
                    fprintf(gTraceFile, ((*listIt).byteMapSign & (1<<i))?"0 ":"X ");
                }
            } else {
                fprintf(gTraceFile, ((*listIt).byteMapMan & (64))?"00 ":"XX ");
                fprintf(gTraceFile, ((*listIt).byteMapMan & (32))?"00 ":"XX ");
                fprintf(gTraceFile, ((*listIt).byteMapMan & (16))?"00 ":"XX ");
                fprintf(gTraceFile, ((*listIt).byteMapMan & (8))?"00 ":"XX ");
                fprintf(gTraceFile, ((*listIt).byteMapMan & (4))?"00 ":"XX ");
                fprintf(gTraceFile, ((*listIt).byteMapMan & (2))?"00 ":"XX ");
                fprintf(gTraceFile, ((*listIt).byteMapMan & (1))?"00 | ":"XX | ");
                fprintf(gTraceFile, ((*listIt).byteMapExp & (2))?"00 ":"XX ");
                fprintf(gTraceFile, ((*listIt).byteMapExp & (1))?"00 | ":"XX | ");
                fprintf(gTraceFile, ((*listIt).byteMapSign & (1))?"0 ":"X ");
                for(uint32_t i=1;i<(*listIt).accessLen/8;i++) {
                    fprintf(gTraceFile, " , ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (64<<(7*i)))?"00 ":"XX ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (32<<(7*i)))?"00 ":"XX ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (16<<(7*i)))?"00 ":"XX ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (8<<(7*i)))?"00 ":"XX ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (4<<(7*i)))?"00 ":"XX ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (2<<(7*i)))?"00 ":"XX ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (1<<(7*i)))?"00 | ":"XX | ");
                    fprintf(gTraceFile, ((*listIt).byteMapExp & (2<<(2*i)))?"00 ":"XX ");
                    fprintf(gTraceFile, ((*listIt).byteMapExp & (1<<(2*i)))?"00 | ":"XX | ");
                    fprintf(gTraceFile, ((*listIt).byteMapSign & (1<<i))?"0 ":"X ");
                }
            }
#else
            if((*listIt).size==4) {
                fprintf(gTraceFile, ((*listIt).byteMapMan & (1))?"00 ":"XX ");
                fprintf(gTraceFile, ((*listIt).byteMapMan & (2))?"00 ":"XX ");
                fprintf(gTraceFile, ((*listIt).byteMapMan & (4))?"00 | ":"XX | ");
                fprintf(gTraceFile, ((*listIt).byteMapExp & (1))?"00 | ":"XX | ");
                fprintf(gTraceFile, ((*listIt).byteMapSign & (1))?"0 ":"X ");
                for(uint32_t i=1;i<(*listIt).accessLen/4;i++) {
                    fprintf(gTraceFile, " , ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (1<<(3*i)))?"00 ":"XX ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (2<<(3*i)))?"00 ":"XX ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (4<<(3*i)))?"00 | ":"XX | ");
                    fprintf(gTraceFile, ((*listIt).byteMapExp & (2<<(i)))?"00 | ":"XX | ");
                    fprintf(gTraceFile, ((*listIt).byteMapSign & (1<<i))?"0 ":"X ");
                }
            } else {
                fprintf(gTraceFile, ((*listIt).byteMapMan & (1))?"00 ":"XX ");
                fprintf(gTraceFile, ((*listIt).byteMapMan & (2))?"00 ":"XX ");
                fprintf(gTraceFile, ((*listIt).byteMapMan & (4))?"00 ":"XX ");
                fprintf(gTraceFile, ((*listIt).byteMapMan & (8))?"00 ":"XX ");
                fprintf(gTraceFile, ((*listIt).byteMapMan & (16))?"00 ":"XX ");
                fprintf(gTraceFile, ((*listIt).byteMapMan & (32))?"00 ":"XX ");
                fprintf(gTraceFile, ((*listIt).byteMapMan & (64))?"00 | ":"XX | ");
                fprintf(gTraceFile, ((*listIt).byteMapExp & (1))?"00 ":"XX ");
                fprintf(gTraceFile, ((*listIt).byteMapExp & (2))?"00 | ":"XX | ");
                fprintf(gTraceFile, ((*listIt).byteMapSign & (1))?"0 ":"X ");
                for(uint32_t i=1;i<(*listIt).accessLen/8;i++) {
                    fprintf(gTraceFile, " , ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (1<<(7*i)))?"00 ":"XX ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (2<<(7*i)))?"00 ":"XX ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (4<<(7*i)))?"00 ":"XX ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (8<<(7*i)))?"00 ":"XX ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (16<<(7*i)))?"00 ":"XX ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (32<<(7*i)))?"00 ":"XX ");
                    fprintf(gTraceFile, ((*listIt).byteMapMan & (64<<(7*i)))?"00 | ":"XX | ");
                    fprintf(gTraceFile, ((*listIt).byteMapExp & (1<<(2*i)))?"00 ":"XX ");
                    fprintf(gTraceFile, ((*listIt).byteMapExp & (2<<(2*i)))?"00 | ":"XX | ");
                    fprintf(gTraceFile, ((*listIt).byteMapSign & (1<<i))?"0 ":"X ");
                }
            }
#endif
#endif
            fprintf(gTraceFile, "\n===== [AccessLen=%d, typesize=%d] =======\n", (*listIt).accessLen, (*listIt).size);
            fprintf(gTraceFile, "\n---------------------Redundant load with---------------------------\n");
            //PrintFullCallingContext((*listIt).kill);
            PrintFullCallingContext((*listIt).cntxt);
        }
        else {
            break;
        }
        cntxtNum++;
    }
    fprintf(gTraceFile, "\n------------ Dumping Approximation Redundancy Info Finish -------------\n");
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
    if (RedMap[threadid].empty() && ApproxRedMap[threadid].empty()) return;
    printf("Now locking client for updating...\n");
    fflush(stdout);
    // Update gTotalInstCount first
    PIN_LockClient();
    printf("Client locked, now generate report\n");
    fflush(stdout);
    PrintRedundancyPairs(threadid);
    printf("Generate Floating point report\n");
    fflush(stdout);
    PrintApproximationRedundancyPairs(threadid);
    printf("all generated\n");
    fflush(stdout);
#ifdef USE_COLLECT_PAGE_CACHE
    PrintPageRedundancy(threadid);
    PrintCacheRedundancy(threadid);
#endif
    PIN_UnlockClient();
    printf("Unlocked\n");
    fflush(stdout);
    // clear redmap now
    RedMap[threadid].clear();
    ApproxRedMap[threadid].clear();
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
                redReadTmp += (*it).second.red;
            }
        }
        unordered_map<uint64_t, ApproxRedLogs>::iterator ait;
        if(!ApproxRedMap[i].empty()){
            for (ait = ApproxRedMap[i].begin(); ait != ApproxRedMap[i].end(); ++ait) {
                approxRedReadTmp += (*ait).second.fred;
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
    ApproxRedMap[threadid].rehash(10000000);
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

