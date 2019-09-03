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

#define SKIP_SMALL_VARS
#ifdef SKIP_SMALL_VARS
#define SMALL_VAR_THRESHOLD 16
#endif

//enable Data-centric
#define USE_TREE_BASED_FOR_DATA_CENTRIC
#define USE_TREE_WITH_ADDR
//#define USE_SHADOW_FOR_DATA_CENTRIC
//#define USE_ADDR_RANGE
#include "cctlib.H"

#define OBJTYPE2STRING(t) ((t==DYNAMIC_OBJECT)?"DYNAMIC":((t==STATIC_OBJECT)?"STATIC":((t==STACK_OBJECT)?"STACK":"UNKNOWN")))
#define SYMNAME2STRING(t,s) ((t==DYNAMIC_OBJECT)?"DYNAMIC":((t==STATIC_OBJECT)?GetStringFromStringPool(s):((t==STACK_OBJECT)?"STACK":"UNKNOWN")))

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
//#define MAX_REDUNDANT_CONTEXTS_TO_LOG (1000)
#define MAX_OBJS_TO_LOG 100
#define MAX_REDUNDANT_CONTEXTS_PER_OBJ_TO_LOG 10
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

#define MAKE_OBJID(a, b) (((uint64_t)(a)<<32) | (b))
#define DECODE_TYPE(a) (((uint64_t)(a)&(0xffffffffffffffff))>>32)
#define DECODE_NAME(b) ((uint64_t)(b)&(0x00000000ffffffff))

#define MAKE_CNTXT(a, b, c) (((uint64_t)(a)<<32) | ((uint64_t)(b)<<16) | (uint64_t)(c))
#define DECODE_CNTXT(a) (static_cast<ContextHandle_t>((((a)&(0xffffffffffffffff))>>32)))
#define DECODE_ACCLN(b) (((uint64_t)(b)&(0x00000000ffff0000))>>16)
#define DECODE_TYPSZ(c)  ((uint64_t)(c)&(0x000000000000ffff))

#define delta 0.01

#define CACHE_LINE_SIZE (64)
#define PAGE_SIZE (4*1024)


/***********************************************
 ******  shadow memory
 ************************************************/
//ConcurrentShadowMemory<uint8_t, DataHandle_t> sm;

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
    char name[MAX_FILE_PATH] = "zeroLoad.dataCentric.out.";
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

#define DATA_STATE_NOT_VISIT 0
#define DATA_STATE_ONLY_ZERO 1
#define DATA_STATE_NOT_ZERO  2

struct RedLogs{
    uint64_t red;  // how many byte zero
    uint64_t tot;
    uint64_t beg_addr;
    uint64_t end_addr;
    //unordered_map<uint32_t, uint32_t> red_addr; // first : addr, second : bytemap
    vector<uint8_t> state;
};

static unordered_map<uint64_t, RedLogs> RedMap[THREAD_MAX];
static unordered_map<uint64_t, RedLogs> ApproxRedMap[THREAD_MAX];

static inline void AddToRedTable(uint32_t addr, DataHandle_t data, ContextHandle_t cntxt, uint16_t value, uint16_t total, uint8_t redmap[32], uint32_t typesz, THREADID threadId) __attribute__((always_inline,flatten));
static inline void AddToRedTable(uint32_t addr, DataHandle_t data, ContextHandle_t cntxt, uint16_t value, uint16_t total, uint8_t redmap[32], uint32_t typesz, THREADID threadId) {
#ifdef MULTI_THREADED
    LOCK_RED_MAP();
#endif
    uint64_t key = MAKE_OBJID(data.objectType,data.symName);
    unordered_map<uint64_t, RedLogs>::iterator it = RedMap[threadId].find(key);
    if ( it  == RedMap[threadId].end() ) {
        RedLogs log;
        log.red = value;
        log.beg_addr = data.beg_addr;
        log.end_addr = data.end_addr;
        log.tot = typesz;
        RedMap[threadId][key] = log;
        RedMap[threadId][key].state.resize(data.end_addr-data.beg_addr,DATA_STATE_NOT_VISIT);
        #pragma unroll
        for(int i=0;i<total;++i)
            RedMap[threadId][key].state[addr+i]=redmap[i];
    } else {
        it->second.red += value;
        #pragma unroll
        for(int i=0;i<total;++i)
            it->second.state[addr+i]|=redmap[i];
        // unordered_map<uint32_t, uint32_t>::iterator it3 = it->second.red_addr.find(addr);
        // if(it3 == it->second.red_addr.end())
        //     it->second.red_addr[addr]  = redmap;
        // else
        //     it->second.red_addr[addr] &= redmap;
    }
#ifdef MULTI_THREADED
    UNLOCK_RED_MAP();
#endif
}

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

static inline void AddToApproximateRedTable(uint32_t addr, DataHandle_t data, ContextHandle_t cntxt, uint16_t value, uint16_t total, uint8_t redmap[32], uint32_t typesz, THREADID threadId) __attribute__((always_inline,flatten));
static inline void AddToApproximateRedTable(uint32_t addr, DataHandle_t data, ContextHandle_t cntxt, uint16_t value, uint16_t total, uint8_t redmap[32], uint32_t typesz, THREADID threadId) {
#ifdef MULTI_THREADED
    LOCK_RED_MAP();
#endif
    //printf("Enter %d %d %d %d, %ld\n",addr,value,total,typesz,data.end_addr-data.beg_addr);
    uint64_t key = MAKE_OBJID(data.objectType,data.symName);
    unordered_map<uint64_t, RedLogs>::iterator it = ApproxRedMap[threadId].find(key);
    if(value > total) {
        cerr << "** Warning AddToApproximateTable : value " << value << ", total " << total << " **" << endl;
        assert(0 && "** BUG #0 Detected. Existing **");
    }
    if ( it  == ApproxRedMap[threadId].end() ) {
        RedLogs log;
        log.red = value;
        log.beg_addr = data.beg_addr;
        log.end_addr = data.end_addr;
        log.tot = typesz;
        //printf("+++ insert finish\n");
        ApproxRedMap[threadId][key] = log;
        //printf("+++ RESIZE : %ld\n",data.end_addr-data.beg_addr);
        ApproxRedMap[threadId][key].state.resize(data.end_addr-data.beg_addr,DATA_STATE_NOT_VISIT);
        //printf("+++ RESIZE FINISH\n");
        #pragma unroll
        for(int i=0;i<total;i+=typesz)
            ApproxRedMap[threadId][key].state[addr+i]=redmap[i];
        //printf("+++ state finish\n");
    } else {
        it->second.red += value;
        #pragma unroll
        for(int i=0;i<total;i+=typesz)
            it->second.state[addr+i]|=redmap[i];
        // unordered_map<uint32_t, uint32_t>::iterator it3 = it->second.red_addr.find(addr);
        // if(it3 == it->second.red_addr.end())
        //     it->second.red_addr[addr]  = redmap;
        // else
        //     it->second.red_addr[addr] &= redmap;
    }
    //printf("Exit\n");
    //fflush(stdout);
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
/*
template<int start, int end, int incr, bool conditional, bool approx>
struct UnrolledLoop{
    static __attribute__((always_inline)) void Body(function<void (const int)> func){
        func(start); // Real loop body
        UnrolledLoop<start+incr, end, incr, conditional, approx>:: Body(func);   // unroll next iteration
    }
    static __attribute__((always_inline)) void BodyStraddlePage(uint64_t addr, const DataHandle_t handle, const ContextHandle_t cntxt, THREADID threadId){        
        if (conditional) {
            // report in RedTable
            if(approx)
                AddToApproximateRedTable(addr, handle, cntxt, 0, 1, 0, threadId);
            else
                AddToRedTable(addr, handle, cntxt, 0, 1, 0, threadId);
        }
        UnrolledLoop<start+incr, end, incr, conditional, approx>:: BodyStraddlePage(addr, handle, cntxt, threadId);   // unroll next iteration
    }
};

template<int end,  int incr, bool conditional, bool approx>
struct UnrolledLoop<end , end , incr, conditional, approx>{
    static __attribute__((always_inline)) void Body(function<void (const int)> func){}
    static __attribute__((always_inline)) void BodyStraddlePage(uint64_t addr, const DataHandle_t handle, const ContextHandle_t cntxt, THREADID threadId){}
};
*/
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
    static __attribute__((always_inline)) void BodyByteMap(uint8_t* addr, uint8_t redmap[32]){
        redmap[start] = addr[start]==0?DATA_STATE_ONLY_ZERO:DATA_STATE_NOT_ZERO;
        UnrolledConjunction<start+incr, end, incr>:: BodyByteMap(addr,redmap);   // unroll next iteration
    }
    static __attribute__((always_inline)) void BodyByteMapApprox(uint8_t* addr, uint8_t redmap[32]){
        if(incr==4) {
            redmap[start] = (*(reinterpret_cast<float_cast*>(&addr[start]))).vars.value==0?DATA_STATE_ONLY_ZERO:DATA_STATE_NOT_ZERO;
        } else {
            redmap[start] = (*(reinterpret_cast<double_cast*>(&addr[start]))).vars.value==0?DATA_STATE_ONLY_ZERO:DATA_STATE_NOT_ZERO;
        }
        UnrolledConjunction<start+incr, end, incr>:: BodyByteMapApprox(addr,redmap);   // unroll next iteration
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
    static __attribute__((always_inline)) void BodyByteMap(uint8_t* addr, uint8_t redmap[32]){
        return ;
    }
    static __attribute__((always_inline)) void BodyByteMapApprox(uint8_t* addr, uint8_t redmap[32]){
        return ;
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
//#define DEBUG_ZEROSPY_SPATIAL
template<class T, uint32_t AccessLen, bool isApprox>
struct ZeroSpyAnalysis{
    static __attribute__((always_inline)) void getRedMap(void * addr, uint8_t redbyteMap[32]){
        if(isApprox){
            uint8_t* bytes = static_cast<uint8_t*>(addr);
            UnrolledConjunction<0,AccessLen,sizeof(T)>::BodyByteMapApprox(bytes, redbyteMap);
        }else{
            uint8_t* bytes = static_cast<uint8_t*>(addr);
            UnrolledConjunction<0,AccessLen,1>::BodyByteMap(bytes, redbyteMap);
        }
    }
    static __attribute__((always_inline)) uint64_t getRedNum(void * addr){
        if(isApprox){
            uint8_t* bytes = static_cast<uint8_t*>(addr);
            uint32_t rednum = UnrolledCount<0,AccessLen,sizeof(T)>::BodyRedZero(bytes);
            return rednum;
        }else{
            uint8_t* bytes = static_cast<uint8_t*>(addr);
            uint32_t rednum = UnrolledCount<0,AccessLen,sizeof(T)>::BodyRedZero(bytes);
            return rednum;
        }
        return 0;
    }
    static __attribute__((always_inline)) VOID CheckNByteValueAfterRead(void* addr, uint32_t opaqueHandle, THREADID threadId){
#ifdef DEBUG_ZEROSPY_SPATIAL
        printf("\n In CheckNByteValueAfterRead Begin : %p %d %d\n", addr,opaqueHandle, threadId);
#endif
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        ContextHandle_t curCtxt = GetContextHandle(threadId,opaqueHandle);
        DataHandle_t curDataHandle = GetDataObjectHandle(addr, threadId);
        if(curDataHandle.objectType!=DYNAMIC_OBJECT && curDataHandle.objectType!=STATIC_OBJECT) {
            return;
        }
#ifdef SKIP_SMALL_VARS
        // if it is a small var, skip logging
        if(curDataHandle.end_addr-curDataHandle.beg_addr<=SMALL_VAR_THRESHOLD) return;
#endif
        uint32_t redbyteNum = getRedNum(addr);
        uint8_t redbyteMap[32] = {0};
        if(redbyteNum) getRedMap(addr, redbyteMap);
        else memset(redbyteMap,DATA_STATE_NOT_ZERO,32);
        if(isApprox)
            AddToApproximateRedTable((uint32_t)((uint64_t)addr-curDataHandle.beg_addr),curDataHandle,curCtxt,redbyteNum,AccessLen,redbyteMap,sizeof(T),threadId);
        else
            AddToRedTable((uint32_t)((uint64_t)addr-curDataHandle.beg_addr),curDataHandle,curCtxt,redbyteNum,AccessLen,redbyteMap,sizeof(T),threadId);
#ifdef DEBUG_ZEROSPY_SPATIAL
        printf("\n In CheckNByteValueAfterRead Finish \n");
#endif
    }
};


static inline VOID CheckAfterLargeRead(void* addr, UINT32 accessLen, uint32_t opaqueHandle, THREADID threadId){
#ifdef DEBUG_ZEROSPY_SPATIAL
    printf("\n In CheckAfterLargeRead Begin : %p %d %d %d\n", addr,accessLen, opaqueHandle, threadId);    
#endif
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    ContextHandle_t curCtxt = GetContextHandle(threadId, opaqueHandle);
    DataHandle_t curDataHandle = GetDataObjectHandle(addr, threadId);
    if(curDataHandle.objectType!=DYNAMIC_OBJECT && curDataHandle.objectType!=STATIC_OBJECT) {
        return;
    }
#ifdef SKIP_SMALL_VARS
    // if it is a small var, skip logging
    if(curDataHandle.end_addr-curDataHandle.beg_addr<=SMALL_VAR_THRESHOLD) return;
#endif
    uint8_t* bytes = static_cast<uint8_t*>(addr);
    uint32_t redbyteNum = 0;
    uint8_t redbyteMap[32] = {0};
    for(int i=accessLen-1;i>=0;--i) {
        if(bytes[i]!=0) {
            break;
        }
        ++redbyteNum;
    }
    if(redbyteNum) {
        for(UINT32 i=0;i<accessLen;++i) {
            if(bytes[i]==0) 
                redbyteMap[i] |= DATA_STATE_ONLY_ZERO;
            else 
                redbyteMap[i] |= DATA_STATE_NOT_ZERO;
        }
        // report in RedTable
        AddToRedTable((uint32_t)((uint64_t)addr-curDataHandle.beg_addr),curDataHandle,curCtxt,redbyteNum,accessLen,redbyteMap,accessLen,threadId);
    }
#ifdef DEBUG_ZEROSPY_SPATIAL
        printf("\n In CheckAfterLargeRead Finish \n");
#endif
}
#undef DEBUG_ZEROSPY_SPATIAL

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
    else if(INS_IsPrefetch(ins)) // Prefetch instructions might access addresses which are invalid.
        return true;
    return false;
}

static VOID InstrumentInsCallback(INS ins, VOID* v, const uint32_t opaqueHandle) {
    if (!INS_HasFallThrough(ins)) return;
    if (INS_IsIgnorable(ins))return;
    if (INS_IsBranchOrCall(ins) || INS_IsRet(ins)) return;
    //printf("\n In InstrumentInsCallback Begin \n");
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
    //printf("\n In InstrumentInsCallback Finished \n");
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
    //printf("\nUpdate Begin\n");
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    tData->bytesLoad += bytes;
    //printf("\nUpdate Finish\n");
}

//instrument the trace, count the number of ins in the trace, decide to instrument or not
static void InstrumentTrace(TRACE trace, void* f) {
    //printf("\nInstrumentTrace Begin\n");
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
    //printf("\nInstrumentTrace Finish\n");
}

#endif

// redundant data for a object
struct ObjRedundancy {
    uint64_t objID;
    uint64_t bytes;
    uint64_t dsize;
    uint64_t typesz;
};

static inline bool ObjRedundancyCompare(const struct ObjRedundancy &first, const struct ObjRedundancy &second) {
    return first.bytes > second.bytes ? true : false;
}

static inline void PrintSize(uint64_t size, char unit='B') {
    if(size >= (1<<20)) {
        fprintf(gTraceFile, "%lf M%c",(double)size/(double)(1<<20),unit);
    } else if(size >= (1<<10)) {
        fprintf(gTraceFile, "%lf K%c",(double)size/(double)(1<<10),unit);
    } else {
        fprintf(gTraceFile, "%ld %c",size,unit);
    }
}

#define MAX_REDMAP_PRINT_SIZE 128
// only print top 5 redundancy with full redmap to file
#define MAX_PRINT_FULL 5

static void PrintRedundancyPairs(THREADID threadId) {
    vector<ObjRedundancy> tmpList;
    
    uint64_t grandTotalRedundantBytes = 0;
    fprintf(gTraceFile, "\n--------------- Dumping Data Redundancy Info ----------------\n");
    fprintf(gTraceFile, "\n*************** Dump Data from Thread %d ****************\n", threadId);

    int count=0;
    int rep=-1;
    int total = RedMap[threadId].size();
    for(unordered_map<uint64_t, RedLogs>::iterator it = RedMap[threadId].begin(); it != RedMap[threadId].end(); ++it) {
        ++count;
        if(100 * count / total!=rep) {
            rep = 100 * count / total;
            printf("Stage 1 : %d%%  Finish\n",rep);
            fflush(stdout);
        }
        grandTotalRedundantBytes += (*it).second.red;
        ObjRedundancy tmp = {(*it).first, (*it).second.red, (*it).second.end_addr-(*it).second.beg_addr,(*it).second.tot};
        tmpList.push_back(tmp); 
    }

    __sync_fetch_and_add(&grandTotBytesRedLoad,grandTotalRedundantBytes);
    fprintf(gTraceFile, "\n Total redundant bytes = %f %%\n", grandTotalRedundantBytes * 100.0 / ClientGetTLS(threadId)->bytesLoad);
    sort(tmpList.begin(), tmpList.end(), ObjRedundancyCompare);

    int objNum = 0;
    rep = -1;
    total = tmpList.size()<MAX_OBJS_TO_LOG?tmpList.size():MAX_OBJS_TO_LOG;
    for(vector<ObjRedundancy>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if(objNum++ >= MAX_OBJS_TO_LOG) break;
        if(100 * objNum / total!=rep) {
            rep = 100 * count / total;
            printf("Stage 2 : %d%%  Finish\n",rep);
            fflush(stdout);
        }
        if((uint8_t)DECODE_TYPE((*listIt).objID) == DYNAMIC_OBJECT) {
            fprintf(gTraceFile, "\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Dynamic Object: ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
            PrintFullCallingContext(DECODE_NAME((*listIt).objID)); // segfault might happen if the shadow memory based data centric is used
        } else  
            fprintf(gTraceFile, "\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Static Object: %s ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", GetStringFromStringPool((uint32_t)DECODE_NAME((*listIt).objID)));

        fprintf(gTraceFile, "\n\n==========================================\n");
        fprintf(gTraceFile, "Redundancy Ratio = %f %% (%ld Bytes)\n", (*listIt).bytes * 100.0 / grandTotalRedundantBytes, (*listIt).bytes);

        uint64_t dfreq = 0;
        uint64_t dread = 0;
        for(vector<uint8_t>::iterator addrIt = RedMap[threadId][(*listIt).objID].state.begin(); addrIt != RedMap[threadId][(*listIt).objID].state.end(); ++addrIt) {
            if(*addrIt == DATA_STATE_ONLY_ZERO) dfreq++;
            if(*addrIt) dread++;
        }
            
        fprintf(gTraceFile, "\n\n======= DATA SIZE : ");
        PrintSize((*listIt).dsize);
        fprintf(gTraceFile, "( Not Accessed Data %f %% (%ld Bytes), Redundant Data %f %% (%ld Bytes) )", 
                ((*listIt).dsize-dread) * 100.0 / (*listIt).dsize, (*listIt).dsize-dread, 
                dfreq * 100.0 / (*listIt).dsize, dfreq);

        fprintf(gTraceFile, "\n======= Redundant byte map : [0] ");
        uint32_t num=0;
        for(vector<uint8_t>::iterator addrIt = RedMap[threadId][(*listIt).objID].state.begin(); addrIt != RedMap[threadId][(*listIt).objID].state.end(); ++addrIt) {
            switch(*addrIt) {
                case DATA_STATE_NOT_VISIT:
                    fprintf(gTraceFile, "?? ");
                    break;
                case DATA_STATE_ONLY_ZERO:
                    fprintf(gTraceFile, "00 ");
                    break;
                default:
                    fprintf(gTraceFile, "XX ");
                    break;
            }
            ++num;
            if(num>MAX_REDMAP_PRINT_SIZE) {
                fprintf(gTraceFile, "... ");
                break;
            }
        }
        if(objNum<=MAX_PRINT_FULL) {
            char fn[50] = {};
            sprintf(fn,"%lx.redmap",(*listIt).objID);
            FILE* fp = fopen(fn,"w");
            if((uint8_t)DECODE_TYPE((*listIt).objID) == DYNAMIC_OBJECT) {
                fprintf(fp, "\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Dynamic Object: ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
                PrintFullCallingContext(DECODE_NAME((*listIt).objID)); // segfault might happen if the shadow memory based data centric is used
            } else  
                fprintf(fp, "\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Static Object: %s ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n", GetStringFromStringPool((uint32_t)DECODE_NAME((*listIt).objID)));
            for(vector<uint8_t>::iterator addrIt = RedMap[threadId][(*listIt).objID].state.begin(); addrIt != RedMap[threadId][(*listIt).objID].state.end(); ++addrIt) {
                switch(*addrIt) {
                    case DATA_STATE_NOT_VISIT:
                        fprintf(fp, "?");
                        break;
                    case DATA_STATE_ONLY_ZERO:
                        fprintf(fp, "0");
                        break;
                    default:
                        fprintf(fp, "X");
                        break;
                }
            }
        }
    }
    fprintf(gTraceFile, "\n------------ Dumping Redundancy Info Finish -------------\n");
}

// TODO : redundant bytes rates are abnormal, need debugging
static void PrintApproximationRedundancyPairs(THREADID threadId) {
    vector<ObjRedundancy> tmpList;
    
    uint64_t grandTotalRedundantBytes = 0;
    fprintf(gTraceFile, "\n--------------- Dumping Data Approximation Redundancy Info ----------------\n");
    fprintf(gTraceFile, "\n*************** Dump Data(delta=%.2f%%) from Thread %d ****************\n", delta*100,threadId);

    for(unordered_map<uint64_t, RedLogs>::iterator it = ApproxRedMap[threadId].begin(); it != ApproxRedMap[threadId].end(); ++it) {
        grandTotalRedundantBytes += (*it).second.red;
        ObjRedundancy tmp = {(*it).first, (*it).second.red, (*it).second.end_addr-(*it).second.beg_addr,(*it).second.tot};
        tmpList.push_back(tmp); 
    }

    __sync_fetch_and_add(&grandTotBytesApproxRedLoad,grandTotalRedundantBytes);

    fprintf(gTraceFile, "\n Total redundant bytes = %f %%\n", grandTotalRedundantBytes * 100.0 / ClientGetTLS(threadId)->bytesLoad);
    sort(tmpList.begin(), tmpList.end(), ObjRedundancyCompare);

    int objNum = 0;
    for(vector<ObjRedundancy>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if(objNum++ >= MAX_OBJS_TO_LOG) break;
        if((uint8_t)DECODE_TYPE((*listIt).objID) == DYNAMIC_OBJECT) {
            fprintf(gTraceFile, "\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Dynamic Object: ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
            PrintFullCallingContext(DECODE_NAME((*listIt).objID)); // segfault might happen if the shadow memory based data centric is used
        } else  
            fprintf(gTraceFile, "\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Static Object: %s ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", GetStringFromStringPool((uint32_t)DECODE_NAME((*listIt).objID)));

        fprintf(gTraceFile, "\n\n==========================================\n");
        fprintf(gTraceFile, "Redundancy Ratio = %f %% (%ld Bytes)\n", (*listIt).bytes * 100.0 / grandTotalRedundantBytes, (*listIt).bytes);

        uint64_t dfreq = 0;
        uint64_t dread = 0;
        for(vector<uint8_t>::iterator addrIt = ApproxRedMap[threadId][(*listIt).objID].state.begin(); addrIt != ApproxRedMap[threadId][(*listIt).objID].state.end(); ++addrIt) {
            if(*addrIt == DATA_STATE_ONLY_ZERO) dfreq+=(*listIt).typesz;
            if(*addrIt) dread+=(*listIt).typesz;
        }
            
        fprintf(gTraceFile, "\n\n======= DATA SIZE : ");
        PrintSize((*listIt).dsize);
        fprintf(gTraceFile, "( Not Accessed Data %f %% (%ld Bytes), Redundant Data %f %% (%ld Bytes) )", 
                ((*listIt).dsize-dread) * 100.0 / (*listIt).dsize, (*listIt).dsize-dread, 
                dfreq * 100.0 / (*listIt).dsize, dfreq);

        fprintf(gTraceFile, "\n======= Redundant byte map : [0] ");
        uint32_t num=0;
        for(uint32_t i=0; i < ApproxRedMap[threadId][(*listIt).objID].state.size(); i+=(*listIt).typesz) {
            switch(ApproxRedMap[threadId][(*listIt).objID].state[i]) {
                case DATA_STATE_NOT_VISIT:
                    fprintf(gTraceFile, "?? ");
                    break;
                case DATA_STATE_ONLY_ZERO:
                    fprintf(gTraceFile, "00 ");
                    break;
                default:
                    fprintf(gTraceFile, "XX ");
                    break;
            }
            ++num;
            if(num>MAX_REDMAP_PRINT_SIZE) {
                fprintf(gTraceFile, "... ");
                break;
            }
        }
        if(objNum<=MAX_PRINT_FULL) {
            char fn[50] = {};
            sprintf(fn,"%lx.redmap",(*listIt).objID);
            FILE* fp = fopen(fn,"w");
            if((uint8_t)DECODE_TYPE((*listIt).objID) == DYNAMIC_OBJECT) {
                fprintf(fp, "\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Dynamic Object: %lx^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n",(*listIt).objID);
            } else  
                fprintf(fp, "\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Static Object: %s, %lx ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n", GetStringFromStringPool((uint32_t)DECODE_NAME((*listIt).objID)),(*listIt).objID);
            for(uint32_t i=0; i < ApproxRedMap[threadId][(*listIt).objID].state.size(); i+=(*listIt).typesz) {
                switch(ApproxRedMap[threadId][(*listIt).objID].state[i]) {
                    case DATA_STATE_NOT_VISIT:
                        fprintf(fp, "?? ");
                        break;
                    case DATA_STATE_ONLY_ZERO:
                        fprintf(fp, "00 ");
                        break;
                    default:
                        fprintf(fp, "XX ");
                        break;
                }
            }
        }
    }
    fprintf(gTraceFile, "\n------------ Dumping Approx Redundancy Info Finish -------------\n");
}
// On each Unload of a loaded image, the accummulated redundancy information is dumped
static VOID ImageUnload(IMG img, VOID* v) {
    printf("==== PIN CLIENT ZEROSPY : Unloading %s, now collecting analysis data ===\n",IMG_Name(img).c_str());
    fprintf(gTraceFile, "\n TODO .. Multi-threading is not well supported.");
    THREADID  threadid =  PIN_ThreadId();
    fprintf(gTraceFile, "\nUnloading %s", IMG_Name(img).c_str());
    if (RedMap[threadid].empty() && ApproxRedMap[threadid].empty()) return;
    // Update gTotalInstCount first
    PIN_LockClient();
    printf("==== PIN CLIENT ZEROSPY : Print Redundancy info ... ===\n");
    PrintRedundancyPairs(threadid);
    printf("==== PIN CLIENT ZEROSPY : Print Approximation Redundancy info ... ===\n");
    PrintApproximationRedundancyPairs(threadid);
#ifdef PRINT_MEM_INFO
    printf("==== PIN CLIENT ZEROSPY : Print Cacheline Redundancy info ... ===\n");
    PrintMemoryRedundancy<CACHE_LINE_SIZE>("Cacheline", threadid);
    printf("==== PIN CLIENT ZEROSPY : Print Page Redundancy info ... ===\n");
    PrintMemoryRedundancy<PAGE_SIZE>("Page", threadid);
#endif
    PIN_UnlockClient();
    // clear redmap now
    RedMap[threadid].clear();
    ApproxRedMap[threadid].clear();
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
    for(int i = 0; i < THREAD_MAX; ++i) {
        if(!RedMap[i].empty()) {
            for(unordered_map<uint64_t, RedLogs>::iterator it = RedMap[i].begin(); it != RedMap[i].end(); ++it) {
                redReadTmp += (*it).second.red;
            }
        }
        if(!ApproxRedMap[i].empty()) {
            for(unordered_map<uint64_t, RedLogs>::iterator it = ApproxRedMap[i].begin(); it != ApproxRedMap[i].end(); ++it) {
                approxRedReadTmp += (*it).second.red;
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
    fprintf(gTraceFile, "\nInit Thread Data Finish\n");
/*    for (int i = 0; i < THREAD_MAX; ++i) {
        RedMap[i].set_empty_key(0);
        ApproxRedMap[i].set_empty_key(0);
    }
*/
}

static VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    RedSpyThreadData* tdata = (RedSpyThreadData*)memalign(32,sizeof(RedSpyThreadData));
    InitThreadData(tdata);
    //    __sync_fetch_and_add(&gClientNumThreads, 1);
    PIN_SetThreadData(client_tls_key, tdata, threadid);
#ifdef MULTI_THREADED
    PIN_SetThreadData(client_tls_key, tdata, threadid);
#else
    gSingleThreadedTData = tdata;
#endif
    fprintf(gTraceFile, "\nInit ThreadStart Finish\n");
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
    PinCCTLibInit(INTERESTING_INS_ALL, gTraceFile, InstrumentInsCallback, 0,/*Do data centric work*/true);

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
    printf("==== PIN CLIENT : Launch program now ===\n");
    // Launch program now
    PIN_StartProgram();
    return 0;
}

