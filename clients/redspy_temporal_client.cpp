// @COPYRIGHT@
// Licensed under MIT license.
// See LICENSE.TXT file in the project root for more information.
// ==============================================================

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
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

#define MAX_ALIAS_REGS (16)  //EAX, EBX, ECX, EDX, EBP, EDI, ESI, ESP, R8-R15
#define MAX_ALIAS_REG_SIZE (8) //RAX is 64bits
#define MAX_ALIAS_TYPE (3) //(RAX, EAX, AX),(AH),(AL)

//different register group
enum AliasReg {
    ALIAS_REG_A = 0, //RAX, EAX, AX, AH, or AL
    ALIAS_REG_B,
    ALIAS_REG_C,
    ALIAS_REG_D,
    ALIAS_REG_BP,
    ALIAS_REG_DI,
    ALIAS_REG_SI,
    ALIAS_REG_SP,
    ALIAS_REG_R8,
    ALIAS_REG_R9,
    ALIAS_REG_R10,
    ALIAS_REG_R11,
    ALIAS_REG_R12,
    ALIAS_REG_R13,
    ALIAS_REG_R14,
    ALIAS_REG_R15};

//alias type, generic, high byte or low byte

enum AliasGroup{
    ALIAS_GENERIC=0, // RAX, EAX, or AX
    ALIAS_HIGH_BYTE, //AH
    ALIAS_LOW_BYTE // AL
};

#if __BYTE_ORDER == __LITTLE_ENDIAN
    //alias begin bytes for different types
    #define ALIAS_BYTES_INDEX_64 (0)
    #define ALIAS_BYTES_INDEX_32 (0)
    #define ALIAS_BYTES_INDEX_16 (0)
    #define ALIAS_BYTES_INDEX_8_L (0)
    #define ALIAS_BYTES_INDEX_8_H (1)

#elif __BYTE_ORDER == __BIG_ENDIAN

    #define ALIAS_BYTES_INDEX_64 (0)
    #define ALIAS_BYTES_INDEX_32 (4)
    #define ALIAS_BYTES_INDEX_16 (6)
    #define ALIAS_BYTES_INDEX_8_L (7)
    #define ALIAS_BYTES_INDEX_8_H (6)

#else

#error "unknown endianness"

#endif



#ifdef ENABLE_SAMPLING

#define WINDOW_ENABLE 1000000
#define WINDOW_DISABLE 100000000
#define WINDOW_CLEAN 10
#endif

#define DECODE_DEAD(data) static_cast<ContextHandle_t>(((data)  & 0xffffffffffffffff) >> 32 )
#define DECODE_KILL(data) (static_cast<ContextHandle_t>( (data)  & 0x00000000ffffffff))


#define MAKE_CONTEXT_PAIR(a, b) (((uint64_t)(a) << 32) | ((uint64_t)(b)))

#define delta 0.01


struct AddrValPair{
    uint8_t value[MAX_WRITE_OP_LENGTH];
    void * address;
} __attribute__((aligned(16)));

struct LargeReg{
    UINT8 value[MAX_SIMD_LENGTH];
} __attribute__((aligned(32)));

struct RedSpyThreadData{

    AddrValPair buffer[MAX_WRITE_OPS_IN_INS];
    struct LargeReg simdValue[MAX_SIMD_REGS];
    
    uint32_t regCtxt[REG_LAST];
    UINT8 regValue[REG_LAST][MAX_REG_LENGTH];
    UINT8 aliasValue[MAX_ALIAS_REGS][MAX_ALIAS_REG_SIZE];
    uint32_t aliasCtxt[MAX_ALIAS_REGS][MAX_ALIAS_TYPE];
    uint32_t simdCtxt[MAX_SIMD_REGS];
    
    uint64_t bytesWritten;
    
    long long numIns;
    bool sampleFlag;
    long long numWinds;
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

static INT32 Usage() {
    PIN_ERROR("Pin tool to gather calling context on each load and store.\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

// Main for RedSpy, initialize the tool, register instrumentation functions and call the target program.
static FILE* gTraceFile;
static  ConcurrentShadowMemory<ContextHandle_t> sm;

// Initialized the needed data structures before launching the target program
static void ClientInit(int argc, char* argv[]) {
    // Create output file
    char name[MAX_FILE_PATH] = "redspy_temporal.out.";
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

static inline VOID EmptyCtxt(RedSpyThreadData* tData){

    memset(&tData->regCtxt, 0, sizeof(uint32_t)*REG_LAST);
    memset(&tData->aliasCtxt, 0, sizeof(uint32_t)*MAX_ALIAS_REGS*MAX_ALIAS_TYPE);
    memset(&tData->regValue, 0, REG_LAST*MAX_REG_LENGTH);
    memset(&tData->aliasValue, 0, MAX_ALIAS_REGS*MAX_ALIAS_REG_SIZE);
}

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

/*********************************************************************************/
/*                              register analysis                                */
/*********************************************************************************/

/****************  handleing align registers ****************/
template<class T, AliasGroup aliasGroup>
struct HandleAliasRegisters{

    static __attribute__((always_inline)) void CheckUpdateGenericAlias(uint8_t regId, T value, uint32_t opaqueHandle, THREADID threadId) {
        
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
        
        //alias begin bytes for different types
        #if __BYTE_ORDER == __LITTLE_ENDIAN
            uint8_t byteOffset = aliasGroup == ALIAS_HIGH_BYTE ? 1 : 0;
        #else
            #error "unknown endianness"
        #endif

        
        T * where = (T *)(&tData->aliasValue[regId][byteOffset]);
        
        if (*where == value) {
            AddToRedTable(MAKE_CONTEXT_PAIR(tData->aliasCtxt[regId][aliasGroup], curCtxtHandle), sizeof(T), threadId);
        }else {
            *where = value;
        }
        tData->aliasCtxt[regId][ALIAS_GENERIC] = curCtxtHandle;
        if(aliasGroup == ALIAS_GENERIC){
            tData->aliasCtxt[regId][ALIAS_HIGH_BYTE] = curCtxtHandle;
            tData->aliasCtxt[regId][ALIAS_LOW_BYTE] = curCtxtHandle;
        } else {
            tData->aliasCtxt[regId][aliasGroup] = curCtxtHandle;
        }
    }
};

/****************  handleing general registers ****************/
template<class T, uint8_t len>
struct HandleGeneralRegisters{
    
    static __attribute__((always_inline)) void CheckValues(T value, REG reg, uint32_t opaqueHandle, THREADID threadId) {
        
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
        
        T * regBefore = (T *)(&tData->regValue[reg][0]);
        
        if (* regBefore == value ) {
            AddToRedTable(MAKE_CONTEXT_PAIR(tData->regCtxt[reg],curCtxtHandle),sizeof(T),threadId);
        }else
            * regBefore = value;
        tData->regCtxt[reg] = curCtxtHandle;
    }
};

//lenInt64: 1(X87), 2(XMM), 4(YMM), 8(ZMM)
template<uint8_t lenInt64>
struct HandleSpecialRegisters{

    //check the MM_x part registers in X87
    static __attribute__((always_inline)) void CheckRegValues(PIN_REGISTER* regRef, REG regID, uint32_t opaqueHandle, THREADID threadId){
        
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        
        ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);

        if(lenInt64 == 1){
            uint64_t *oldValue = (uint64_t*)&(tData->regValue[regID][0]);
            if(*oldValue == regRef->qword[0])
                AddToRedTable(MAKE_CONTEXT_PAIR(tData->regCtxt[regID],curCtxtHandle),8,threadId);
            else
                *oldValue = regRef->qword[0];
        
            tData->regCtxt[regID] = curCtxtHandle;
        }else if(lenInt64 == 2){
            
            uint64_t *oldValue1 = (uint64_t*)&(tData->simdValue[regID].value);
            uint64_t *oldValue2 = (uint64_t*)&(tData->simdValue[regID].value[8]);
            if(*oldValue1 == regRef->qword[0] && *oldValue2 == regRef->qword[1])
            AddToRedTable(MAKE_CONTEXT_PAIR(tData->simdCtxt[regID],curCtxtHandle),16,threadId);
            else{
                *oldValue1 = regRef->qword[0];
                *oldValue2 = regRef->qword[1];
            }
            tData->simdCtxt[regID] = curCtxtHandle;
            
        }else{
            
            uint64_t *oldValue;
            bool isRedundant = true;
            for(int i = 0,j = 0; i < lenInt64; ++i, j += 8){
                oldValue = (uint64_t*)&(tData->simdValue[regID].value[j]);
                if(*oldValue != regRef->qword[i]){
                    isRedundant = false;
                    *oldValue = regRef->qword[i];
                }
            }
            
            if(isRedundant)
                AddToRedTable(MAKE_CONTEXT_PAIR(tData->simdCtxt[regID],curCtxtHandle),lenInt64*8,threadId);
            
            tData->simdCtxt[regID] = curCtxtHandle;
        }
    }
    
    static __attribute__((always_inline)) void CheckSIMDRegValues(PIN_REGISTER* regRef, uint8_t simdID, uint32_t opaqueHandle, THREADID threadId){
        
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        
        ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
        
        if(lenInt64 == 2){
            
            uint64_t *oldValue1 = (uint64_t*)&(tData->simdValue[simdID].value[0]);
            uint64_t *oldValue2 = (uint64_t*)&(tData->simdValue[simdID].value[8]);
            if(*oldValue1 == regRef->qword[0] && *oldValue2 == regRef->qword[1])
                AddToRedTable(MAKE_CONTEXT_PAIR(tData->simdCtxt[simdID],curCtxtHandle),16,threadId);
            else{
                *oldValue1 = regRef->qword[0];
                *oldValue2 = regRef->qword[1];
            }
        }else{
            
            uint64_t *oldValue;
            bool isRedundant = true;
            for(int i = 0,j = 0; i < lenInt64; ++i, j += 8){
                oldValue = (uint64_t*)&(tData->simdValue[simdID].value[j]);
                if(*oldValue != regRef->qword[i]){
                    isRedundant = false;
                    *oldValue = regRef->qword[i];
                }
            }
            
            if(isRedundant)
                AddToRedTable(MAKE_CONTEXT_PAIR(tData->simdCtxt[simdID],curCtxtHandle),lenInt64*8,threadId);
        }
        tData->simdCtxt[simdID] = curCtxtHandle;
    }
};

/****************  handleing registers approximation  ****************/
//static void Check10BytesReg(PIN_REGISTER* regRef, REG reg, uint32_t opaqueHandle, THREADID threadId)__attribute__((always_inline));
static void Check10BytesReg(CONTEXT * ctxt, REG reg, uint32_t opaqueHandle, THREADID threadId){
    
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
    
    UINT8 * valueAfter;
    valueAfter = (UINT8 *)malloc(10*sizeof(UINT8));
    PIN_GetContextRegval(ctxt,reg,valueAfter);
    
    uint64_t * upperOld = (uint64_t*)&(tData->regValue[reg][2]);
    uint64_t * upperNew = (uint64_t*)&(valueAfter[2]);
    
    uint16_t * lowOld = (uint16_t*)&(tData->regValue[reg][0]);
    uint16_t * lowNew = (uint16_t*)(valueAfter);
    
    if((*lowOld & 0xfff0) == (*lowNew & 0xfff0) && *upperNew == *upperOld){
        AddToApproximateRedTable(MAKE_CONTEXT_PAIR(tData->regCtxt[reg],curCtxtHandle),10,threadId);
        *lowOld = *lowNew;
    }else
        memcpy(&tData->regValue[reg][0], valueAfter, 10);
    tData->regCtxt[reg] = curCtxtHandle;
}

//approximate general registers
template<class T, bool isAlias>
struct ApproxGeneralRegisters{
    
    static __attribute__((always_inline)) void CheckValues(PIN_REGISTER* regRef, uint32_t reg, uint32_t opaqueHandle, THREADID threadId){
        
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        
        ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
        
        if(isAlias){
            uint8_t byteOffset = 0;
            
            T newValue;
            if(sizeof(T) == 8)
                newValue = regRef->dbl[0];
            else
                newValue = regRef->flt[0];
            
            T oldValue = *((T*)(&tData->aliasValue[reg][byteOffset]));
            T rate = (newValue - oldValue)/oldValue;
            if( rate <= delta && rate >= -delta ){
                AddToApproximateRedTable(MAKE_CONTEXT_PAIR(tData->aliasCtxt[reg][ALIAS_GENERIC],curCtxtHandle),sizeof(T),threadId);
            }
            if( newValue != oldValue)
                *((T*)(&tData->aliasValue[reg][byteOffset])) = newValue;
            
            tData->aliasCtxt[reg][ALIAS_GENERIC] = curCtxtHandle;
            tData->aliasCtxt[reg][ALIAS_HIGH_BYTE] = curCtxtHandle;
            tData->aliasCtxt[reg][ALIAS_LOW_BYTE] = curCtxtHandle;
            
        }else{
            T newValue;
            if(sizeof(T) == 8)
                newValue = regRef->dbl[0];
            else
                newValue = regRef->flt[0];
            
            T oldValue = *((T*)(&tData->regValue[reg][0]));
            T rate = (newValue - oldValue)/oldValue;
            if(rate <= delta && rate >= -delta) {
                AddToApproximateRedTable(MAKE_CONTEXT_PAIR(tData->regCtxt[reg],curCtxtHandle),sizeof(T),threadId);
            }
            if(newValue != oldValue)
                *((T*)(&tData->regValue[reg][0])) = newValue;
            tData->regCtxt[reg] = curCtxtHandle;
        }
    }
};

//approximate SIMD registers, simdType:0(XMM), 1(YMM), 2(ZMM)
template<class T, uint8_t simdType>
struct ApproxLargeRegisters{
    
    static __attribute__((always_inline)) void CheckValues(PIN_REGISTER* regRef, uint8_t regInd, uint32_t opaqueHandle, THREADID threadId){
        
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        
        ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
        
        if(simdType == 0){
            
            if(sizeof(T) == 4){
                __m128 oldValue = _mm_load_ps( reinterpret_cast<const float*> (&(tData->simdValue[regInd].value[0])));
                __m128 newValue = _mm_loadu_ps( reinterpret_cast<const float*> (regRef));
                
                __m128 result = _mm_sub_ps(newValue,oldValue);
                
                result = _mm_div_ps(result,oldValue);
                float rates[4] __attribute__((aligned(16)));
                _mm_store_ps(rates,result);
                
                uint8_t redCount = 0;
                if(rates[0] <= delta && rates[0] >= -delta) redCount++;
                if(rates[1] <= delta && rates[1] >= -delta) redCount++;
                if(rates[2] <= delta && rates[2] >= -delta) redCount++;
                if(rates[3] <= delta && rates[3] >= -delta) redCount++;

                if(redCount)
                    AddToApproximateRedTable(MAKE_CONTEXT_PAIR(tData->simdCtxt[regInd],curCtxtHandle),4*redCount,threadId);
                _mm_store_ps(reinterpret_cast<float*> (&(tData->simdValue[regInd].value[0])),newValue);
                
            }else if(sizeof(T) == 8){
                __m128d oldValue = _mm_load_pd( reinterpret_cast<const double*> (&(tData->simdValue[regInd].value[0])));
                __m128d newValue = _mm_loadu_pd( reinterpret_cast<const double*> (regRef));
                
                __m128d result = _mm_sub_pd(newValue,oldValue);
                
                result = _mm_div_pd(result,oldValue);
                
                double rate[2];
                _mm_storel_pd(&rate[0],result);
                _mm_storeh_pd(&rate[1],result);
                
                uint8_t redCount = 0;
                if(rate[0] <= delta && rate[0] >=-delta) redCount++;
                if(rate[1] <= delta && rate[1] >= -delta) redCount++;
                
                if(redCount)
                    AddToApproximateRedTable(MAKE_CONTEXT_PAIR(tData->simdCtxt[regInd],curCtxtHandle),8*redCount,threadId);
                _mm_store_pd(reinterpret_cast<double*> (&(tData->simdValue[regInd].value[0])),newValue);
            }else ;
            
        }else if(simdType == 1){
            
            if(sizeof(T) == 4){
                __m256 oldValue = _mm256_load_ps( reinterpret_cast<const float*> (&(tData->simdValue[regInd].value[0])));
                __m256 newValue = _mm256_loadu_ps( reinterpret_cast<const float*> (regRef));
                
                __m256 result = _mm256_sub_ps(newValue,oldValue);
                
                result = _mm256_div_ps(result,oldValue);
                float rates[8] __attribute__((aligned(32)));
                _mm256_store_ps(rates,result);
                
                uint8_t redCount = 0;
                for(int i = 0; i < 7; ++i)
                    if(rates[i] <= delta && rates[i] >= -delta) redCount++;
                
                if(redCount)
                    AddToApproximateRedTable(MAKE_CONTEXT_PAIR(tData->simdCtxt[regInd],curCtxtHandle),4*redCount,threadId);
                _mm256_store_ps(reinterpret_cast<float*> (&(tData->simdValue[regInd].value[0])),newValue);
                
            }else if(sizeof(T) == 8){
                __m256d oldValue = _mm256_load_pd( reinterpret_cast<const double*> (&(tData->simdValue[regInd].value[0])));
                __m256d newValue = _mm256_loadu_pd( reinterpret_cast<const double*> (regRef));
                
                __m256d result = _mm256_sub_pd(newValue,oldValue);
                
                result = _mm256_div_pd(result,oldValue);
                
                double rate[4] __attribute__((aligned(32)));
                _mm256_store_pd(rate,result);
                
                uint8_t redCount = 0;
                if(rate[0] <= delta && rate[0] >=-delta) redCount++;
                if(rate[1] <= delta && rate[1] >= -delta) redCount++;
                if(rate[2] <= delta && rate[2] >=-delta) redCount++;
                if(rate[3] <= delta && rate[3] >= -delta) redCount++;
                
                if(redCount)
                    AddToApproximateRedTable(MAKE_CONTEXT_PAIR(tData->simdCtxt[regInd],curCtxtHandle),8*redCount,threadId);
                _mm256_store_pd(reinterpret_cast<double*> (&(tData->simdValue[regInd].value[0])),newValue);
            }else ;
            
        }else ;/*else{
            
            if(sizeof(T) == 4){
                __m512 oldValue = _mm512_load_ps( reinterpret_cast<const float*> (&(tData->simdValue[regInd].value[0])));
                __m512 newValue = _mm512_loadu_ps( reinterpret_cast<const float*> (regRef));
                
                __m512 result = _mm512_sub_ps(newValue,oldValue);
                
                result = _mm512_div_ps(result,oldValue);
                float rates[16] __attribute__((aligned(64)));
                _mm512_store_ps(rates,result);
                
                uint8_t redCount = 0;
                for(int i = 0; i < 15; ++i)
                    if(rates[i] <= delta && rates[i] >= -delta) redCount++;
                
                if(redCount)
                    AddToApproximateRedTable(MAKE_CONTEXT_PAIR(tData->simdCtxt[regInd],curCtxtHandle),4*redCount,threadId);
                _mm512_store_ps(reinterpret_cast<float*> (&(tData->simdValue[regInd].value[0])),newValue);
                
            }else if(sizeof(T) == 8){
                __m512d oldValue = _mm512_load_pd( reinterpret_cast<const double*> (&(tData->simdValue[regInd].value[0])));
                __m512d newValue = _mm512_loadu_pd( reinterpret_cast<const double*> (regRef));
                
                __m512d result = _mm512_sub_pd(newValue,oldValue);
                
                result = _mm512_div_pd(result,oldValue);
                
                double rates[8] __attribute__((aligned(64)));
                _mm512_store_ps(rates,result);
                
                uint8_t redCount = 0;
                for(int i = 0; i < 7; ++i)
                    if(rates[i] <= delta && rates[i] >= -delta) redCount++;
                
                if(redCount)
                AddToApproximateRedTable(MAKE_CONTEXT_PAIR(tData->regCtxt[reg],curCtxtHandle),8*redCount,threadId);
                _mm512_store_pd(reinterpret_cast<double*> (&(tData->simdValue[regInd].value[0])),newValue);
            }else ;
        }*/

        tData->simdCtxt[regInd] = curCtxtHandle;
    }
};

static inline uint32_t GetAliasIDs(REG reg){
    uint8_t regGroup = 0;
    uint8_t byteInd = 0;
    uint8_t type = 0;
    switch (reg) {
        case REG_RAX: regGroup = ALIAS_REG_A; byteInd = ALIAS_BYTES_INDEX_64; type = ALIAS_GENERIC; break;
        case REG_EAX: regGroup = ALIAS_REG_A; byteInd = ALIAS_BYTES_INDEX_32; type = ALIAS_GENERIC; break;
        case REG_AX: regGroup = ALIAS_REG_A; byteInd = ALIAS_BYTES_INDEX_16; type = ALIAS_GENERIC; break;
        case REG_AH: regGroup = ALIAS_REG_A; byteInd = ALIAS_BYTES_INDEX_8_H; type = ALIAS_HIGH_BYTE; break;
        case REG_AL: regGroup = ALIAS_REG_A; byteInd = ALIAS_BYTES_INDEX_8_L; type = ALIAS_LOW_BYTE; break;
            
        case REG_RBX: regGroup = ALIAS_REG_B; byteInd = ALIAS_BYTES_INDEX_64; type = ALIAS_GENERIC; break;
        case REG_EBX: regGroup = ALIAS_REG_B; byteInd = ALIAS_BYTES_INDEX_32; type = ALIAS_GENERIC; break;
        case REG_BX: regGroup = ALIAS_REG_B; byteInd = ALIAS_BYTES_INDEX_16; type = ALIAS_GENERIC; break;
        case REG_BH: regGroup = ALIAS_REG_B; byteInd = ALIAS_BYTES_INDEX_8_H; type = ALIAS_HIGH_BYTE; break;
        case REG_BL: regGroup = ALIAS_REG_B; byteInd = ALIAS_BYTES_INDEX_8_L; type = ALIAS_LOW_BYTE; break;
            
        case REG_RCX: regGroup = ALIAS_REG_C; byteInd = ALIAS_BYTES_INDEX_64; type = ALIAS_GENERIC; break;
        case REG_ECX: regGroup = ALIAS_REG_C; byteInd = ALIAS_BYTES_INDEX_32; type = ALIAS_GENERIC; break;
        case REG_CX: regGroup = ALIAS_REG_C; byteInd = ALIAS_BYTES_INDEX_16; type = ALIAS_GENERIC; break;
        case REG_CH: regGroup = ALIAS_REG_C; byteInd = ALIAS_BYTES_INDEX_8_H; type = ALIAS_HIGH_BYTE; break;
        case REG_CL: regGroup = ALIAS_REG_C; byteInd = ALIAS_BYTES_INDEX_8_L; type = ALIAS_LOW_BYTE; break;
            
        case REG_RDX: regGroup = ALIAS_REG_D; byteInd = ALIAS_BYTES_INDEX_64; type = ALIAS_GENERIC; break;
        case REG_EDX: regGroup = ALIAS_REG_D; byteInd = ALIAS_BYTES_INDEX_32; type = ALIAS_GENERIC; break;
        case REG_DX: regGroup = ALIAS_REG_D; byteInd = ALIAS_BYTES_INDEX_16; type = ALIAS_GENERIC; break;
        case REG_DH: regGroup = ALIAS_REG_D; byteInd = ALIAS_BYTES_INDEX_8_H; type = ALIAS_HIGH_BYTE; break;
        case REG_DL: regGroup = ALIAS_REG_D; byteInd = ALIAS_BYTES_INDEX_8_L; type = ALIAS_LOW_BYTE; break;
            
        case REG_RBP: regGroup = ALIAS_REG_BP; byteInd = ALIAS_BYTES_INDEX_64; type = ALIAS_GENERIC; break;
        case REG_EBP: regGroup = ALIAS_REG_BP; byteInd = ALIAS_BYTES_INDEX_32; type = ALIAS_GENERIC; break;
        case REG_BP: regGroup = ALIAS_REG_BP; byteInd = ALIAS_BYTES_INDEX_16; type = ALIAS_GENERIC; break;
        case REG_BPL: regGroup = ALIAS_REG_BP; byteInd = ALIAS_BYTES_INDEX_8_L; type = ALIAS_GENERIC; break;
            
        case REG_RDI: regGroup = ALIAS_REG_DI; byteInd = ALIAS_BYTES_INDEX_64; type = ALIAS_GENERIC; break;
        case REG_EDI: regGroup = ALIAS_REG_DI; byteInd = ALIAS_BYTES_INDEX_32; type = ALIAS_GENERIC; break;
        case REG_DI: regGroup = ALIAS_REG_DI; byteInd = ALIAS_BYTES_INDEX_16; type = ALIAS_GENERIC; break;
        case REG_DIL: regGroup = ALIAS_REG_DI; byteInd = ALIAS_BYTES_INDEX_8_L; type = ALIAS_GENERIC; break;
            
        case REG_RSI: regGroup = ALIAS_REG_SI; byteInd = ALIAS_BYTES_INDEX_64; type = ALIAS_GENERIC; break;
        case REG_ESI: regGroup = ALIAS_REG_SI; byteInd = ALIAS_BYTES_INDEX_32; type = ALIAS_GENERIC; break;
        case REG_SI: regGroup = ALIAS_REG_SI; byteInd = ALIAS_BYTES_INDEX_16; type = ALIAS_GENERIC; break;
        case REG_SIL: regGroup = ALIAS_REG_SI; byteInd = ALIAS_BYTES_INDEX_8_L; type = ALIAS_GENERIC; break;
            
        case REG_RSP: regGroup = ALIAS_REG_SP; byteInd = ALIAS_BYTES_INDEX_64; type = ALIAS_GENERIC; break;
        case REG_ESP: regGroup = ALIAS_REG_SP; byteInd = ALIAS_BYTES_INDEX_32; type = ALIAS_GENERIC; break;
        case REG_SP: regGroup = ALIAS_REG_SP; byteInd = ALIAS_BYTES_INDEX_16; type = ALIAS_GENERIC; break;
        case REG_SPL: regGroup = ALIAS_REG_SP; byteInd = ALIAS_BYTES_INDEX_8_L; type = ALIAS_GENERIC; break;
            
        case REG_R8: regGroup = ALIAS_REG_R8; byteInd = ALIAS_BYTES_INDEX_64; type = ALIAS_GENERIC; break;
        case REG_R8D: regGroup = ALIAS_REG_R8; byteInd = ALIAS_BYTES_INDEX_32; type = ALIAS_GENERIC; break;
        case REG_R8W: regGroup = ALIAS_REG_R8; byteInd = ALIAS_BYTES_INDEX_16; type = ALIAS_GENERIC; break;
        case REG_R8B: regGroup = ALIAS_REG_R8; byteInd = ALIAS_BYTES_INDEX_8_L; type = ALIAS_GENERIC; break;
            
        case REG_R9: regGroup = ALIAS_REG_R9; byteInd = ALIAS_BYTES_INDEX_64; type = ALIAS_GENERIC; break;
        case REG_R9D: regGroup = ALIAS_REG_R9; byteInd = ALIAS_BYTES_INDEX_32; type = ALIAS_GENERIC; break;
        case REG_R9W: regGroup = ALIAS_REG_R9; byteInd = ALIAS_BYTES_INDEX_16; type = ALIAS_GENERIC; break;
        case REG_R9B: regGroup = ALIAS_REG_R9; byteInd = ALIAS_BYTES_INDEX_8_L; type = ALIAS_GENERIC; break;

        case REG_R10: regGroup = ALIAS_REG_R10; byteInd = ALIAS_BYTES_INDEX_64; type = ALIAS_GENERIC; break;
        case REG_R10D: regGroup = ALIAS_REG_R10; byteInd = ALIAS_BYTES_INDEX_32; type = ALIAS_GENERIC; break;
        case REG_R10W: regGroup = ALIAS_REG_R10; byteInd = ALIAS_BYTES_INDEX_16; type = ALIAS_GENERIC; break;
        case REG_R10B: regGroup = ALIAS_REG_R10; byteInd = ALIAS_BYTES_INDEX_8_L; type = ALIAS_GENERIC; break;

        case REG_R11: regGroup = ALIAS_REG_R11; byteInd = ALIAS_BYTES_INDEX_64; type = ALIAS_GENERIC; break;
        case REG_R11D: regGroup = ALIAS_REG_R11; byteInd = ALIAS_BYTES_INDEX_32; type = ALIAS_GENERIC; break;
        case REG_R11W: regGroup = ALIAS_REG_R11; byteInd = ALIAS_BYTES_INDEX_16; type = ALIAS_GENERIC; break;
        case REG_R11B: regGroup = ALIAS_REG_R11; byteInd = ALIAS_BYTES_INDEX_8_L; type = ALIAS_GENERIC; break;

        case REG_R12: regGroup = ALIAS_REG_R12; byteInd = ALIAS_BYTES_INDEX_64; type = ALIAS_GENERIC; break;
        case REG_R12D: regGroup = ALIAS_REG_R12; byteInd = ALIAS_BYTES_INDEX_32; type = ALIAS_GENERIC; break;
        case REG_R12W: regGroup = ALIAS_REG_R12; byteInd = ALIAS_BYTES_INDEX_16; type = ALIAS_GENERIC; break;
        case REG_R12B: regGroup = ALIAS_REG_R12; byteInd = ALIAS_BYTES_INDEX_8_L; type = ALIAS_GENERIC; break;

        case REG_R13: regGroup = ALIAS_REG_R13; byteInd = ALIAS_BYTES_INDEX_64; type = ALIAS_GENERIC; break;
        case REG_R13D: regGroup = ALIAS_REG_R13; byteInd = ALIAS_BYTES_INDEX_32; type = ALIAS_GENERIC; break;
        case REG_R13W: regGroup = ALIAS_REG_R13; byteInd = ALIAS_BYTES_INDEX_16; type = ALIAS_GENERIC; break;
        case REG_R13B: regGroup = ALIAS_REG_R13; byteInd = ALIAS_BYTES_INDEX_8_L; type = ALIAS_GENERIC; break;

        case REG_R14: regGroup = ALIAS_REG_R14; byteInd = ALIAS_BYTES_INDEX_64; type = ALIAS_GENERIC; break;
        case REG_R14D: regGroup = ALIAS_REG_R14; byteInd = ALIAS_BYTES_INDEX_32; type = ALIAS_GENERIC; break;
        case REG_R14W: regGroup = ALIAS_REG_R14; byteInd = ALIAS_BYTES_INDEX_16; type = ALIAS_GENERIC; break;
        case REG_R14B: regGroup = ALIAS_REG_R14; byteInd = ALIAS_BYTES_INDEX_8_L; type = ALIAS_GENERIC; break;

        case REG_R15: regGroup = ALIAS_REG_R15; byteInd = ALIAS_BYTES_INDEX_64; type = ALIAS_GENERIC; break;
        case REG_R15D: regGroup = ALIAS_REG_R15; byteInd = ALIAS_BYTES_INDEX_32; type = ALIAS_GENERIC; break;
        case REG_R15W: regGroup = ALIAS_REG_R15; byteInd = ALIAS_BYTES_INDEX_16; type = ALIAS_GENERIC; break;
        case REG_R15B: regGroup = ALIAS_REG_R15; byteInd = ALIAS_BYTES_INDEX_8_L; type = ALIAS_GENERIC; break;

        default: assert(0 && "not alias registers! should not reach here!"); break;
    }
    uint32_t aliasGroupByteType = ((uint32_t)regGroup << 16) | ((uint32_t)byteInd << 8) | ((uint32_t)type);
    return aliasGroupByteType;
}

inline bool RegHasAlias(REG reg){
    switch(reg){
        case REG_RAX:
        case REG_RBX:
        case REG_RCX:
        case REG_RDX:
        case REG_EAX:
        case REG_EBX:
        case REG_ECX:
        case REG_EDX:
        case REG_AX:
        case REG_BX:
        case REG_CX:
        case REG_DX:
        case REG_AH:
        case REG_BH:
        case REG_CH:
        case REG_DH:
        case REG_AL:
        case REG_BL:
        case REG_CL:
        case REG_DL:
        case REG_RBP:
        case REG_EBP:
        case REG_BP:
        case REG_BPL:
        case REG_RDI:
        case REG_EDI:
        case REG_DI:
        case REG_DIL:
        case REG_RSI:
        case REG_ESI:
        case REG_SI:
        case REG_SIL:
        case REG_RSP:
        case REG_ESP:
        case REG_SP:
        case REG_SPL:
        case REG_R8:
        case REG_R8D:
        case REG_R8W:
        case REG_R8B:
        case REG_R9:
        case REG_R9D:
        case REG_R9W:
        case REG_R9B:
        case REG_R10:
        case REG_R10D:
        case REG_R10W:
        case REG_R10B:
        case REG_R11:
        case REG_R11D:
        case REG_R11W:
        case REG_R11B:
        case REG_R12:
        case REG_R12D:
        case REG_R12W:
        case REG_R12B:
        case REG_R13:
        case REG_R13D:
        case REG_R13W:
        case REG_R13B:
        case REG_R14:
        case REG_R14D:
        case REG_R14W:
        case REG_R14B:
        case REG_R15:
        case REG_R15D:
        case REG_R15W:
        case REG_R15B:
            return true;
        default: return false;
    }
}

#ifdef ENABLE_SAMPLING

#define HANDLE_SPECIALREG(LEN,REG_ID) \
INS_InsertIfPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR)IfEnableSample, IARG_THREAD_ID,IARG_END);\
INS_InsertThenPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) HandleSpecialRegisters<LEN>::CheckRegValues, IARG_REG_CONST_REFERENCE,reg, IARG_UINT32, REG_ID, IARG_UINT32, opaqueHandle, IARG_THREAD_ID,IARG_END)

#define HANDLE_LARGEREG_APPROX(T, SIMD_TYPE, REG_ID) \
INS_InsertIfPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR)IfEnableSample, IARG_THREAD_ID,IARG_END);\
INS_InsertThenPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) ApproxLargeRegisters<T, SIMD_TYPE>::CheckValues, IARG_REG_CONST_REFERENCE,reg, IARG_UINT32, REG_ID, IARG_UINT32, opaqueHandle, IARG_THREAD_ID,IARG_END)

#define HANDLE_ALIAS_REG(T, ALIAS_GRP, ID) \
INS_InsertIfPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR)IfEnableSample, IARG_THREAD_ID,IARG_END); \
INS_InsertThenPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) HandleAliasRegisters<T, ALIAS_GRP>::CheckUpdateGenericAlias, IARG_UINT32, ID, IARG_REG_VALUE, reg, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_END)

#define HANDLE_GENERAL(T) \
INS_InsertIfPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR)IfEnableSample, IARG_THREAD_ID,IARG_END); \
INS_InsertThenPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) HandleGeneralRegisters<T,1>::CheckValues,IARG_REG_VALUE,reg,IARG_UINT32, reg, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_END)

#define HANDLE_APPROXREG(T, IS_ALIAS, REG_ID) \
INS_InsertIfPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR)IfEnableSample, IARG_THREAD_ID,IARG_END);\
INS_InsertThenPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) ApproxGeneralRegisters<T, IS_ALIAS>::CheckValues, IARG_REG_CONST_REFERENCE,reg, IARG_UINT32, REG_ID, IARG_UINT32, opaqueHandle, IARG_THREAD_ID,IARG_END)

#define HANDLE_10BYTES_APPROX(REG_ID) \
INS_InsertIfPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR)IfEnableSample, IARG_THREAD_ID,IARG_END);\
INS_InsertThenPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) Check10BytesReg, IARG_CONTEXT, IARG_UINT32, REG_ID, IARG_UINT32, opaqueHandle, IARG_THREAD_ID,IARG_END)

#else

#define HANDLE_SPECIALREG(LEN,REG_ID) \
INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) HandleSpecialRegisters<LEN>::CheckRegValues, IARG_REG_CONST_REFERENCE,reg, IARG_UINT32, REG_ID, IARG_UINT32, opaqueHandle, IARG_THREAD_ID,IARG_END)

#define HANDLE_LARGEREG_APPROX(T, SIMD_TYPE, REG_ID) \
INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) ApproxLargeRegisters<T, SIMD_TYPE>::CheckValues, IARG_REG_CONST_REFERENCE,reg, IARG_UINT32, REG_ID, IARG_UINT32, opaqueHandle, IARG_THREAD_ID,IARG_END)

#define HANDLE_ALIAS_REG(T, ALIAS_GRP, ID) \
INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) HandleAliasRegisters<T, ALIAS_GRP>::CheckUpdateGenericAlias, IARG_UINT32, ID,IARG_REG_VALUE, reg, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_END)

#define HANDLE_GENERAL(T) \
INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) HandleGeneralRegisters<T,1>::CheckValues,IARG_REG_VALUE,reg,IARG_UINT32, reg, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_END)

#define HANDLE_APPROXREG(T, IS_ALIAS, REG_ID) \
INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) ApproxGeneralRegisters<T, IS_ALIAS>::CheckValues, IARG_REG_CONST_REFERENCE,reg, IARG_UINT32, REG_ID, IARG_UINT32, opaqueHandle, IARG_THREAD_ID,IARG_END)

#define HANDLE_10BYTES_APPROX(REG_ID) \
INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) Check10BytesReg, IARG_CONTEXT, IARG_UINT32, REG_ID, IARG_UINT32, opaqueHandle, IARG_THREAD_ID,IARG_END)

#endif

static inline void InstrumentAliasReg(INS ins, REG reg, uint16_t oper, uint32_t opaqueHandle){
    
    uint32_t regSize = REG_Size(reg);
    uint32_t aliasIDs = GetAliasIDs(reg);
    uint8_t regId = static_cast<uint8_t>(((aliasIDs)  & 0x00ffffff) >> 16 );
    
    if (IsFloatInstruction(INS_Address(ins))){
        switch (regSize) {
            case 1:
            case 2:
            case 4: HANDLE_APPROXREG(float, true, regId); break;
            case 8: HANDLE_APPROXREG(double, true, regId); break;
            default: break;
        }
    }else{
        switch (regSize) {
            case 8: HANDLE_ALIAS_REG(uint64_t, ALIAS_GENERIC, regId); break;
            case 4: HANDLE_ALIAS_REG(uint32_t, ALIAS_GENERIC, regId); break;
            case 2: HANDLE_ALIAS_REG(uint16_t, ALIAS_GENERIC, regId); break;
            case 1: if (REG_is_Lower8(reg)){
                HANDLE_ALIAS_REG(uint8_t, ALIAS_LOW_BYTE, regId);
            }else{
                HANDLE_ALIAS_REG(uint8_t, ALIAS_HIGH_BYTE, regId);
            }break;
            default: break;
        }

    }
}

static inline void InstrumentGeneralReg(INS ins, REG reg, uint16_t oper, uint32_t opaqueHandle){
    uint32_t regSize = REG_Size(reg);
    
    if (IsFloatInstruction(INS_Address(ins))){
        unsigned int operSize = FloatOperandSize(INS_Address(ins),oper);
        switch (regSize) {
            case 1:
            case 2:
            case 4: HANDLE_APPROXREG(float, false, reg); break;
            case 8: HANDLE_APPROXREG(double, false, reg); break;
            case 10: HANDLE_10BYTES_APPROX(reg); break;
            case 16: {
                switch (operSize) {
                    case 4: HANDLE_LARGEREG_APPROX(float,0,reg-REG_XMM_BASE);break;
                    case 8: HANDLE_LARGEREG_APPROX(double,0,reg-REG_XMM_BASE);break;
                    default: assert(0 && "handle large reg with large operand size\n"); break;
                }
            }break;
            case 32:{
                switch (operSize) {
                    case 4: HANDLE_LARGEREG_APPROX(float,1,reg-REG_YMM_BASE);break;
                    case 8: HANDLE_LARGEREG_APPROX(double,1,reg-REG_YMM_BASE);break;
                    default: assert(0 && "handle large reg with large operand size\n"); break;
                }
            }break;
            case 64: {
                switch (operSize) {
                    case 4: HANDLE_LARGEREG_APPROX(float,2,reg-REG_ZMM_BASE);break;
                    case 8: HANDLE_LARGEREG_APPROX(double,2,reg-REG_ZMM_BASE);break;
                    default: assert(0 && "handle large reg with large operand size\n"); break;
                }
            }break;
            default: assert(0 && "not recoganized register size for floating instruction!\n");
        }
    }else{
        if (REG_is_in_X87(reg)) {
            HANDLE_SPECIALREG(1,reg);
            return;
        }
        switch(regSize) {
            case 1: HANDLE_GENERAL(uint8_t); break;
            case 2: HANDLE_GENERAL(uint16_t); break;
            case 4: HANDLE_GENERAL(uint32_t); break;
            case 8: HANDLE_GENERAL(uint64_t); break;
            case 16: HANDLE_SPECIALREG(2,reg-REG_XMM_BASE); break;
            case 32: HANDLE_SPECIALREG(4,reg-REG_YMM_BASE); break;
            case 64: HANDLE_SPECIALREG(8,reg-REG_ZMM_BASE); break;
            default: assert(0 && "not recoganized register size for integer instruction!\n"); break;
        }
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
        uint8_t * status = (uint8_t *) get<0>(sm.GetOrCreateShadowBaseAddress((uint64_t)addr + start));
        ContextHandle_t * prevIP = (ContextHandle_t*)(status + PAGE_OFFSET(((uint64_t)addr + start)) * sizeof(ContextHandle_t));
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


template<class T, uint32_t AccessLen, uint32_t bufferOffset, bool isApprox>
struct RedSpyAnalysis{
    static __attribute__((always_inline)) bool IsWriteRedundant(void * &addr, THREADID threadId){
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        AddrValPair * avPair = & tData->buffer[bufferOffset];
        addr = avPair->address;
        
        if(isApprox){
            if(AccessLen>=32){
                if(sizeof(T) == 4){
                    __m256 oldValue = _mm256_load_ps( reinterpret_cast<const float*> (&avPair->value));
                    __m256 newValue = _mm256_loadu_ps( reinterpret_cast<const float*> (avPair->address));
                    
                    __m256 result = _mm256_sub_ps(newValue,oldValue);
                    
                    result = _mm256_div_ps(result,oldValue);
                    float rates[8] __attribute__((aligned(32)));
                    _mm256_store_ps(rates,result);
                    
                    for(int i = 0; i < 8; ++i){
                        if(rates[i] < -delta || rates[i] > delta) {
                            return false;
                        }
                    }
                    return true;
                    
                }else if(sizeof(T) == 8){
                    __m256d oldValue = _mm256_load_pd( reinterpret_cast<const double*> (&avPair->value));
                    __m256d newValue = _mm256_loadu_pd( reinterpret_cast<const double*> (avPair->address));
                    
                    __m256d result = _mm256_sub_pd(newValue,oldValue);
                    
                    result = _mm256_div_pd(result,oldValue);
                    
                    double rates[4] __attribute__((aligned(32)));
                    _mm256_store_pd(rates,result);
                    
                    for(int i = 0; i < 4; ++i){
                        if(rates[i] < -delta || rates[i] > delta) {
                            return false;
                        }
                    }
                    return true;
                }
            }else if(AccessLen == 16){
                if(sizeof(T) == 4){
                    __m128 oldValue = _mm_load_ps( reinterpret_cast<const float*> (&avPair->value));
                    __m128 newValue = _mm_loadu_ps( reinterpret_cast<const float*> (avPair->address));
                    
                    __m128 result = _mm_sub_ps(newValue,oldValue);
                    
                    result = _mm_div_ps(result,oldValue);
                    float rates[4] __attribute__((aligned(16)));
                    _mm_store_ps(rates,result);
                    
                    for(int i = 0; i < 4; ++i){
                        if(rates[i] < -delta || rates[i] > delta) {
                            return false;
                        }
                    }
                    return true;
                    
                }else if(sizeof(T) == 8){
                    __m128d oldValue = _mm_load_pd( reinterpret_cast<const double*> (&avPair->value));
                    __m128d newValue = _mm_loadu_pd( reinterpret_cast<const double*> (avPair->address));
                    
                    __m128d result = _mm_sub_pd(newValue,oldValue);
                    
                    result = _mm_div_pd(result,oldValue);
                    
                    double rate[2];
                    _mm_storel_pd(&rate[0],result);
                    _mm_storeh_pd(&rate[1],result);
                    
                    if(rate[0] < -delta || rate[0] > delta)
                        return false;
                    if(rate[1] < -delta || rate[1] > delta)
                        return false;
                    return true;
                }
            }else if(AccessLen == 10){
                UINT8 newValue[10];
                memcpy(newValue, addr, AccessLen);
                
                uint64_t * upperOld = (uint64_t*)&(avPair->value[2]);
                uint64_t * upperNew = (uint64_t*)&(newValue[2]);
                
                uint16_t * lowOld = (uint16_t*)&(avPair->value[0]);
                uint16_t * lowNew = (uint16_t*)&(newValue[0]);
                
                if((*lowOld & 0xfff0) == (*lowNew & 0xfff0) && *upperNew == *upperOld){
                    return true;
                }
                return false;
            }else{
                T newValue = *(static_cast<T*>(avPair->address));
                T oldValue = *((T*)(&avPair->value));
            
                T rate = (newValue - oldValue)/oldValue;
                if( rate <= delta && rate >= -delta ) return true;
                else return false;
            }
        }else{
            return *((T*)(&avPair->value)) == *(static_cast<T*>(avPair->address));
        }
        return false;
    }
    
    static __attribute__((always_inline)) VOID RecordNByteValueBeforeWrite(void* addr, THREADID threadId){
        
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
       
        AddrValPair * avPair = & tData->buffer[bufferOffset];

        avPair->address = addr;
        if(AccessLen >= 32){
            if(sizeof(T) == 4){
                __m256 newValue = _mm256_loadu_ps( reinterpret_cast<const float*> (addr));
                _mm256_store_ps(reinterpret_cast<float*> (&avPair->value), newValue);
                
            }else if(sizeof(T) == 8){
                __m256d newValue = _mm256_loadu_pd(reinterpret_cast<const double*> (addr));
                _mm256_store_pd(reinterpret_cast<double*> (&avPair->value), newValue);
            }
        }else if(AccessLen == 16){
            if(sizeof(T) == 4){
                __m128 newValue = _mm_loadu_ps( reinterpret_cast<const float*> (addr));
                _mm_store_ps(reinterpret_cast<float*> (&avPair->value), newValue);
                         
            }else if(sizeof(T) == 8){
                __m128d newValue = _mm_loadu_pd(reinterpret_cast<const double*> (addr));
                _mm_store_pd(reinterpret_cast<double*> (&avPair->value), newValue);
            }
        }else if(AccessLen == 10){
            memcpy(&avPair->value, addr, AccessLen);
        }else
            *((T*)(&avPair->value)) = *(static_cast<T*>(addr));
    }
    
    static __attribute__((always_inline)) VOID CheckNByteValueAfterWrite(uint32_t opaqueHandle, THREADID threadId){
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        void * addr;
        bool isRedundantWrite = IsWriteRedundant(addr, threadId);

        ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
        
        uint8_t* status = (uint8_t *) get<0>(sm.GetOrCreateShadowBaseAddress((uint64_t)addr));
        ContextHandle_t * __restrict__ prevIP = (ContextHandle_t*)(status + PAGE_OFFSET((uint64_t)addr) * sizeof(ContextHandle_t));
        const bool isAccessWithinPageBoundary = IS_ACCESS_WITHIN_PAGE_BOUNDARY( (uint64_t)addr, AccessLen);
        if(isRedundantWrite) {
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
                // Write across a 64-K page boundary
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
                // Write across a 64-K page boundary
                // Update context
                prevIP[0] = curCtxtHandle;
                
                // Remaining bytes [1..AccessLen] somewhere will across a 64-K page boundary
                UnrolledLoop<1, AccessLen, 1, false, /* not redundant*/ isApprox>::BodyStraddlePage( (uint64_t) addr, curCtxtHandle, threadId);
            }
        }
    }
    static __attribute__((always_inline)) VOID ApproxCheckAfterWrite(uint32_t opaqueHandle, THREADID threadId){
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        void * addr;
        bool isRedundantWrite = IsWriteRedundant(addr, threadId);
        
        ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
        
        UINT32 const interv = sizeof(T);
        uint8_t* status = (uint8_t *)  get<0>(sm.GetOrCreateShadowBaseAddress((uint64_t)addr));
        ContextHandle_t * __restrict__ prevIP = (ContextHandle_t*)(status + PAGE_OFFSET((uint64_t)addr) * sizeof(ContextHandle_t));
        
        if(isRedundantWrite){
            for(UINT32 index = 0 ; index < AccessLen; index+=interv){
                status = (uint8_t *)  get<0>(sm.GetOrCreateShadowBaseAddress((uint64_t)addr + index));
                prevIP = (ContextHandle_t*)(status + PAGE_OFFSET(((uint64_t)addr + index)) * sizeof(ContextHandle_t));
                // report in RedTable
                AddToApproximateRedTable(MAKE_CONTEXT_PAIR(prevIP[0 /* 0 is correct*/ ], curCtxtHandle), interv, threadId);
                // Update context
                prevIP[0] = curCtxtHandle;
            }
        }else{
            for(UINT32 index = 0 ; index < AccessLen; index+=interv){
                status = (uint8_t *) get<0>(sm.GetOrCreateShadowBaseAddress((uint64_t)addr + index));
                prevIP = (ContextHandle_t*)(status + PAGE_OFFSET(((uint64_t)addr + index)) * sizeof(ContextHandle_t));
                // Update context
                prevIP[0] = curCtxtHandle;
            }
        }
    }
};


static inline VOID RecordValueBeforeLargeWrite(void* addr, UINT32 accessLen,  uint32_t bufferOffset, THREADID threadId){
    
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    memcpy(& (tData->buffer[bufferOffset].value), addr, accessLen);
    tData->buffer[bufferOffset].address = addr;
}

static inline VOID CheckAfterLargeWrite(UINT32 accessLen,  uint32_t bufferOffset, uint32_t opaqueHandle, THREADID threadId){

    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    void * addr = tData->buffer[bufferOffset].address;
    ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
    
    uint8_t* status = (uint8_t *) get<0>(sm.GetOrCreateShadowBaseAddress((uint64_t)addr));
    ContextHandle_t * __restrict__ prevIP = (ContextHandle_t*)(status + PAGE_OFFSET((uint64_t)addr) * sizeof(ContextHandle_t));
    if(memcmp( & (tData->buffer[bufferOffset].value), addr, accessLen) == 0){
        // redundant
        for(UINT32 index = 0 ; index < accessLen; index++){
            status = (uint8_t *) get<0>(sm.GetOrCreateShadowBaseAddress((uint64_t)addr + index));
            prevIP = (ContextHandle_t*)(status + PAGE_OFFSET(((uint64_t)addr + index)) * sizeof(ContextHandle_t));
            // report in RedTable
            AddToRedTable(MAKE_CONTEXT_PAIR(prevIP[0 /* 0 is correct*/ ], curCtxtHandle), 1, threadId);
            // Update context
            prevIP[0] = curCtxtHandle;
        }
    }else{
        // Not redundant
        for(UINT32 index = 0 ; index < accessLen; index++){
            status = (uint8_t *) get<0>(sm.GetOrCreateShadowBaseAddress((uint64_t)addr + index));
            prevIP = (ContextHandle_t*)(status + PAGE_OFFSET(((uint64_t)addr + index)) * sizeof(ContextHandle_t));
            // Update context
            prevIP[0] = curCtxtHandle;
        }
    }
}

#ifdef ENABLE_SAMPLING

#define HANDLE_CASE(T, ACCESS_LEN, BUFFER_INDEX, IS_APPROX) \
INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)IfEnableSample, IARG_THREAD_ID,IARG_END);\
INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) RedSpyAnalysis<T, (ACCESS_LEN), (BUFFER_INDEX),(IS_APPROX)>::RecordNByteValueBeforeWrite, IARG_MEMORYOP_EA, memOp, IARG_THREAD_ID, IARG_END);\
INS_InsertIfPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR)IfEnableSample, IARG_THREAD_ID,IARG_END);\
INS_InsertThenPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) RedSpyAnalysis<T, (ACCESS_LEN), (BUFFER_INDEX),(IS_APPROX)>::CheckNByteValueAfterWrite, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_INST_PTR,IARG_END)

#define HANDLE_APPROX_CASE(T, ACCESS_LEN, BUFFER_INDEX, IS_APPROX) \
INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)IfEnableSample, IARG_THREAD_ID,IARG_END);\
INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) RedSpyAnalysis<T, (ACCESS_LEN), (BUFFER_INDEX),(IS_APPROX)>::RecordNByteValueBeforeWrite, IARG_MEMORYOP_EA, memOp, IARG_THREAD_ID, IARG_END);\
INS_InsertIfPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR)IfEnableSample, IARG_THREAD_ID,IARG_END);\
INS_InsertThenPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) RedSpyAnalysis<T, (ACCESS_LEN), (BUFFER_INDEX),(IS_APPROX)>::ApproxCheckAfterWrite, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_INST_PTR,IARG_END)

#define HANDLE_LARGE() \
INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)IfEnableSample, IARG_THREAD_ID,IARG_END);\
INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) RecordValueBeforeLargeWrite, IARG_MEMORYOP_EA, memOp, IARG_MEMORYWRITE_SIZE, IARG_UINT32, readBufferSlotIndex, IARG_THREAD_ID, IARG_END);\
INS_InsertIfPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR)IfEnableSample, IARG_THREAD_ID,IARG_END);\
INS_InsertThenPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) CheckAfterLargeWrite, IARG_MEMORYREAD_SIZE, IARG_UINT32, readBufferSlotIndex, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_END)

#else

#define HANDLE_CASE(T, ACCESS_LEN, BUFFER_INDEX, IS_APPROX) \
INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) RedSpyAnalysis<T, (ACCESS_LEN), (BUFFER_INDEX),(IS_APPROX)>::RecordNByteValueBeforeWrite, IARG_MEMORYOP_EA, memOp, IARG_THREAD_ID, IARG_END);\
INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) RedSpyAnalysis<T, (ACCESS_LEN), (BUFFER_INDEX),(IS_APPROX)>::CheckNByteValueAfterWrite, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_INST_PTR,IARG_END)

#define HANDLE_APPROX_CASE(T, ACCESS_LEN, BUFFER_INDEX, IS_APPROX) \
INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) RedSpyAnalysis<T, (ACCESS_LEN), (BUFFER_INDEX),(IS_APPROX)>::RecordNByteValueBeforeWrite, IARG_MEMORYOP_EA, memOp, IARG_THREAD_ID, IARG_END);\
INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) RedSpyAnalysis<T, (ACCESS_LEN), (BUFFER_INDEX),(IS_APPROX)>::ApproxCheckAfterWrite, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_INST_PTR,IARG_END)

#define HANDLE_LARGE() \
INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) RecordValueBeforeLargeWrite, IARG_MEMORYOP_EA, memOp, IARG_MEMORYWRITE_SIZE, IARG_UINT32, readBufferSlotIndex, IARG_THREAD_ID, IARG_END);\
INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) CheckAfterLargeWrite, IARG_MEMORYREAD_SIZE, IARG_UINT32, readBufferSlotIndex, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_END)

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
    static __attribute__((always_inline)) void InstrumentReadValueBeforeAndAfterWriting(INS ins, UINT32 memOp, uint32_t opaqueHandle){
        UINT32 refSize = INS_MemoryOperandSize(ins, memOp);
        
        if (IsFloatInstruction(INS_Address(ins))) {
            unsigned int operSize = FloatOperandSize(INS_Address(ins),INS_MemoryOperandIndexToOperandIndex(ins,memOp));
            switch(refSize) {
                case 1:
                case 2: assert(0 && "memory write floating data with unexptected small size");
                case 4: HANDLE_APPROX_CASE(float, 4, readBufferSlotIndex, true); break;
                case 8: HANDLE_APPROX_CASE(double, 8, readBufferSlotIndex, true); break;
                case 10: HANDLE_APPROX_CASE(uint8_t, 10, readBufferSlotIndex, true); break;
                case 16: {
                    switch (operSize) {
                        case 4: HANDLE_APPROX_CASE(float, 16, readBufferSlotIndex, true); break;
                        case 8: HANDLE_APPROX_CASE(double, 16, readBufferSlotIndex, true); break;
                        default: assert(0 && "handle large mem write with unexpected operand size\n"); break;
                    }
                }break;
                case 32: {
                    switch (operSize) {
                        case 4: HANDLE_APPROX_CASE(float, 32, readBufferSlotIndex, true); break;
                        case 8: HANDLE_APPROX_CASE(double, 32, readBufferSlotIndex, true); break;
                        default: assert(0 && "handle large mem write with unexpected operand size\n"); break;
                    }
                }break;
                default: assert(0 && "unexpected large memory writes\n"); break;
            }
        }else{
            switch(refSize) {
                case 1: HANDLE_CASE(uint8_t, 1, readBufferSlotIndex, false); break;
                case 2: HANDLE_CASE(uint16_t, 2, readBufferSlotIndex, false); break;
                case 4: HANDLE_CASE(uint32_t, 4, readBufferSlotIndex, false); break;
                case 8: HANDLE_CASE(uint64_t, 8, readBufferSlotIndex, false); break;
                    
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

static inline bool REG_IsIgnorable(REG reg){
    if (REG_is_seg(reg))
        return true;
    else if(REG_is_pin_gr(reg))
        return true;
    else if(reg == REG_MXCSR)
        return true;
    else if(REG_is_flags(reg))
        return true;
    return false;
}

static VOID InstrumentInsCallback(INS ins, VOID* v, const uint32_t opaqueHandle) {
    if (!INS_HasFallThrough(ins)) return;
    if (INS_IsIgnorable(ins))return;
    if (INS_IsBranchOrCall(ins) || INS_IsRet(ins)) return;
    
    //Instrument memory writes to find redundancy
    // Special case, if we have only one write operand
    UINT32 whichOp = 0;
    if(GetNumWriteOperandsInIns(ins, whichOp) == 1){
        // Read the value at location before and after the instruction
        RedSpyInstrument<0>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, opaqueHandle);
    }else{
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
    
    //Instrument register writes to find redundancy
    UINT32 numOperands = INS_OperandCount(ins);
    
    for(UINT32 oper = 0; oper < numOperands; oper++) {
        
        if(!INS_OperandWritten(ins, oper) || !INS_OperandIsReg(ins,oper))
            continue;
        
        REG reg = INS_OperandReg(ins,oper);
        
        if(REG_IsIgnorable(reg))
            continue;
        
        if (RegHasAlias(reg)) {
            InstrumentAliasReg(ins, reg , oper, opaqueHandle);
        }else{
            InstrumentGeneralReg(ins, reg, oper, opaqueHandle);
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
            EmptyCtxt(tData);
        }
    }else{
        tData->numIns += count;
        if(tData->numIns > WINDOW_DISABLE){
            tData->sampleFlag = true;
            tData->numIns = 0;
        }
    }
    if (tData->sampleFlag) {
        tData->bytesWritten += bytes;
    }
}

inline VOID Update(uint32_t count, uint32_t bytes, THREADID threadId){
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    tData->numIns += count;
    if (tData->sampleFlag) {
        tData->bytesWritten += bytes;
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
            
            if(INS_IsMemoryWrite(ins)) {
                totBytes += INS_MemoryWriteSize(ins);
            }
            UINT32 numOperands = INS_OperandCount(ins);
            
            for(UINT32 Oper = 0; Oper < numOperands; Oper++) {
                
                if(!INS_OperandWritten(ins, Oper) || !INS_OperandIsReg(ins,Oper))
                    continue;
                
                REG curReg = INS_OperandReg(ins,Oper);
                
                if(REG_IsIgnorable(curReg))
                    continue;
                
                totBytes += REG_Size(curReg);
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
    tData->bytesWritten += bytes;
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
            
            if(INS_IsMemoryWrite(ins)) {
                totBytes += INS_MemoryWriteSize(ins);
            }
            UINT32 numOperands = INS_OperandCount(ins);
            
            for(UINT32 Oper = 0; Oper < numOperands; Oper++) {
                
                if(!INS_OperandWritten(ins, Oper) || !INS_OperandIsReg(ins,Oper))
                    continue;
                
                REG curReg = INS_OperandReg(ins,Oper);
                
                if(REG_IsIgnorable(curReg))
                    continue;
                
                totBytes += REG_Size(curReg);
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
    PrintApproximationRedundancyPairs(threadid);
    PIN_UnlockClient();
    // clear redmap now
    RedMap[threadid].clear();
    ApproxRedMap[threadid].clear();
}

static VOID ThreadFiniFunc(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v) {
}

static VOID FiniFunc(INT32 code, VOID *v) {
    // do whatever you want to the full CCT with footpirnt
}

static void InitThreadData(RedSpyThreadData* tdata){
    tdata->bytesWritten = 0;
    tdata->sampleFlag = true;
    tdata->numIns = 0;
    tdata->numWinds = 0;
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


