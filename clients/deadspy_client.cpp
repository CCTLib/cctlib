// @COPYRIGHT@
// Licensed under MIT license.
// See LICENSE.TXT file in the project root for more information.
// ==============================================================

#define __STDC_FORMAT_MACROS
#include <stdio.h>
#include <stdlib.h>
#include "pin.H"
#include <map>
#include <list>
#include <inttypes.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <locale>
#include <unistd.h>
#include <sys/syscall.h>
#include <iostream>
#include <assert.h>
#include <sys/mman.h>
#include <exception>
#include <sys/time.h>
#include <signal.h>
#include <string.h>
#include <setjmp.h>
#include <sstream>
#include <fstream>

#if __cplusplus > 199711L
#include <tr1/unordered_map>
#else
#include <hash_map>
#endif

#if __cplusplus > 199711L
// Need GOOGLE sparse hash tables
#include <google/sparse_hash_map>
#include <google/dense_hash_map>
using google::sparse_hash_map;      // namespace where class lives by default
using google::dense_hash_map;      // namespace where class lives by default
using namespace std;
using namespace std::tr1;
#else
using namespace std;
#define unordered_map hash_map
#endif

#include "cctlib.H"
using namespace PinCCTLib;


#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

// ensures CONTINUOUS_DEADINFO

#define CONTINUOUS_DEADINFO


#define MAX_CCT_PRINT_DEPTH (20)
#define MAX_FILE_PATH   (200)
#ifndef MAX_DEAD_CONTEXTS_TO_LOG
#define MAX_DEAD_CONTEXTS_TO_LOG   (1000)
#endif //MAX_DEAD_CONTEXTS_TO_LOG

// 64KB shadow pages
#define PAGE_OFFSET_BITS (16LL)
#define PAGE_OFFSET(addr) ( addr & 0xFFFF)
#define PAGE_OFFSET_MASK ( 0xFFFF)

#define DEADSPY_PAGE_SIZE (1 << PAGE_OFFSET_BITS)

// 2 level page table
#define PTR_SIZE (sizeof(struct Status *))
#define LEVEL_1_PAGE_TABLE_BITS  (20)
#define LEVEL_1_PAGE_TABLE_ENTRIES  (1 << LEVEL_1_PAGE_TABLE_BITS )
#define LEVEL_1_PAGE_TABLE_SIZE  (LEVEL_1_PAGE_TABLE_ENTRIES * PTR_SIZE )

#define LEVEL_2_PAGE_TABLE_BITS  (12)
#define LEVEL_2_PAGE_TABLE_ENTRIES  (1 << LEVEL_2_PAGE_TABLE_BITS )
#define LEVEL_2_PAGE_TABLE_SIZE  (LEVEL_2_PAGE_TABLE_ENTRIES * PTR_SIZE )

#define LEVEL_1_PAGE_TABLE_SLOT(addr) ((((uint64_t)addr) >> (LEVEL_2_PAGE_TABLE_BITS + PAGE_OFFSET_BITS)) & 0xfffff)
#define LEVEL_2_PAGE_TABLE_SLOT(addr) ((((uint64_t)addr) >> (PAGE_OFFSET_BITS)) & 0xFFF)


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



#ifdef TESTING_BYTES
uint64_t gFullyKilling1;
uint64_t gFullyKilling2;
uint64_t gFullyKilling4;
uint64_t gFullyKilling8;
uint64_t gFullyKilling10;
uint64_t gFullyKilling16;
uint64_t gFullyKillingLarge;

uint64_t gPartiallyKilling1;
uint64_t gPartiallyKilling2;
uint64_t gPartiallyKilling4;
uint64_t gPartiallyKilling8;
uint64_t gPartiallyKilling10;
uint64_t gPartiallyKilling16;
uint64_t gPartiallyKillingLarge;

uint64_t gPartiallyDeadBytes1;
uint64_t gPartiallyDeadBytes2;
uint64_t gPartiallyDeadBytes4;
uint64_t gPartiallyDeadBytes8;
uint64_t gPartiallyDeadBytes10;
uint64_t gPartiallyDeadBytes16;
uint64_t gPartiallyDeadBytesLarge;
#endif // end TESTING_BYTES


// All fwd declarations

struct DeadInfo;
FILE* gTraceFile;
std::fstream topnStream;


struct MergedDeadInfo;
struct DeadInfoForPresentation;

// should become TLS
struct DeadSpyThreadData {
    uint64_t g1ByteWriteInstrCount;
    uint64_t g2ByteWriteInstrCount;
    uint64_t g4ByteWriteInstrCount;
    uint64_t g8ByteWriteInstrCount;
    uint64_t g10ByteWriteInstrCount;
    uint64_t g16ByteWriteInstrCount;
    uint64_t gLargeByteWriteInstrCount;
    uint64_t gLargeByteWriteByteCount;
};



struct DeadInfo {
    void* firstIP;
    void* secondIP;
    uint64_t count;
};

// key for accessing TLS storage in the threads. initialized once in main()
static  TLS_KEY client_tls_key;

static struct{
    char dummy1[128];
    string topNLogFileName;
    char dummy2[128];
} DeadSpyGlobals;



KNOB<UINT32> KnobTopN(KNOB_MODE_WRITEONCE, "pintool", "d", "0", "how many top contexts to log");


// function to access thread-specific data
inline DeadSpyThreadData* ClientGetTLS(const THREADID threadId) {
    DeadSpyThreadData* tdata =
        static_cast<DeadSpyThreadData*>(PIN_GetThreadData(client_tls_key, threadId));
    return tdata;
}

#if 0
volatile bool gDSLock;
inline VOID TakeLock() {
    do {
        while(gDSLock);
    } while(!__sync_bool_compare_and_swap(&gDSLock, 0, 1));
}

inline VOID ReleaseLock() {
    gDSLock = 0;
}
#endif


inline void InitThreadData(DeadSpyThreadData* const tdata) {
    tdata->g1ByteWriteInstrCount = 0;
    tdata->g2ByteWriteInstrCount = 0;
    tdata->g4ByteWriteInstrCount = 0;
    tdata->g8ByteWriteInstrCount = 0;
    tdata->g10ByteWriteInstrCount = 0;
    tdata->g16ByteWriteInstrCount = 0;
    tdata->gLargeByteWriteInstrCount = 0;
    tdata->gLargeByteWriteByteCount = 0;
}

PIN_LOCK lock;

inline bool DeadInfoComparer(const DeadInfo& first, const DeadInfo& second);
inline bool IsValidIP(DeadInfo  di);


uint8_t** gL1PageTable[LEVEL_1_PAGE_TABLE_SIZE];

//map < void *, Status > MemState;
#if defined(CONTINUOUS_DEADINFO)
unordered_map<uint64_t, uint64_t> DeadMap;
unordered_map<uint64_t, uint64_t>::iterator gDeadMapIt;
//dense_hash_map<uint64_t, uint64_t> DeadMap;
//dense_hash_map<uint64_t, uint64_t>::iterator gDeadMapIt;
//sparse_hash_map<uint64_t, uint64_t> DeadMap;
//sparse_hash_map<uint64_t, uint64_t>::iterator gDeadMapIt;
#else // no defined(CONTINUOUS_DEADINFO)
dense_hash_map<uint64_t, DeadInfo> DeadMap;
dense_hash_map<uint64_t, DeadInfo>::iterator gDeadMapIt;
//unordered_map<uint64_t, DeadInfo> DeadMap;
//unordered_map<uint64_t, DeadInfo>::iterator gDeadMapIt;
#endif //end defined(CONTINUOUS_DEADINFO)

#ifdef GATHER_STATS
FILE* statsFile;
#endif //end GATHER_STATS

uint64_t gTotalDead = 0;
#ifdef MULTI_THREADED
uint64_t gTotalMTDead = 0;
#endif // end MULTI_THREADED


volatile uint32_t gClientNumThreads;

VOID Instruction(INS ins, VOID* v, uint32_t slot);

// The following functions accummulates the number of bytes written in this basic block for the calling thread categorized by the write size.

inline VOID InstructionContributionOfBBL1Byte(uint32_t count, THREADID threadId) {
    ClientGetTLS(threadId)->g1ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL2Byte(uint32_t count, THREADID threadId) {
    ClientGetTLS(threadId)->g2ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL4Byte(uint32_t count, THREADID threadId) {
    ClientGetTLS(threadId)->g4ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL8Byte(uint32_t count, THREADID threadId) {
    ClientGetTLS(threadId)->g8ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL10Byte(uint32_t count, THREADID threadId) {
    ClientGetTLS(threadId)->g16ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL16Byte(uint32_t count, THREADID threadId) {
    ClientGetTLS(threadId)->g16ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBLLargeByte(uint32_t count, THREADID threadId) {
    ClientGetTLS(threadId)->gLargeByteWriteInstrCount += count;
}




// Instrument a trace, take the first instruction in the first BBL and insert the analysis function before that
static void InstrumentTrace(TRACE trace, void* f) {
    // Insert counting code
    for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        uint32_t inst1ByteSize = 0;
        uint32_t inst2ByteSize = 0;
        uint32_t inst4ByteSize = 0;
        uint32_t inst8ByteSize = 0;
        uint32_t inst10ByteSize = 0;
        uint32_t inst16ByteSize = 0;
        uint32_t instLargeByteSize  = 0;

        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            // instrument instruction, called by the call  back
            // Instruction(ins, 0);
            if(INS_IsMemoryWrite(ins)) {
                // get instruction info in trace
                USIZE writeSize = INS_MemoryWriteSize(ins);

                switch(writeSize) {
                case 1:
                    inst1ByteSize++;
                    break;

                case 2:
                    inst2ByteSize++;
                    break;

                case 4:
                    inst4ByteSize++;
                    break;

                case 8:
                    inst8ByteSize++;
                    break;

                case 10:
                    inst10ByteSize++;
                    break;

                case 16:
                    inst16ByteSize++;
                    break;

                default:
                    instLargeByteSize += writeSize;
                    //assert(0 && "NOT IMPLEMENTED ... SHOULD NOT SEE large writes in trace");
                }
            }
        }

        // Insert a call to corresponding count routines before every bbl, passing the number of instructions

        // Increment Inst count by trace
        if(inst1ByteSize)
            BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR) InstructionContributionOfBBL1Byte, IARG_UINT32, inst1ByteSize, IARG_THREAD_ID, IARG_END);

        if(inst2ByteSize)
            BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR) InstructionContributionOfBBL2Byte, IARG_UINT32, inst2ByteSize, IARG_THREAD_ID, IARG_END);

        if(inst4ByteSize)
            BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR) InstructionContributionOfBBL4Byte, IARG_UINT32, inst4ByteSize, IARG_THREAD_ID, IARG_END);

        if(inst8ByteSize)
            BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR) InstructionContributionOfBBL8Byte, IARG_UINT32, inst8ByteSize, IARG_THREAD_ID, IARG_END);

        if(inst10ByteSize)
            BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR) InstructionContributionOfBBL10Byte, IARG_UINT32, inst10ByteSize, IARG_THREAD_ID, IARG_END);

        if(inst16ByteSize)
            BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR) InstructionContributionOfBBL16Byte, IARG_UINT32, inst16ByteSize, IARG_THREAD_ID, IARG_END);

        if(instLargeByteSize)
            BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR) InstructionContributionOfBBLLargeByte, IARG_UINT32, instLargeByteSize, IARG_THREAD_ID, IARG_END);
    }
}



// Given a address generated by the program, returns the corresponding shadow address FLOORED to  DEADSPY_PAGE_SIZE
// If the shadow page does not exist a new one is MMAPed

inline uint8_t* GetOrCreateShadowBaseAddress(void* address) {
    // No entries at all ?
    uint8_t* shadowPage;
    uint8_t**  * l1Ptr = &gL1PageTable[LEVEL_1_PAGE_TABLE_SLOT(address)];

    if(*l1Ptr == 0) {
        *l1Ptr = (uint8_t**) calloc(1, LEVEL_2_PAGE_TABLE_SIZE);
        shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] = (uint8_t*) mmap(0, DEADSPY_PAGE_SIZE * (1 + sizeof(uint32_t)), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    } else if((shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)]) == 0) {
        shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] = (uint8_t*) mmap(0, DEADSPY_PAGE_SIZE * (1 + sizeof(uint32_t)), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    }

    return shadowPage;
}

// Given a address generated by the program, returns the corresponding shadow address FLOORED to  DEADSPY_PAGE_SIZE
// If the shadow page does not exist none is created instead 0 is returned

inline uint8_t* GetShadowBaseAddress(void* address) {
    // No entries at all ?
    uint8_t* shadowPage;
    uint8_t** * l1Ptr = &gL1PageTable[LEVEL_1_PAGE_TABLE_SLOT(address)];

    if(*l1Ptr == 0) {
        return 0;
    } else if((shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)]) == 0) {
        return 0;
    }

    return shadowPage;
}



// make 64bit hash from 2 32bit deltas from
// remove lower 3 bits so that when we need more than 4 GB HASH still continues to work

#if 0
#define CONTEXT_HASH_128BITS_TO_64BITS(curCtxt, oldCtxt, hashVar)  \
{\
uint64_t key = (uint64_t) (((void**)oldCtxt) - gPreAllocatedContextBuffer); \
hashVar = key << 32;\
key = (uint64_t) (((void**)curCtxt) - gPreAllocatedContextBuffer); \
hashVar |= key;\
}

#else

#define CONTEXT_HASH_128BITS_TO_64BITS(curCtxt, oldCtxt, hashVar)  \
{\
uint64_t key = (uint64_t) (oldCtxt); \
hashVar = key << 32;\
key = (uint64_t) (curCtxt); \
hashVar |= key;\
}

#endif


#define OLD_CTXT (*lastIP)
// defined in cct lib: #define CUR_CTXT_INDEX (&(tData->gCurrentIPNode[tData->curSlotNo]))


#if defined(CONTINUOUS_DEADINFO)

#define DECLARE_HASHVAR(name) uint64_t name

#define REPORT_DEAD(curCtxt, lastCtxt,hashVar, size) do { \
CONTEXT_HASH_128BITS_TO_64BITS(curCtxt, lastCtxt,hashVar)  \
if ( (gDeadMapIt = DeadMap.find(hashVar))  == DeadMap.end()) {    \
DeadMap.insert(std::pair<uint64_t, uint64_t>(hashVar,size)); \
} else {    \
(gDeadMapIt->second) += size;    \
}   \
}while(0)

#else // no defined(CONTINUOUS_DEADINFO)
#define DECLARE_HASHVAR(name) uint64_t name

#define REPORT_DEAD(curCtxt, lastCtxt,hashVar, size) do { \
CONTEXT_HASH_128BITS_TO_64BITS(curCtxt, lastCtxt,hashVar)  \
if ( (gDeadMapIt = DeadMap.find(hashVar))  == DeadMap.end()) {    \
DeadInfo deadInfo = { lastCtxt,  curCtxt, size };   \
DeadMap.insert(std::pair<uint64_t, DeadInfo>(hashVar,deadInfo)); \
} else {    \
(gDeadMapIt->second.count) += size;    \
}   \
}while(0)

#endif // end defined(CONTINUOUS_DEADINFO)

#define REPORT_IF_DEAD(mask, curCtxt, lastCtxt, hashVar) do {if (state & (mask)){ \
REPORT_DEAD(curCtxt, lastCtxt,hashVar, 1);\
}}while(0)


#ifdef TESTING_BYTES
#define RecordNByteMemWrite(type, size, sizeSTR) do{\
uint8_t * status = GetOrCreateShadowBaseAddress(addr);\
if(PAGE_OFFSET((uint64_t)addr) <  (PAGE_OFFSET_MASK - size - 2)){\
type state = *((type*)(status +  PAGE_OFFSET((uint64_t)addr)));\
if ( state != sizeSTR##_BYTE_READ_ACTION) {\
if (state == sizeSTR##_BYTE_WRITE_ACTION) {\
gFullyKilling##size ++;\
} else {\
gPartiallyKilling##size ++;\
for(type s = state; s != 0 ; s >>= 8)\
if(s & 0xff)\
gPartiallyDeadBytes##size++;\
}\
} \
*((type* )(status +  PAGE_OFFSET((uint64_t)addr))) = sizeSTR##_BYTE_WRITE_ACTION;\
} else {\
type state = *((uint8_t*)(status +  PAGE_OFFSET((uint64_t)addr)));        \
*((uint8_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = ONE_BYTE_WRITE_ACTION;\
uint8_t deadBytes =  state == ONE_BYTE_WRITE_ACTION ? 1 :0;\
for(uint8_t i = 1 ; i < size; i++){\
status = GetOrCreateShadowBaseAddress(((char *) addr ) + i);            \
state = *((uint8_t*)(status +  PAGE_OFFSET((((uint64_t)addr) + i))));\
if(state == ONE_BYTE_WRITE_ACTION)\
deadBytes++;            \
*((uint8_t*)(status +  PAGE_OFFSET((((uint64_t)addr) + i)))) = ONE_BYTE_WRITE_ACTION;\
}\
if(deadBytes == size)\
gFullyKilling##size ++;\
else if(deadBytes){\
gPartiallyKilling##size ++;\
gPartiallyDeadBytes##size += deadBytes;\
}        \
}\
}while(0)

#endif // end TESTING_BYTES


// Analysis routines to update the shadow memory for different size READs and WRITEs


VOID Record1ByteMemRead(VOID* addr) {
    uint8_t* status = GetShadowBaseAddress(addr);

    // status == 0 if not created.
    if(status) {
        // NOT NEEDED status->lastIP = ip;
        *(status + PAGE_OFFSET((uint64_t)addr))  = ONE_BYTE_READ_ACTION;
    }
}


#ifdef TESTING_BYTES
inline VOID Record1ByteMemWrite(VOID* addr) {
    uint8_t* status = GetOrCreateShadowBaseAddress(addr);

    if(*(status +  PAGE_OFFSET((uint64_t)addr)) == ONE_BYTE_WRITE_ACTION) {
        gFullyKilling1 ++;
    }

    *(status +  PAGE_OFFSET((uint64_t)addr)) = ONE_BYTE_WRITE_ACTION;
}

#else  // no TESTING_BYTES
VOID Record1ByteMemWrite(VOID* addr, const uint32_t opaqueHandle, THREADID threadId) {
    uint8_t* status = GetOrCreateShadowBaseAddress(addr);
    const uint32_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
    uint32_t* lastIP = (uint32_t*)(status + DEADSPY_PAGE_SIZE +  PAGE_OFFSET((uint64_t)addr) * sizeof(uint32_t));

    if(*(status +  PAGE_OFFSET((uint64_t)addr)) == ONE_BYTE_WRITE_ACTION) {
        DECLARE_HASHVAR(myhash);
        REPORT_DEAD(curCtxtHandle, OLD_CTXT, myhash, 1);
    } else {
        *(status +  PAGE_OFFSET((uint64_t)addr)) = ONE_BYTE_WRITE_ACTION;
    }

    *lastIP = curCtxtHandle;
}
#endif // end TESTING_BYTES

inline VOID Record1ByteMemWriteWithoutDead(VOID* addr, const uint32_t opaqueHandle, THREADID threadId) {
    uint8_t* status = GetOrCreateShadowBaseAddress(addr);
    const uint32_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
    uint32_t* lastIP = (uint32_t*)(status + DEADSPY_PAGE_SIZE +  PAGE_OFFSET((uint64_t)addr) * sizeof(uint32_t));
    *(status +  PAGE_OFFSET((uint64_t)addr)) = ONE_BYTE_WRITE_ACTION;
    *lastIP = curCtxtHandle;
}


VOID Record2ByteMemRead(VOID* addr) {
    uint8_t* status = GetShadowBaseAddress(addr);

    // status == 0 if not created.
    if(PAGE_OFFSET((uint64_t)addr) != PAGE_OFFSET_MASK) {
        if(status) {
            *((uint16_t*)(status + PAGE_OFFSET((uint64_t)addr)))  = TWO_BYTE_READ_ACTION;
        }
    } else {
        if(status) {
            *(status + PAGE_OFFSET_MASK)  = ONE_BYTE_READ_ACTION;
        }

        status = GetShadowBaseAddress(((char*)addr) + 1);

        if(status) {
            *status  = ONE_BYTE_READ_ACTION;
        }
    }
}
#ifdef TESTING_BYTES
VOID Record2ByteMemWrite(VOID* addr) {
    RecordNByteMemWrite(uint16_t, 2, TWO);
}
#else // no bytes test
VOID Record2ByteMemWrite(VOID* addr, const uint32_t opaqueHandle, THREADID threadId) {
    uint8_t* status = GetOrCreateShadowBaseAddress(addr);
    const uint32_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);

    // status == 0 if not created.
    if(PAGE_OFFSET((uint64_t)addr) != PAGE_OFFSET_MASK) {
        uint32_t* lastIP = (uint32_t*)(status + DEADSPY_PAGE_SIZE +  PAGE_OFFSET((uint64_t)addr) * sizeof(uint32_t));
        uint16_t state = *((uint16_t*)(status +  PAGE_OFFSET((uint64_t)addr)));

        if(state != TWO_BYTE_READ_ACTION) {
            DECLARE_HASHVAR(myhash);

            // fast path where all bytes are dead by same context
            if(state == TWO_BYTE_WRITE_ACTION && lastIP[0] == lastIP[1]) {
                REPORT_DEAD(curCtxtHandle, (*lastIP), myhash, 2);
                // State is already written, so no need to dead write in a tool that detects dead writes
            } else {
                // slow path
                // byte 1 dead ?
                REPORT_IF_DEAD(0x00ff, curCtxtHandle, lastIP[0], myhash);
                // byte 2 dead ?
                REPORT_IF_DEAD(0xff00, curCtxtHandle, lastIP[1], myhash);
                // update state for all
                *((uint16_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = TWO_BYTE_WRITE_ACTION;
            }
        } else {
            // record as written
            *((uint16_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = TWO_BYTE_WRITE_ACTION;
        }

        lastIP[0] = curCtxtHandle;
        lastIP[1] = curCtxtHandle;
    } else {
        Record1ByteMemWrite(addr, opaqueHandle, threadId);
        Record1ByteMemWrite(((char*) addr) + 1, opaqueHandle, threadId);
    }
}
#endif  // end TESTING_BYTES

VOID Record4ByteMemRead(VOID* addr) {
    uint8_t* status = GetShadowBaseAddress(addr);
    // status == 0 if not created.
    int overflow = PAGE_OFFSET((uint64_t)addr) - (PAGE_OFFSET_MASK - 3);

    if(overflow <= 0) {
        if(status) {
            *((uint32_t*)(status + PAGE_OFFSET((uint64_t)addr)))  = FOUR_BYTE_READ_ACTION;
        }
    } else {
        if(status) {
            status += PAGE_OFFSET((uint64_t)addr);

            for(int nonOverflowBytes = 0 ; nonOverflowBytes < 4 - overflow; nonOverflowBytes++) {
                *(status++)  = ONE_BYTE_READ_ACTION;
            }
        }

        status = GetShadowBaseAddress(((char*)addr) + 4);  // +4 so that we get next page

        if(status) {
            for(; overflow; overflow--) {
                *(status++)  = ONE_BYTE_READ_ACTION;
            }
        }
    }
}

#ifdef TESTING_BYTES
VOID Record4ByteMemWrite(VOID* addr) {
    RecordNByteMemWrite(uint32_t, 4, FOUR);
}
#else // no TESTING_BYTES

VOID Record4ByteMemWrite(VOID* addr, const uint32_t opaqueHandle, THREADID threadId) {
    uint8_t* status = GetOrCreateShadowBaseAddress(addr);
    const uint32_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);

    // status == 0 if not created.
    if(PAGE_OFFSET((uint64_t)addr) < (PAGE_OFFSET_MASK - 2)) {
        uint32_t* lastIP = (uint32_t*)(status + DEADSPY_PAGE_SIZE +  PAGE_OFFSET((uint64_t)addr) * sizeof(uint32_t));
        uint32_t state = *((uint32_t*)(status +  PAGE_OFFSET((uint64_t)addr)));

        if(state != FOUR_BYTE_READ_ACTION) {
            DECLARE_HASHVAR(myhash);
            uint32_t ipZero = lastIP[0];

            // fast path where all bytes are dead by same context
            if(state == FOUR_BYTE_WRITE_ACTION &&
                    ipZero == lastIP[0] && ipZero == lastIP[1] && ipZero  == lastIP[2] && ipZero  == lastIP[3]) {
                REPORT_DEAD(curCtxtHandle, ipZero, myhash, 4);
                // State is already written, so no need to dead write in a tool that detects dead writes
            } else {
                // slow path
                // byte 1 dead ?
                REPORT_IF_DEAD(0x000000ff, curCtxtHandle, ipZero, myhash);
                // byte 2 dead ?
                REPORT_IF_DEAD(0x0000ff00, curCtxtHandle, lastIP[1], myhash);
                // byte 3 dead ?
                REPORT_IF_DEAD(0x00ff0000, curCtxtHandle, lastIP[2], myhash);
                // byte 4 dead ?
                REPORT_IF_DEAD(0xff000000, curCtxtHandle, lastIP[3], myhash);
                // update state for all
                *((uint32_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = FOUR_BYTE_WRITE_ACTION;
            }
        } else {
            // record as written
            *((uint32_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = FOUR_BYTE_WRITE_ACTION;
        }

        lastIP[0] = curCtxtHandle;
        lastIP[1] = curCtxtHandle;
        lastIP[2] = curCtxtHandle;
        lastIP[3] = curCtxtHandle;
    } else {
        Record1ByteMemWrite(addr, opaqueHandle, threadId);
        Record1ByteMemWrite(((char*) addr) + 1, opaqueHandle, threadId);
        Record1ByteMemWrite(((char*) addr) + 2, opaqueHandle, threadId);
        Record1ByteMemWrite(((char*) addr) + 3, opaqueHandle, threadId);
    }
}
#endif // end TESTING_BYTES

VOID Record8ByteMemRead(VOID* addr) {
    uint8_t* status = GetShadowBaseAddress(addr);
    // status == 0 if not created.
    int overflow = PAGE_OFFSET((uint64_t)addr) - (PAGE_OFFSET_MASK - 7);

    if(overflow <= 0) {
        if(status) {
            *((uint64_t*)(status + PAGE_OFFSET((uint64_t)addr)))  = EIGHT_BYTE_READ_ACTION;
        }
    } else {
        if(status) {
            status += PAGE_OFFSET((uint64_t)addr);

            for(int nonOverflowBytes = 0 ; nonOverflowBytes < 8 - overflow; nonOverflowBytes++) {
                *(status++)  = ONE_BYTE_READ_ACTION;
            }
        }

        status = GetShadowBaseAddress(((char*)addr) + 8);  // +8 so that we get next page

        if(status) {
            for(; overflow; overflow--) {
                *(status++)  = ONE_BYTE_READ_ACTION;
            }
        }
    }
}

#ifdef TESTING_BYTES
VOID Record8ByteMemWrite(VOID* addr) {
    RecordNByteMemWrite(uint64_t, 8, EIGHT);
}
#else // no TESTING_BYTES

VOID Record8ByteMemWrite(VOID* addr, const uint32_t opaqueHandle, THREADID threadId) {
    uint8_t* status = GetOrCreateShadowBaseAddress(addr);
    const uint32_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);

    // status == 0 if not created.
    if(PAGE_OFFSET((uint64_t)addr) < (PAGE_OFFSET_MASK - 6)) {
        uint32_t* lastIP = (uint32_t*)(status + DEADSPY_PAGE_SIZE +  PAGE_OFFSET((uint64_t)addr) * sizeof(uint32_t));
        uint64_t state = *((uint64_t*)(status +  PAGE_OFFSET((uint64_t)addr)));

        if(state != EIGHT_BYTE_READ_ACTION) {
            DECLARE_HASHVAR(myhash);
            uint32_t ipZero = lastIP[0];

            // fast path where all bytes are dead by same context
            if(state == EIGHT_BYTE_WRITE_ACTION &&
                    ipZero  == lastIP[1] && ipZero  == lastIP[2] &&
                    ipZero  == lastIP[3] && ipZero  == lastIP[4] &&
                    ipZero  == lastIP[5] && ipZero  == lastIP[6] && ipZero  == lastIP[7]) {
                REPORT_DEAD(curCtxtHandle, ipZero, myhash, 8);
                // State is already written, so no need to dead write in a tool that detects dead writes
            } else {
                // slow path
                // byte 1 dead ?
                REPORT_IF_DEAD(0x00000000000000ff, curCtxtHandle, ipZero, myhash);
                // byte 2 dead ?
                REPORT_IF_DEAD(0x000000000000ff00, curCtxtHandle, lastIP[1], myhash);
                // byte 3 dead ?
                REPORT_IF_DEAD(0x0000000000ff0000, curCtxtHandle, lastIP[2], myhash);
                // byte 4 dead ?
                REPORT_IF_DEAD(0x00000000ff000000, curCtxtHandle, lastIP[3], myhash);
                // byte 5 dead ?
                REPORT_IF_DEAD(0x000000ff00000000, curCtxtHandle, lastIP[4], myhash);
                // byte 6 dead ?
                REPORT_IF_DEAD(0x0000ff0000000000, curCtxtHandle, lastIP[5], myhash);
                // byte 7 dead ?
                REPORT_IF_DEAD(0x00ff000000000000, curCtxtHandle, lastIP[6], myhash);
                // byte 8 dead ?
                REPORT_IF_DEAD(0xff00000000000000, curCtxtHandle, lastIP[7], myhash);
                // update state for all
                *((uint64_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
            }
        } else {
            // record as written
            *((uint64_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
        }

        lastIP[0] = curCtxtHandle;
        lastIP[1] = curCtxtHandle;
        lastIP[2] = curCtxtHandle;
        lastIP[3] = curCtxtHandle;
        lastIP[4] = curCtxtHandle;
        lastIP[5] = curCtxtHandle;
        lastIP[6] = curCtxtHandle;
        lastIP[7] = curCtxtHandle;
    } else {
        Record1ByteMemWrite(addr, opaqueHandle, threadId);
        Record1ByteMemWrite(((char*) addr) + 1, opaqueHandle, threadId);
        Record1ByteMemWrite(((char*) addr) + 2, opaqueHandle, threadId);
        Record1ByteMemWrite(((char*) addr) + 3, opaqueHandle, threadId);
        Record1ByteMemWrite(((char*) addr) + 4, opaqueHandle, threadId);
        Record1ByteMemWrite(((char*) addr) + 5, opaqueHandle, threadId);
        Record1ByteMemWrite(((char*) addr) + 6, opaqueHandle, threadId);
        Record1ByteMemWrite(((char*) addr) + 7, opaqueHandle, threadId);
    }
}
#endif      // end TESTING_BYTES

VOID Record10ByteMemRead(VOID* addr) {
    uint8_t* status = GetShadowBaseAddress(addr);
    // status == 0 if not created.
    int overflow = PAGE_OFFSET((uint64_t)addr) - (PAGE_OFFSET_MASK - 15);

    if(overflow <= 0) {
        if(status) {
            *((uint64_t*)(status + PAGE_OFFSET((uint64_t)addr)))  = EIGHT_BYTE_READ_ACTION;
            *((uint16_t*)(status + PAGE_OFFSET(((uint64_t)addr + 8))))  = TWO_BYTE_READ_ACTION;
        }
    } else {
        // slow path
        Record8ByteMemRead(addr);
        Record2ByteMemRead((char*)addr + 8);
    }
}



#ifdef TESTING_BYTES
VOID Record10ByteMemWrite(VOID* addr) {
    uint8_t* status = GetOrCreateShadowBaseAddress(addr);

    if(PAGE_OFFSET((uint64_t)addr) < (PAGE_OFFSET_MASK - 14)) {
        uint64_t state1 = *((uint64_t*)(status +  PAGE_OFFSET((uint64_t)addr)));
        uint16_t state2 = *((uint64_t*)(status +  PAGE_OFFSET(((uint64_t)addr) + 8)));

        if((state1 != EIGHT_BYTE_READ_ACTION) || (state2 != TWO_BYTE_READ_ACTION)) {
            if((state1 == EIGHT_BYTE_WRITE_ACTION) && (state2 == TWO_BYTE_WRITE_ACTION)) {
                gFullyKilling10 ++;
            } else {
                gPartiallyKilling10 ++;

                for(uint64_t s = state1; s != 0 ; s >>= 8)
                    if(s & 0xff)
                        gPartiallyDeadBytes10++;

                for(uint16_t s = state2; s != 0 ; s >>= 8)
                    if(s & 0xff)
                        gPartiallyDeadBytes10++;
            }
        }

        *((uint64_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
        *((uint16_t*)(status +  PAGE_OFFSET(((uint64_t)addr) + 8))) = TWO_BYTE_WRITE_ACTION;
    } else {
        uint8_t state = *((uint8_t*)(status +  PAGE_OFFSET((uint64_t)addr)));
        *((uint8_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = ONE_BYTE_WRITE_ACTION;
        uint8_t deadBytes =  state == ONE_BYTE_WRITE_ACTION ? 1 : 0;

        for(uint8_t i = 1 ; i < 10; i++) {
            status = GetOrCreateShadowBaseAddress(((char*) addr) + i);
            state = *((uint8_t*)(status +  PAGE_OFFSET((((uint64_t)addr) + i))));

            if(state == ONE_BYTE_WRITE_ACTION)
                deadBytes++;

            *((uint8_t*)(status +  PAGE_OFFSET((((uint64_t)addr) + i)))) = ONE_BYTE_WRITE_ACTION;
        }

        if(deadBytes == 10)
            gFullyKilling10 ++;
        else if(deadBytes) {
            gPartiallyKilling10 ++;
            gPartiallyDeadBytes10 += deadBytes;
        }
    }
}
#else // no TESTING_BYTES

VOID Record10ByteMemWrite(VOID* addr, const uint32_t opaqueHandle, THREADID threadId) {
    uint8_t* status = GetOrCreateShadowBaseAddress(addr);
    const uint32_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);

    // status == 0 if not created.
    if(PAGE_OFFSET((uint64_t)addr) < (PAGE_OFFSET_MASK - 8)) {
        uint32_t* lastIP = (uint32_t*)(status + DEADSPY_PAGE_SIZE +  PAGE_OFFSET((uint64_t)addr) * sizeof(uint32_t));
        uint64_t state = *((uint64_t*)(status +  PAGE_OFFSET((uint64_t)addr)));

        if(state != EIGHT_BYTE_READ_ACTION) {
            DECLARE_HASHVAR(myhash);
            uint32_t ipZero = lastIP[0];

            // fast path where all bytes are dead by same context
            if(state == EIGHT_BYTE_WRITE_ACTION &&
                    ipZero  == lastIP[1] && ipZero  == lastIP[2] &&
                    ipZero  == lastIP[3] && ipZero  == lastIP[4] &&
                    ipZero  == lastIP[5] && ipZero  == lastIP[6] && ipZero  == lastIP[7]) {
                REPORT_DEAD(curCtxtHandle, ipZero, myhash, 8);
                // No state update needed
            } else {
                // slow path
                // byte 1 dead ?
                REPORT_IF_DEAD(0x00000000000000ff, curCtxtHandle, ipZero, myhash);
                // byte 2 dead ?
                REPORT_IF_DEAD(0x000000000000ff00, curCtxtHandle, lastIP[1], myhash);
                // byte 3 dead ?
                REPORT_IF_DEAD(0x0000000000ff0000, curCtxtHandle, lastIP[2], myhash);
                // byte 4 dead ?
                REPORT_IF_DEAD(0x00000000ff000000, curCtxtHandle, lastIP[3], myhash);
                // byte 5 dead ?
                REPORT_IF_DEAD(0x000000ff00000000, curCtxtHandle, lastIP[4], myhash);
                // byte 6 dead ?
                REPORT_IF_DEAD(0x0000ff0000000000, curCtxtHandle, lastIP[5], myhash);
                // byte 7 dead ?
                REPORT_IF_DEAD(0x00ff000000000000, curCtxtHandle, lastIP[6], myhash);
                // byte 8 dead ?
                REPORT_IF_DEAD(0xff00000000000000, curCtxtHandle, lastIP[7], myhash);
                // update state of these 8 bytes could be some overwrites
                *((uint64_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
            }
        } else {
            // update state of these 8 bytes
            *((uint64_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
        }

        // This looks like it was a bug, should not OR with 0xffffffffffff0000
        // state = (*((uint16_t*) (status +  PAGE_OFFSET((uint64_t)addr) + 8)) )| 0xffffffffffff0000;
        state = (*((uint16_t*)(status +  PAGE_OFFSET((uint64_t)addr) + 8)));

        if(state != TWO_BYTE_READ_ACTION) {
            DECLARE_HASHVAR(myhash);
            uint32_t ipZero = lastIP[8];

            // fast path where all bytes are dead by same context
            if(state == TWO_BYTE_WRITE_ACTION &&
                    ipZero == lastIP[9]) {
                REPORT_DEAD(curCtxtHandle, ipZero, myhash, 2);
                // No state update needed
            } else {
                // slow path
                // byte 1 dead ?
                REPORT_IF_DEAD(0x00ff, curCtxtHandle, ipZero, myhash);
                // byte 2 dead ?
                REPORT_IF_DEAD(0xff00, curCtxtHandle, lastIP[9], myhash);
                // update state
                *((uint16_t*)(status +  PAGE_OFFSET(((uint64_t)addr + 8)))) = TWO_BYTE_WRITE_ACTION;
            }
        } else {
            // Update state of these 2 bytes
            *((uint16_t*)(status +  PAGE_OFFSET(((uint64_t)addr + 8)))) = TWO_BYTE_WRITE_ACTION;
        }

        lastIP[0] = curCtxtHandle;
        lastIP[1] = curCtxtHandle;
        lastIP[2] = curCtxtHandle;
        lastIP[3] = curCtxtHandle;
        lastIP[4] = curCtxtHandle;
        lastIP[5] = curCtxtHandle;
        lastIP[6] = curCtxtHandle;
        lastIP[7] = curCtxtHandle;
        lastIP[8] = curCtxtHandle;
        lastIP[9] = curCtxtHandle;
    } else {
        for(int i = 0; i < 10; i++) {
            Record1ByteMemWrite(((char*) addr) + i, opaqueHandle, threadId);
        }
    }
}
#endif // end TESTING_BYTES



VOID Record16ByteMemRead(VOID* addr) {
    uint8_t* status = GetShadowBaseAddress(addr);
    // status == 0 if not created.
    int overflow = PAGE_OFFSET((uint64_t)addr) - (PAGE_OFFSET_MASK - 15);

    if(overflow <= 0) {
        if(status) {
            *((uint64_t*)(status + PAGE_OFFSET((uint64_t)addr)))  = EIGHT_BYTE_READ_ACTION;
            *((uint64_t*)(status + PAGE_OFFSET(((uint64_t)addr + 8))))  = EIGHT_BYTE_READ_ACTION;
        }
    } else {
        // slow path
        Record8ByteMemRead(addr);
        Record8ByteMemRead((char*)addr + 8);
    }
}


#ifdef TESTING_BYTES
VOID Record16ByteMemWrite(VOID* addr) {
    uint8_t* status = GetOrCreateShadowBaseAddress(addr);

    if(PAGE_OFFSET((uint64_t)addr) < (PAGE_OFFSET_MASK - 14)) {
        uint64_t state1 = *((uint64_t*)(status +  PAGE_OFFSET((uint64_t)addr)));
        uint64_t state2 = *((uint64_t*)(status +  PAGE_OFFSET(((uint64_t)addr) + 8)));

        if((state1 != EIGHT_BYTE_READ_ACTION) || (state2 != EIGHT_BYTE_READ_ACTION)) {
            if((state1 == EIGHT_BYTE_WRITE_ACTION) && (state2 == EIGHT_BYTE_WRITE_ACTION)) {
                gFullyKilling16 ++;
            } else {
                gPartiallyKilling16 ++;

                for(uint64_t s = state1; s != 0 ; s >>= 8)
                    if(s & 0xff)
                        gPartiallyDeadBytes16++;

                for(uint64_t s = state2; s != 0 ; s >>= 8)
                    if(s & 0xff)
                        gPartiallyDeadBytes16++;
            }
        }

        *((uint64_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
        *((uint64_t*)(status +  PAGE_OFFSET(((uint64_t)addr) + 8))) = EIGHT_BYTE_WRITE_ACTION;
    } else {
        uint8_t state = *((uint8_t*)(status +  PAGE_OFFSET((uint64_t)addr)));
        *((uint8_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = ONE_BYTE_WRITE_ACTION;
        uint8_t deadBytes =  state == ONE_BYTE_WRITE_ACTION ? 1 : 0;

        for(uint8_t i = 1 ; i < 16; i++) {
            status = GetOrCreateShadowBaseAddress(((char*) addr) + i);
            state = *((uint8_t*)(status +  PAGE_OFFSET((((uint64_t)addr) + i))));

            if(state == ONE_BYTE_WRITE_ACTION)
                deadBytes++;

            *((uint8_t*)(status +  PAGE_OFFSET((((uint64_t)addr) + i)))) = ONE_BYTE_WRITE_ACTION;
        }

        if(deadBytes == 16)
            gFullyKilling16 ++;
        else if(deadBytes) {
            gPartiallyKilling16 ++;
            gPartiallyDeadBytes16 += deadBytes;
        }
    }
}
#else // no TESTING_BYTES

VOID Record16ByteMemWrite(VOID* addr, const uint32_t opaqueHandle, THREADID threadId) {
    uint8_t* status = GetOrCreateShadowBaseAddress(addr);
    const uint32_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);

    // status == 0 if not created.
    if(PAGE_OFFSET((uint64_t)addr) < (PAGE_OFFSET_MASK - 14)) {
        uint32_t* lastIP = (uint32_t*)(status + DEADSPY_PAGE_SIZE +  PAGE_OFFSET((uint64_t)addr) * sizeof(uint32_t));
        uint64_t state = *((uint64_t*)(status +  PAGE_OFFSET((uint64_t)addr)));

        if(state != EIGHT_BYTE_READ_ACTION) {
            DECLARE_HASHVAR(myhash);
            uint32_t ipZero = lastIP[0];

            // fast path where all bytes are dead by same context
            if(state == EIGHT_BYTE_WRITE_ACTION &&
                    ipZero  == lastIP[1] && ipZero  == lastIP[2] &&
                    ipZero  == lastIP[3] && ipZero  == lastIP[4] &&
                    ipZero  == lastIP[5] && ipZero  == lastIP[6] && ipZero  == lastIP[7]) {
                REPORT_DEAD(curCtxtHandle, ipZero, myhash, 8);
                // No state update needed
            } else {
                // slow path
                // byte 1 dead ?
                REPORT_IF_DEAD(0x00000000000000ff, curCtxtHandle, ipZero, myhash);
                // byte 2 dead ?
                REPORT_IF_DEAD(0x000000000000ff00, curCtxtHandle, lastIP[1], myhash);
                // byte 3 dead ?
                REPORT_IF_DEAD(0x0000000000ff0000, curCtxtHandle, lastIP[2], myhash);
                // byte 4 dead ?
                REPORT_IF_DEAD(0x00000000ff000000, curCtxtHandle, lastIP[3], myhash);
                // byte 5 dead ?
                REPORT_IF_DEAD(0x000000ff00000000, curCtxtHandle, lastIP[4], myhash);
                // byte 6 dead ?
                REPORT_IF_DEAD(0x0000ff0000000000, curCtxtHandle, lastIP[5], myhash);
                // byte 7 dead ?
                REPORT_IF_DEAD(0x00ff000000000000, curCtxtHandle, lastIP[6], myhash);
                // byte 8 dead ?
                REPORT_IF_DEAD(0xff00000000000000, curCtxtHandle, lastIP[7], myhash);
                // update state of these 8 bytes could be some overwrites
                *((uint64_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
            }
        } else {
            // update state of these 8 bytes
            *((uint64_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
        }

        state = *((uint64_t*)(status +  PAGE_OFFSET((uint64_t)addr) + 8));

        if(state != EIGHT_BYTE_READ_ACTION) {
            DECLARE_HASHVAR(myhash);
            uint32_t ipZero = lastIP[8];

            // fast path where all bytes are dead by same context
            if(state == EIGHT_BYTE_WRITE_ACTION &&
                    ipZero == lastIP[9] && ipZero  == lastIP[10] && ipZero  == lastIP[11] &&
                    ipZero  == lastIP[12] && ipZero  == lastIP[13] &&
                    ipZero  == lastIP[14] && ipZero  == lastIP[15]) {
                REPORT_DEAD(curCtxtHandle, ipZero, myhash, 8);
                // No state update needed
            } else {
                // slow path
                // byte 1 dead ?
                REPORT_IF_DEAD(0x00000000000000ff, curCtxtHandle, ipZero, myhash);
                // byte 2 dead ?
                REPORT_IF_DEAD(0x000000000000ff00, curCtxtHandle, lastIP[9], myhash);
                // byte 3 dead ?
                REPORT_IF_DEAD(0x0000000000ff0000, curCtxtHandle, lastIP[10], myhash);
                // byte 4 dead ?
                REPORT_IF_DEAD(0x00000000ff000000, curCtxtHandle, lastIP[11], myhash);
                // byte 5 dead ?
                REPORT_IF_DEAD(0x000000ff00000000, curCtxtHandle, lastIP[12], myhash);
                // byte 6 dead ?
                REPORT_IF_DEAD(0x0000ff0000000000, curCtxtHandle, lastIP[13], myhash);
                // byte 7 dead ?
                REPORT_IF_DEAD(0x00ff000000000000, curCtxtHandle, lastIP[14], myhash);
                // byte 8 dead ?
                REPORT_IF_DEAD(0xff00000000000000, curCtxtHandle, lastIP[15], myhash);
                // update state
                *((uint64_t*)(status +  PAGE_OFFSET(((uint64_t)addr + 8)))) = EIGHT_BYTE_WRITE_ACTION;
            }
        } else {
            // Update state of these 8 bytes
            *((uint64_t*)(status +  PAGE_OFFSET(((uint64_t)addr + 8)))) = EIGHT_BYTE_WRITE_ACTION;
        }

        lastIP[0] = curCtxtHandle;
        lastIP[1] = curCtxtHandle;
        lastIP[2] = curCtxtHandle;
        lastIP[3] = curCtxtHandle;
        lastIP[4] = curCtxtHandle;
        lastIP[5] = curCtxtHandle;
        lastIP[6] = curCtxtHandle;
        lastIP[7] = curCtxtHandle;
        lastIP[8] = curCtxtHandle;
        lastIP[9] = curCtxtHandle;
        lastIP[10] = curCtxtHandle;
        lastIP[11] = curCtxtHandle;
        lastIP[12] = curCtxtHandle;
        lastIP[13] = curCtxtHandle;
        lastIP[14] = curCtxtHandle;
        lastIP[15] = curCtxtHandle;
    } else {
        for(int i = 0; i < 16; i++) {
            Record1ByteMemWrite(((char*) addr) + i, opaqueHandle, threadId);
        }
    }
}
#endif  // end TESTING_BYTES


//// IMPROVE ME
VOID RecordLargeMemRead(VOID* addr, UINT32 size) {
    for(UINT32 i = 0 ; i < size; i++) {
        uint8_t* status = GetShadowBaseAddress(((char*) addr) + i);

        if(status) {
            *(status + PAGE_OFFSET(((uint64_t)addr + i)))  = ONE_BYTE_READ_ACTION;
        }
    }
}

#ifdef  TESTING_BYTES

VOID RecordLargeMemWrite(VOID* addr, UINT32 size) {
    uint8_t* status ;
    uint8_t state;
    uint8_t deadBytes =  0;

    for(uint8_t i = 0 ; i < size; i++) {
        status = GetOrCreateShadowBaseAddress(((char*) addr) + i);
        state = *((uint8_t*)(status +  PAGE_OFFSET((((uint64_t)addr) + i))));

        if(state == ONE_BYTE_WRITE_ACTION)
            deadBytes++;

        *((uint8_t*)(status +  PAGE_OFFSET((((uint64_t)addr) + i)))) = ONE_BYTE_WRITE_ACTION;
    }

    if(deadBytes == size) {
        gFullyKillingLarge ++;
    } else if(deadBytes) {
        gPartiallyKillingLarge ++;
    }

    // for large we just add them all to partially dead
    gPartiallyDeadBytesLarge += deadBytes;
    //assert(0 && "NOT IMPLEMENTED LARGE WRITE BYTE");
}

#else // no TESTING_BYTES

//// IMPROVE  ME
VOID RecordLargeMemWrite(VOID* addr, UINT32 size, const uint32_t opaqueHandle, THREADID threadId) {
    for(UINT32 i = 0 ; i < size ; i++) {
        // report dead for first byte if needed
        Record1ByteMemWrite((char*)addr + i, opaqueHandle, threadId);
    }
}
#endif      // end TESTING_BYTES

void InspectMemRead(VOID* addr, UINT32 sz) {
    cerr << "\n" << addr << ":" << sz;
}



// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, void* v, const uint32_t opaqueHandle) {
    // Note: predicated instructions are correctly handled as given in PIN's sample example pinatrace.cpp
    /* Comment taken from PIN sample :
     Instruments memory accesses using a predicated call, i.e.
     the instrumentation is called iff the instruction will actually be executed.

     The IA-64 architecture has explicitly predicated instructions.
     On the IA-32 and Intel(R) 64 architectures conditional moves and REP
     prefixed instructions appear as predicated instructions in Pin. */
    // In Multi-threaded skip call, ret and JMP instructions
#ifdef MULTI_THREADED
    if(INS_IsBranchOrCall(ins) || INS_IsRet(ins)) {
        return;
    }

#endif //end MULTI_THREADED
    // How may memory operations?
    UINT32 memOperands = INS_MemoryOperandCount(ins);
#ifdef MULTI_THREADED
    // Support for MT
    // Acquire the lock before starting the analysis routine since we need analysis routine and original instruction to run atomically.
    bool lockNeeded = false;

    if(memOperands) {
        for(UINT32 memOp = 0; memOp < memOperands; memOp++) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) TakeLock, IARG_END);
            lockNeeded = true;
            break;
        }
    }

#endif //end MULTI_THREADED

    // Iterate over each memory operand of the instruction and add Analysis routine to check for dead writes.
    // We correctly handle instructions that do both read and write.

    for(UINT32 memOp = 0; memOp < memOperands; memOp++) {
        UINT32 refSize = INS_MemoryOperandSize(ins, memOp);

        switch(refSize) {
        case 1: {
            if(INS_MemoryOperandIsRead(ins, memOp)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Record1ByteMemRead, IARG_MEMORYOP_EA, memOp, IARG_END);
            }

            if(INS_MemoryOperandIsWritten(ins, memOp)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                         (AFUNPTR) Record1ByteMemWrite,
                                         IARG_MEMORYOP_EA, memOp,
                                         IARG_UINT32, opaqueHandle,
                                         IARG_THREAD_ID, IARG_END);
            }
        }
        break;

        case 2: {
            if(INS_MemoryOperandIsRead(ins, memOp)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Record2ByteMemRead, IARG_MEMORYOP_EA, memOp, IARG_END);
            }

            if(INS_MemoryOperandIsWritten(ins, memOp)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                         (AFUNPTR) Record2ByteMemWrite,
                                         IARG_MEMORYOP_EA, memOp,
                                         IARG_UINT32, opaqueHandle,
                                         IARG_THREAD_ID, IARG_END);
            }
        }
        break;

        case 4: {
            if(INS_MemoryOperandIsRead(ins, memOp)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Record4ByteMemRead, IARG_MEMORYOP_EA, memOp, IARG_END);
            }

            if(INS_MemoryOperandIsWritten(ins, memOp)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                         (AFUNPTR) Record4ByteMemWrite,
                                         IARG_MEMORYOP_EA, memOp,
                                         IARG_UINT32, opaqueHandle,
                                         IARG_THREAD_ID, IARG_END);
            }
        }
        break;

        case 8: {
            if(INS_MemoryOperandIsRead(ins, memOp)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Record8ByteMemRead, IARG_MEMORYOP_EA, memOp, IARG_END);
            }

            if(INS_MemoryOperandIsWritten(ins, memOp)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                         (AFUNPTR) Record8ByteMemWrite,
                                         IARG_MEMORYOP_EA, memOp,
                                         IARG_UINT32, opaqueHandle,
                                         IARG_THREAD_ID, IARG_END);
            }
        }
        break;

        case 10: {
            if(INS_MemoryOperandIsRead(ins, memOp)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Record10ByteMemRead, IARG_MEMORYOP_EA, memOp, IARG_END);
            }

            if(INS_MemoryOperandIsWritten(ins, memOp)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                         (AFUNPTR) Record10ByteMemWrite,
                                         IARG_MEMORYOP_EA, memOp,
                                         IARG_UINT32, opaqueHandle,
                                         IARG_THREAD_ID, IARG_END);
            }
        }
        break;

        case 16: { // SORRY! XMM regs use 16 bits :((
            if(INS_MemoryOperandIsRead(ins, memOp)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Record16ByteMemRead, IARG_MEMORYOP_EA, memOp, IARG_END);
            }

            if(INS_MemoryOperandIsWritten(ins, memOp)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                         (AFUNPTR) Record16ByteMemWrite,
                                         IARG_MEMORYOP_EA, memOp,
                                         IARG_UINT32, opaqueHandle,
                                         IARG_THREAD_ID, IARG_END);
            }
        }
        break;

        default: {
            // seeing some stupid 10, 16, 512 (fxsave)byte operations. Suspecting REP-instructions.
            if(INS_MemoryOperandIsRead(ins, memOp)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) RecordLargeMemRead, IARG_MEMORYOP_EA, memOp, IARG_MEMORYREAD_SIZE, IARG_END);
            }

            if(INS_MemoryOperandIsWritten(ins, memOp)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                         (AFUNPTR) RecordLargeMemWrite,
                                         IARG_MEMORYOP_EA, memOp, IARG_MEMORYWRITE_SIZE,
                                         IARG_UINT32, opaqueHandle,
                                         IARG_THREAD_ID, IARG_END);
            }
        }
        break;
            //assert( 0 && "BAD refSize");
        }
    }

#ifdef MULTI_THREADED

    // Support for MT
    // release the lock if we had taken it
    if(lockNeeded) {
        INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) ReleaseLock, IARG_END);
    }

#endif //end MULTI_THREADED
}

#ifdef TESTING_BYTES
// Prints the collected statistics on writes along with their sizes and dead/killing writes and their sizes
inline VOID PrintInstructionBreakdown() {
    fprintf(gTraceFile, "\n%lu,%lu,%lu,%lu ", g1ByteWriteInstrCount, gFullyKilling1, gPartiallyKilling1, gPartiallyDeadBytes1);
    fprintf(gTraceFile, "\n%lu,%lu,%lu,%lu ", g2ByteWriteInstrCount, gFullyKilling2, gPartiallyKilling2, gPartiallyDeadBytes2);
    fprintf(gTraceFile, "\n%lu,%lu,%lu,%lu ", g4ByteWriteInstrCount, gFullyKilling4, gPartiallyKilling4, gPartiallyDeadBytes4);
    fprintf(gTraceFile, "\n%lu,%lu,%lu,%lu ", g8ByteWriteInstrCount, gFullyKilling8, gPartiallyKilling8, gPartiallyDeadBytes8);
    fprintf(gTraceFile, "\n%lu,%lu,%lu,%lu ", g10ByteWriteInstrCount, gFullyKilling10, gPartiallyKilling10, gPartiallyDeadBytes10);
    fprintf(gTraceFile, "\n%lu,%lu,%lu,%lu ", g16ByteWriteInstrCount, gFullyKilling16, gPartiallyKilling16, gPartiallyDeadBytes16);
    fprintf(gTraceFile, "\n%lu,%lu,%lu,%lu,%lu ", gLargeByteWriteInstrCount,  gFullyKillingLarge, gPartiallyKillingLarge, gLargeByteWriteByteCount, gPartiallyDeadBytesLarge);
}
#endif //end TESTING_BYTES



// Returns the total N-byte size writes across all CCTs
uint64_t GetTotalNByteWrites(uint32_t size) {
    uint64_t total = 0;

    for(uint32_t i = 0 ; i < gClientNumThreads; i++) {
        DeadSpyThreadData* tData = ClientGetTLS(i);

        switch(size) {
        case 1: {
            total += tData->g1ByteWriteInstrCount;
            break;
        }

        case 2: {
            total += tData->g2ByteWriteInstrCount;
            break;
        }

        case 4: {
            total += tData->g4ByteWriteInstrCount;
            break;
        }

        case 8: {
            total += tData->g8ByteWriteInstrCount;
            break;
        }

        case 10: {
            total += tData->g10ByteWriteInstrCount;
            break;
        }

        case 16: {
            total += tData->g16ByteWriteInstrCount;
            break;
        }

        default: {
            // Not too sure :(
            total += tData->gLargeByteWriteInstrCount;
            break;
        }
        }
    }//end for

    return total;
}

inline uint64_t GetMeasurementBaseCount() {
    // byte count
    uint64_t measurementBaseCount =  GetTotalNByteWrites(1) + 2 * GetTotalNByteWrites(2) + 4 * GetTotalNByteWrites(4) + 8 * GetTotalNByteWrites(8) + 10 * GetTotalNByteWrites(10) + 16 * GetTotalNByteWrites(16) + GetTotalNByteWrites(-1);
    return measurementBaseCount;
}

// Prints the collected statistics on writes along with their sizes
inline void PrintEachSizeWrite() {
    fprintf(gTraceFile, "\n1:%" PRIu64, GetTotalNByteWrites(1));
    fprintf(gTraceFile, "\n2:%" PRIu64, GetTotalNByteWrites(2));
    fprintf(gTraceFile, "\n4:%" PRIu64, GetTotalNByteWrites(4));
    fprintf(gTraceFile, "\n8:%" PRIu64, GetTotalNByteWrites(8));
    fprintf(gTraceFile, "\n10:%" PRIu64, GetTotalNByteWrites(10));
    fprintf(gTraceFile, "\n16:%" PRIu64, GetTotalNByteWrites(16));
    fprintf(gTraceFile, "\nother:%" PRIu64, GetTotalNByteWrites(-1));
}



// On program termination output all gathered data and statistics
VOID Fini(INT32 code, VOID* v) {
    // Serialize CCTLib
    SerializeMetadata("DeadSpy-CCTLib-database");
    // byte count
    uint64_t measurementBaseCount = GetMeasurementBaseCount();
    fprintf(gTraceFile, "\n#deads");
    fprintf(gTraceFile, "\nGrandTotalWrites = %" PRIu64, measurementBaseCount);
    fprintf(gTraceFile, "\nGrandTotalDead = %" PRIu64 " = %e%%", gTotalDead, gTotalDead * 100.0 / measurementBaseCount);
#ifdef MULTI_THREADED
    fprintf(gTraceFile, "\nGrandTotalMTDead = %" PRIu64 " = %e%%", gTotalMTDead, gTotalMTDead * 100.0 / measurementBaseCount);
#endif // end MULTI_THREADED
    fprintf(gTraceFile, "\n#eof");
    fclose(gTraceFile);
    if(KnobTopN.Value())
        topnStream.close();
}


// When we make System calls we need to update the shadow regions with the effect of the system call
// TODO: handle other system calls. Currently only SYS_write is handled.

VOID SyscallEntry(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std,
                  VOID* v) {
    ADDRINT number = PIN_GetSyscallNumber(ctxt, std);

    switch(number) {
    case SYS_write: {
        char* bufStart = (char*) PIN_GetSyscallArgument(ctxt, std, 1);
        char* bufEnd = bufStart
                       + (size_t) PIN_GetSyscallArgument(ctxt, std, 2);
#ifdef DEBUG
        printf("\n WRITE %p - %p\n", bufStart, bufEnd);
#endif //end DEBUG

        while(bufStart < bufEnd)
            Record1ByteMemRead(bufStart++);
    }
    break;

    default:
        break;//NOP
    }
}



struct MergedDeadInfo {
    uint32_t context1;
    uint32_t context2;

    bool operator==(const MergedDeadInfo&   x) const {
        if(this->context1 == x.context1 && this->context2 == x.context2)
            return true;

        return false;
    }

    bool operator<(const MergedDeadInfo& x) const {
        if((this->context1 < x.context1) ||
                (this->context1 == x.context1 && this->context2 < x.context2))
            return true;

        return false;
    }
};

struct DeadInfoForPresentation {
    const MergedDeadInfo* pMergedDeadInfo;
    uint64_t count;
};







inline bool MergedDeadInfoComparer(const DeadInfoForPresentation& first, const DeadInfoForPresentation&  second) {
    return first.count > second.count ? true : false;
}// Returns true if the given deadinfo belongs to one of the loaded binaries
inline bool IsValidIP(DeadInfo  di) {
    bool res = false;

    for(IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
        if((ADDRINT)di.firstIP >= IMG_LowAddress(img) && (ADDRINT)di.firstIP <= IMG_HighAddress(img)) {
            res = true;
            break;
        }
    }

    if(!res)
        return false;

    for(IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
        if((ADDRINT)di.secondIP >= IMG_LowAddress(img) && (ADDRINT)di.secondIP <= IMG_HighAddress(img)) {
            return true;
        }
    }

    return false;
}


// Prints the complete calling context including the line nunbers and the context's contribution, given a DeadInfo
inline VOID PrintIPAndCallingContexts(const DeadInfoForPresentation& di, uint64_t measurementBaseCount) {
    fprintf(gTraceFile, "\n%" PRIu64 " = %e", di.count, di.count * 100.0 / measurementBaseCount);
    fprintf(gTraceFile, "\n-------------------------------------------------------\n");
    PrintFullCallingContext(di.pMergedDeadInfo->context1);
    fprintf(gTraceFile, "\n***********************\n");
    PrintFullCallingContext(di.pMergedDeadInfo->context2);
    fprintf(gTraceFile, "\n-------------------------------------------------------\n");
}


// On each Unload of a loaded image, the accummulated deadness information is dumped
VOID ImageUnload(IMG img, VOID* v) {
    fprintf(gTraceFile, "\nUnloading %s", IMG_Name(img).c_str());
    // Update gTotalInstCount first
    uint64_t measurementBaseCount =  GetMeasurementBaseCount();
    fprintf(gTraceFile, "\nTotal Instr = %" PRIu64 , measurementBaseCount);
    fflush(gTraceFile);
    unordered_map<uint64_t, uint64_t>::iterator mapIt = DeadMap.begin();
    map<MergedDeadInfo, uint64_t> mergedDeadInfoMap;

    for(; mapIt != DeadMap.end(); mapIt++) {
        MergedDeadInfo tmpMergedDeadInfo;
        uint64_t hash = mapIt->first;
        uint32_t ctxt1 = (hash >> 32);
        uint32_t ctxt2 = (hash & 0xffffffff);
        tmpMergedDeadInfo.context1 = ctxt1;
        tmpMergedDeadInfo.context2 = ctxt2;
        map<MergedDeadInfo, uint64_t>::iterator tmpIt;

        if((tmpIt = mergedDeadInfoMap.find(tmpMergedDeadInfo)) == mergedDeadInfoMap.end()) {
            mergedDeadInfoMap[tmpMergedDeadInfo] = mapIt->second;
        } else {
            tmpIt->second  += mapIt->second;
        }
    }

    // clear dead map now
    DeadMap.clear();
    map<MergedDeadInfo, uint64_t>::iterator it = mergedDeadInfoMap.begin();
    list<DeadInfoForPresentation> deadList;

    for(; it != mergedDeadInfoMap.end(); it ++) {
        DeadInfoForPresentation deadInfoForPresentation;
        deadInfoForPresentation.pMergedDeadInfo = &(it->first);
        deadInfoForPresentation.count = it->second;
        deadList.push_back(deadInfoForPresentation);
    }

    deadList.sort(MergedDeadInfoComparer);
    //present and delete all
    list<DeadInfoForPresentation>::iterator dipIter = deadList.begin();
    PIN_LockClient();
    uint64_t deads = 0;

    for(; dipIter != deadList.end(); dipIter++) {
#ifdef MULTI_THREADED
        assert(0 && "NYI");
#endif //end MULTI_THREADED

        // Print just first MAX_DEAD_CONTEXTS_TO_LOG contexts
        if(deads < MAX_DEAD_CONTEXTS_TO_LOG) {
#if PIN_CRT != 1
            try {
                PrintIPAndCallingContexts(*dipIter, measurementBaseCount);
            } catch(...) {
                fprintf(gTraceFile, "\nexcept");
            }
#else
            PrintIPAndCallingContexts(*dipIter, measurementBaseCount);
#endif
        } else {
            // print only dead count
#ifdef PRINT_ALL_CTXT
            fprintf(gTraceFile, "\nCTXT_DEAD_CNT:%lu = %e", dipIter->count, dipIter->count * 100.0 / measurementBaseCount);
#endif                //end PRINT_ALL_CTXT
        }

        gTotalDead += dipIter->count ;
        deads++;
    }

static bool done = false;
if(KnobTopN.Value() && (!done)){
done = true;
    // Produce a log of Top 10
    dipIter = deadList.begin();
     topnStream<<"<LOADMODULES>";
     AppendLoadModulesToStream(topnStream);
     topnStream<<"\n</LOADMODULES>\n<TOPN>";
    for(UINT32 topN = 0; dipIter != deadList.end() && (topN <KnobTopN.Value()) ; dipIter++, topN++) {
     topnStream <<"\n"<<(*dipIter).count<<":"<< (*dipIter).count * 1.0 / gTotalDead<<":";
     LogContexts(topnStream, (*dipIter).pMergedDeadInfo->context2 /* kill first*/, (*dipIter).pMergedDeadInfo->context1);
    }
     topnStream<<"\n</TOPN>";
}
    PrintEachSizeWrite();
#ifdef TESTING_BYTES
    PrintInstructionBreakdown();
#endif //end TESTING_BYTES
#ifdef GATHER_STATS
    PrintStats(deadList, deads);
#endif //end GATHER_STATS
    mergedDeadInfoMap.clear();
    deadList.clear();
    PIN_UnlockClient();
}





// Initialized the needed data structures before launching the target program
void InitDeadSpy(int argc, char* argv[]) {
    // Create output file
    char name[MAX_FILE_PATH] = "deadspy.out.";
    char* envPath = getenv("DEADSPY_OUTPUT_FILE");

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
    if(KnobTopN.Value()) {
       topnStream.open ((string(name) + ".topn").c_str(), std::fstream::out | std::fstream::trunc);
       topnStream<<"\n";
       for(int i = 0 ; i < argc; i++) {
        topnStream << argv[i] << " ";
       }
       topnStream<<"\n";
    }

#ifdef GATHER_STATS
    string statFileName(name);
    statFileName += ".stats";
    statsFile = fopen(statFileName.c_str() , "w");
    fprintf(statsFile, "\n");

    for(int i = 0 ; i < argc; i++) {
        fprintf(statsFile, "%s ", argv[i]);
    }

    fprintf(statsFile, "\n");
#endif //end   GATHER_STATS
}

static INT32 Usage() {
    PIN_ERROR("DeadSPy is a PinTool which tracks each memory access and reports dead writes.\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}


static VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    DeadSpyThreadData* tdata = new DeadSpyThreadData();
    InitThreadData(tdata);
    __sync_fetch_and_add(&gClientNumThreads, 1);
    PIN_SetThreadData(client_tls_key, tdata, threadid);
}


// Main for DeadSpy, initialize the tool, register instrumentation functions and call the target program.

int main(int argc, char* argv[]) {
    // Initialize PIN
    if(PIN_Init(argc, argv))
        return Usage();

    // Initialize Symbols, we need them to report functions and lines
    PIN_InitSymbols();
    // Intialize DeadSpy
    InitDeadSpy(argc, argv);
    // Intialize CCTLib
    PinCCTLibInit(INTERESTING_INS_MEMORY_ACCESS, gTraceFile, Instruction, 0, /*doDataCentric=*/ false);
    // Obtain  a key for TLS storage.
    client_tls_key = PIN_CreateThreadDataKey(0 /*TODO have a destructir*/);
    // Register ThreadStart to be called when a thread starts.
    PIN_AddThreadStartFunction(ThreadStart, 0);
    // capture write or other sys call that read from user space
    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    // Instrument instruction
    TRACE_AddInstrumentFunction(InstrumentTrace, 0);
    // Register ImageUnload to be called when an image is unloaded
    IMG_AddUnloadFunction(ImageUnload, 0);
    // Add a function to report entire stats at the termination.
    PIN_AddFiniFunction(Fini, 0);
    // Launch program now
    PIN_StartProgram();
    return 0;
}


