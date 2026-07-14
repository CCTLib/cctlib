// @COPYRIGHT@
// Licensed under MIT license.
// See LICENSE.TXT file in the project root for more information.
// ==============================================================
#include <set>
#include "cctlib.H"
#include "shadow_memory.H"
#define __STDC_FORMAT_MACROS
#include <stdio.h>
#include <stdlib.h>
#include "pin.H"
#include <map>
#include <unordered_map>
#include <vector>
#include <list>
#include <inttypes.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <libgen.h>
#include <locale>
#include <unistd.h>
#include <sys/syscall.h>
#include <assert.h>
#include <sys/mman.h>
#include <exception>
#include <sys/time.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <setjmp.h>
#include <sstream>
#include <limits.h>
#include <dirent.h>
#include <unwind.h>
#include <sys/resource.h>

// CCTLib historically had an optional Boost dependency (guarded by USE_BOOST)
// for two tiny things -- std::to_string() didn't exist pre-C++11 and there
// was no std trim. Both are handled with C++11 now. Boost is also
// explicitly unsupported by Pin RT (no RTTI in Pin's libcxx), so we do not
// include or link Boost anywhere.
static inline void CCTLibTrimInPlace(std::string& s) {
    const char* ws = " \t\n\r\f\v";
    size_t b = s.find_first_not_of(ws);
    if (b == std::string::npos) {
        s.clear();
        return;
    }
    size_t e = s.find_last_not_of(ws);
    s = s.substr(b, e - b + 1);
}

#ifdef TARGET_MAC
#include <libelf/libelf.h>
#include <libelf/gelf.h>
#elif defined(TARGET_LINUX)
#include <libelf.h>
#include <gelf.h>
#else
"Unsupported platform"
#endif


#include "splay-macros.h"
// Need GOOGLE sparse hash tables
#include <google/sparse_hash_map>
#include <google/dense_hash_map>
// XED for printing instr
extern "C" {
#include "xed-interface.h"
}

using google::sparse_hash_map; // namespace where class lives by default
using namespace std;

namespace PinCCTLib {

// All globals
#define USE_SPLAY_TREE
#define MAX_PATH_NAME 1024
#define MALLOC_FN_NAME "malloc"
#define CALLOC_FN_NAME "calloc"
#define REALLOC_FN_NAME "realloc"
#define FREE_FN_NAME "free"


#define CCTLIB_SERIALIZATION_DEFAULT_DIR_NAME "cctlib-database-"
#ifndef MAX_IPNODES
#if defined(TARGET_IA32E)
// 2^32  IPNODES
#define MAX_IPNODES (1L << 32)
#elif defined(TARGET_IA32)
// 1M IPNODES
#define MAX_IPNODES (1L << 20)
#else
"SHOULD NEVER REACH HERE"
#endif
#endif

#ifndef MAX_STRING_POOL_NODES
#if defined(TARGET_IA32E)
// 2^32  IPNODES
#define MAX_STRING_POOL_NODES (1L << 30)
#elif defined(TARGET_IA32)
// 1M charaters
#define MAX_STRING_POOL_NODES (1L << 20)
#else
    "SHOULD NEVER REACH HERE"
#endif
#endif

// Assuming 128 byte line size.
#define CACHE_LINE_SIZE (128)


#define GET_CONTEXT_HANDLE_FROM_IP_NODE_CHECKED(node) ((ContextHandle_t)((node) ? ((node)-GLOBAL_STATE.preAllocatedContextBuffer) : 0))
#define GET_IPNODE_FROM_CONTEXT_HANDLE_CHECKED(handle) ((handle) ? (GLOBAL_STATE.preAllocatedContextBuffer + (handle)) : NULL)

#define GET_CONTEXT_HANDLE_FROM_IP_NODE(node) ((ContextHandle_t)((node)-GLOBAL_STATE.preAllocatedContextBuffer))
#define GET_IPNODE_FROM_CONTEXT_HANDLE(handle) (GLOBAL_STATE.preAllocatedContextBuffer + handle)
#define IS_VALID_CONTEXT(c) (c != 0)


#define BREAK_HERE raise(SIGINT)

//Serialization related macros
#define SERIALIZED_SHADOW_TRACE_IP_FILE_SUFFIX "/TraceMap.traceShadowMap"
#define SERIALIZED_CCT_FILE_PREFIX "/Thread-"
#define SERIALIZED_CCT_FILE_EXTN ".cct"
#define SERIALIZED_CCT_FILE_SUFFIX "-CCTMap.cct"

// Platform specific macros
#ifdef TARGET_MAC
#define MAP_ANONYMOUS MAP_ANON
typedef uintptr_t _Unwind_Ptr;
#endif

struct _Unwind_Context;


/******** Fwd declarations **********/
struct TraceNode;
struct SerializedTraceNode;
struct IPNode;
struct TraceSplay;
struct ModuleInfo;
struct QNode;
struct NewIPNode;

#ifdef USE_TREE_BASED_FOR_DATA_CENTRIC

#define LOCKED (1)
#define UNLOCKED (0)
#define UNLOCKED_AND_PREDECESSOR_WAS_WRITER (2)

struct varType;
struct PendingOps_t;
struct ConcurrentReaderWriterTree_t;
using varSet = set<varType>;
#endif

static inline ADDRINT GetIPFromInfo(ContextHandle_t);
static inline void SetIPFromInfo(ContextHandle_t ctxtHndle, ADDRINT val);
static inline const string& GetModulePathFromInfo(IPNode* ipNode);
static inline void GetLineFromInfo(const ADDRINT& ip, uint32_t& lineNo, string& filePath);

static inline bool IsValidIP(ADDRINT ip);

static void SerializeCCTNode(TraceNode* traceNode, FILE* const fp);
enum CCTLibUsageMode { CCT_LIB_MODE_COLLECTION = 1,
                       CCT_LIB_MODE_POSTMORTEM = 2 };


#ifdef USE_TREE_BASED_FOR_DATA_CENTRIC
enum AccessStatus { START_READING = 0,
                    END_READING = 1,
                    WAITING_WRITE = 3,
                    WRITE_STARTED = 4 };
#endif


/******** Data structures **********/
struct TraceNode {
    ContextHandle_t callerCtxtHndl;
    ContextHandle_t childCtxtStartIdx;
    uint32_t traceKey; // max of 2^32 traces allowed
    uint32_t nSlots;
};

struct SerializedTraceNode {
    uint32_t traceKey;
    uint32_t nSlots;
    ContextHandle_t childCtxtStartIdx;
};


struct TraceSplay {
    ADDRINT key;
    TraceNode* value;
    TraceSplay* left;
    TraceSplay* right;
};

struct IPNode {
    TraceNode* parentTraceNode;
#ifdef USE_SPLAY_TREE
    TraceSplay* calleeTraceNodes;
#else
    sparse_hash_map<ADDRINT, TraceNode*>* calleeTraceNodes;
#endif

#ifdef HAVE_METRIC_PER_IPNODE
    void* metric;
#endif
};

using QNode = struct QNode {
    struct QNode* volatile next;
    union {
        struct {
            volatile bool locked : 1;
            volatile bool predecessorWasWriter : 1;
        };
        volatile uint8_t status;
    };
};

// should become TLS
struct ThreadData {
    uint8_t pad0[CACHE_LINE_SIZE];
#ifndef USE_SPLAY_TREE
    sparse_hash_map<ADDRINT, TraceNode*>::iterator gTraceIter;
#endif

    uint32_t tlsThreadId; // useful only during deserialization
    ContextHandle_t tlsCurrentCtxtHndl;
    ContextHandle_t tlsCurrentChildContextStartIndex;
    struct TraceNode* tlsCurrentTraceNode;
    ContextHandle_t tlsRootCtxtHndl;
    struct TraceNode* tlsRootTraceNode;
    bool tlsInitiatedCall;

    struct TraceNode* tlsParentThreadTraceNode;
    ContextHandle_t tlsParentThreadCtxtHndl;


    sparse_hash_map<ADDRINT, ContextHandle_t> tlsLongJmpMap;
    ADDRINT tlsLongJmpHoldBuf;

    uint32_t curSlotNo;

    // Landing-pad re-anchor state. See design notes on
    // CaptureLandingPadTarget + InstrumentTraceEntry's reset block.
    //
    //   tlsPendingLandingPadIp   -- set at _Unwind_SetIP entry to the
    //                               resume IP the personality function
    //                               just installed. Consumed on the
    //                               next Pin trace entry whose first
    //                               IP matches; then cleared.
    //   tlsPendingHandlerFrame   -- the CCT TraceNode of the frame
    //                               that owns the landing pad
    //                               (identified by walking the parent
    //                               chain looking for a frame whose
    //                               ipShadow slots fall inside the
    //                               target function's address range).
    //   tlsPendingHandlerCtxt    -- the ctxt handle within that frame
    //                               to re-anchor tlsCurrentCtxtHndl to.
    //
    // Necessary because libgcc's _Unwind_RaiseException / _Unwind_Resume
    // / _Unwind_ForcedUnwind never RET on a caught unwind -- they
    // transfer via __builtin_eh_return, which is not a `ret` insn and
    // therefore not a valid hookpoint for the pre-existing "reset on
    // last RET" scheme. The (SetIP-entry, matching-trace-entry) pair
    // is the reliable substitute.
    ADDRINT tlsPendingLandingPadIp;
    struct TraceNode* tlsPendingHandlerFrame;
    ContextHandle_t tlsPendingHandlerCtxt;
    void* tlsStackBase;
    void* tlsStackEnd;


    //DO_DATA_CENTRIC
    size_t tlsDynamicMemoryAllocationSize;
    ContextHandle_t tlsDynamicMemoryAllocationPathHandle;
#ifdef USE_TREE_BASED_FOR_DATA_CENTRIC
    uint8_t pad1[CACHE_LINE_SIZE];
    uint32_t rwLockStatus;
    uint8_t pad2[CACHE_LINE_SIZE];
    struct ConcurrentReaderWriterTree_t* tlsLatestConcurrentTree;
    uint8_t pad3[CACHE_LINE_SIZE];
    volatile uint8_t tlsMallocDSAccessStatus;
    uint8_t pad4[CACHE_LINE_SIZE];
#endif
    // TODO .. identify why perf screws up w/o this buffer
    // For hpcrun format -- report the number of new CCT nodes
    uint64_t nodeCount;
    NewIPNode* tlsHPCRunCCTRoot;
    uint8_t pad5[CACHE_LINE_SIZE];
};


//DO_DATA_CENTRIC

// Data centric support

#ifdef USE_TREE_BASED_FOR_DATA_CENTRIC


struct varType {
    void* start;
    void* end;
    union {
        uint32_t pathHandle;
        uint32_t symName;
    };
    uint8_t objectType;
    varType(void* s, void* e, uint32_t handle, uint8_t type)
        : start(s), end(e), pathHandle(handle), objectType(type) {}
};

bool operator<(varType const& a, varType const& b) {
    return (ADDRINT)a.start < (ADDRINT)b.start;
}

struct PendingOps_t {
    uint8_t pad0[CACHE_LINE_SIZE];
    uint8_t operation;
    varType var;
    PendingOps_t(const uint8_t o, varType const& v)
        : operation(o), var(v) {}
};

enum { INSERT = 0,
       DELETE = 1 };

struct ConcurrentReaderWriterTree_t {
    vector<PendingOps_t> pendingOps;
    varSet tree;
};

#endif


// Information about loaded images.
struct ModuleInfo {
    // a ID used for hpcrun format
    uint16_t id;
    // name
    string moduleName;
    //Offset from the image's link-time address to its load-time address.
    ADDRINT imgLoadOffset;
};

// Per-routine info populated by GetOrClassifyRoutine() the first time
// we see any Pin trace of a routine. Used to fold direct self-recursion:
//   * hasSelfRec         -- true if the routine contains any direct call
//                           whose immediate target equals its own entry.
//   * selfRecReturnAddrs -- exact set of INS_NextAddress(callIns) for
//                           each such direct self-call. On a RET, if
//                           the return target matches any of these, the
//                           RET is unwinding a collapsed recursion
//                           frame and we must NOT walk up the CCT.
// The address set is derived from decoded CALL immediates -- it is
// independent of RTN_Size / any symbol- or loader-derived range, so it
// works on stripped binaries and around function padding.
struct RtnInfo {
    ADDRINT rtnStart;
    bool hasSelfRec;
    uint16_t nReturnAddrs;
    ADDRINT* selfRecReturnAddrs; // heap array, typically 1-4 entries
};

/******** Globals variables **********/
#define MAX_METRICS (10)
#define MAX_LEN (128)

struct CCT_LIB_GLOBAL_STATE {
    // record the IP of the first instruction in main
    bool skip; // whether we want to skip all the frames above main; default is false
    void (*mergeFunc)(void* des, void* src); // merge metrics in nodes
    uint64_t (*computeMetricVal)(void* metric); // convert the metric pointer to a value
    ADDRINT mainIP;
    int nmetric;
    char metrics[MAX_METRICS][MAX_LEN];
    // Should data-centric attribution be perfomed?
    bool doDataCentric; // false  by default
    bool applicationStarted; // false by default
    uint8_t cctLibUsageMode;
    FILE* CCTLibLogFile;
    CCTLibInstrumentInsCallback userInstrumentationCallback;
    VOID* userInstrumentationCallbackArg;
    char disassemblyBuff[200]; // string of 0 by default
    /// XED state
    xed_state_t cct_xed_state;
    // prefix string for flushing all data for post processing.
    string CCTLibFilePathPrefix;
    IPNode* preAllocatedContextBuffer;
    char* preAllocatedStringPool;
    // SEGVHANDLEING FOR BAD .plt
    jmp_buf env;
    struct sigaction sigAct;
    //Load module info
    unordered_map<UINT32, ModuleInfo> ModuleInfoMap;
    // Per-routine direct-self-recursion classifier cache, populated
    // lazily by GetOrClassifyRoutine() on first sight of any trace of
    // a routine. Guarded by rtnSelfRecRWMutex: reader-writer because
    // once a routine is classified every subsequent trace-instrument
    // pass only reads (lookup), so the common path takes the read lock
    // and can proceed concurrently across worker threads. The write
    // lock is taken only for the first insert per routine.
    unordered_map<ADDRINT, RtnInfo> rtnSelfRecMap;
    PIN_RWMUTEX rtnSelfRecRWMutex;
    uint8_t padRtnSelfRec[CACHE_LINE_SIZE];
    // serialization directory path
    string serializationDirectory;
    // Deserialized CCTs
    vector<ThreadData> deserializedCCTs;
    //dense_hash_map<ADDRINT, void *> traceShadowMap;
    unordered_map<uint32_t, void*> traceShadowMap;
    uint8_t pad13[CACHE_LINE_SIZE];
    PIN_LOCK lock;
    uint8_t pad0[CACHE_LINE_SIZE];
    // key for accessing TLS storage in the threads. initialized once in main()
    TLS_KEY CCTLibTlsKey; // align to eliminate any false sharing with other  members
    uint8_t pad1[CACHE_LINE_SIZE];
    uint32_t numThreads; // initial value = 0  // align to eliminate any false sharing with other  members
    uint8_t pad2[CACHE_LINE_SIZE];
    uint32_t curPreAllocatedStringPoolIndex; // align to eliminate any false sharing with other  members
    uint8_t pad3[CACHE_LINE_SIZE];
    uint64_t curPreAllocatedContextBufferIndex; // align to eliminate any false sharing with other  members
    uint8_t pad4[CACHE_LINE_SIZE];
    // keys to associate parent child threads
    volatile uint64_t threadCreateCount; // initial value = 0  // align to eliminate any false sharing with other  members
    uint8_t pad5[CACHE_LINE_SIZE];
    volatile uint64_t threadCaptureCount; // initial value = 0  // align to eliminate any false sharing with other  members
    uint8_t pad6[CACHE_LINE_SIZE];
    volatile TraceNode* threadCreatorTraceNode; // align to eliminate any false sharing with other  members
    uint8_t pad7[CACHE_LINE_SIZE];
    volatile ContextHandle_t threadCreatorCtxtHndl; // align to eliminate any false sharing with other  members
    uint8_t pad8[CACHE_LINE_SIZE];
    volatile bool DSLock;
    uint8_t pad9[CACHE_LINE_SIZE];
#ifdef USE_TREE_BASED_FOR_DATA_CENTRIC
    //Data centric support
    unordered_map<UINT32, vector<PendingOps_t>> staticVariablesInModule;
    uint8_t pad10[CACHE_LINE_SIZE];
    volatile ConcurrentReaderWriterTree_t* latestConcurrentTree;
    uint8_t pad11[CACHE_LINE_SIZE];
    ConcurrentReaderWriterTree_t concurrentReaderWriterTree[2];
    uint8_t pad12[CACHE_LINE_SIZE];
#endif
} static GLOBAL_STATE;

static void SegvHandler(int);


/******** Function definitions **********/


inline BOOL IsCallOrRetIns(INS ins) {
    if (INS_IsProcedureCall(ins))
        return true;

    if (INS_IsRet(ins))
        return true;

    return false;
}


// function to get the next unique key for a trace
ADDRINT GetNextTraceKey() {
    static uint32_t traceKey = 0;
    uint32_t key = __sync_fetch_and_add(&traceKey, 1);

    if (key == UINT_MAX) {
        fprintf(stderr, "\n UINT_MAX traces created! Exiting...\n");
        PIN_ExitProcess(-1);
    }

    return key;
}

// function to access thread-specific data
static inline ThreadData* CCTLibGetTLS(const THREADID threadId) {
    ThreadData* tdata =
        static_cast<ThreadData*>(PIN_GetThreadData(GLOBAL_STATE.CCTLibTlsKey, threadId));
    return tdata;
}

// This function is for dumping call path from debugger.
void DumpCallStack(THREADID id, uint32_t slot) {
    ThreadData* tData = CCTLibGetTLS(id);
    fprintf(stderr, "\n slot =%u, max = %u\n", slot, tData->tlsCurrentTraceNode->nSlots);
    PIN_LockClient();
    ContextHandle_t h = tData->tlsCurrentTraceNode->childCtxtStartIdx + slot;
    fprintf(stderr, "\n");
    vector<Context> contextVec;
    GetFullCallingContext(h, contextVec);

    for (uint32_t i = 0; i < contextVec.size(); i++) {
        fprintf(stderr, "\n%u:%p:%s:%s:%s:%u", contextVec[i].ctxtHandle, (void*)contextVec[i].ip, contextVec[i].disassembly.c_str(), contextVec[i].functionName.c_str(), contextVec[i].filePath.c_str(), contextVec[i].lineNo);
    }

    PIN_UnlockClient();
}

// This function is for dumping call path from debugger.
void DumpCallStackEasy() {
    DumpCallStack(PIN_ThreadId(), 0);
}


#if 0
    static int SetJmpOverride(const CONTEXT* 	ctxt, 	THREADID 	tid, AFUNPTR gOriginalSetjmpRtn, jmp_buf env) {
        int ret = -1;
        PIN_CallApplicationFunction(ctxt,
                                    tid,
                                    CALLINGSTD_DEFAULT,
                                    gOriginalSetjmpRtn,
                                    PIN_PARG(int), &ret,
                                    PIN_PARG(void*), env,
                                    PIN_PARG_END());

        if(ret == 0) {
            // Remember the context.
            fprintf(stderr, "\n Here due to SetJmp\n");
        } else {
            //
            fprintf(stderr, "\n Here due to LongJmp\n");
        }

        return ret;
    }
#endif

static inline void UpdateCurTraceAndIp(ThreadData* tData, TraceNode* const trace, ContextHandle_t const ctxtHndle) {
    tData->tlsCurrentTraceNode = trace;
    tData->tlsCurrentChildContextStartIndex = trace->childCtxtStartIdx;
    tData->tlsCurrentCtxtHndl = ctxtHndle;
}

static inline void UpdateCurTraceAndIp(ThreadData* tData, TraceNode* const trace) {
    UpdateCurTraceAndIp(tData, trace, trace->childCtxtStartIdx);
}

static inline void UpdateCurTraceOnly(ThreadData* tData, TraceNode* const trace) {
    tData->tlsCurrentTraceNode = trace;
    tData->tlsCurrentChildContextStartIndex = trace->childCtxtStartIdx;
}


static inline VOID CaptureSigSetJmpCtxt(ADDRINT buf, THREADID threadId) {
    ThreadData* tData = CCTLibGetTLS(threadId);
    // Does not work when a trace has zero IPs!! tData->tlsLongJmpMap[buf] = tData->tlsCurrentCtxtHndl->parentTraceNode->callerCtxtHndl;
    tData->tlsLongJmpMap[buf] = tData->tlsCurrentTraceNode->callerCtxtHndl;
    //fprintf(GLOBAL_STATE.CCTLibLogFile,"\n CaptureSetJmpCtxt buf = %lu, tData->tlsCurrentCtxtHndl = %p", buf, tData->tlsCurrentCtxtHndl);
}

static inline VOID HoldLongJmpBuf(ADDRINT buf, THREADID threadId) {
    ThreadData* tData = CCTLibGetTLS(threadId);
    tData->tlsLongJmpHoldBuf = buf;
    //fprintf(GLOBAL_STATE.CCTLibLogFile,"\n HoldLongJmpBuf tlsLongJmpHoldBuf = %lu, tData->tlsCurrentCtxtHndl = %p", tData->tlsLongJmpHoldBuf, tData->tlsCurrentCtxtHndl);
}

static inline VOID RestoreSigLongJmpCtxt(THREADID threadId) {
    ThreadData* tData = CCTLibGetTLS(threadId);
    assert(tData->tlsLongJmpHoldBuf);
    tData->tlsCurrentCtxtHndl = tData->tlsLongJmpMap[tData->tlsLongJmpHoldBuf];
    UpdateCurTraceOnly(tData, GET_IPNODE_FROM_CONTEXT_HANDLE(tData->tlsCurrentCtxtHndl)->parentTraceNode);
    tData->tlsLongJmpHoldBuf = 0; // reset so that next time we can check if it was set correctly.
    //fprintf(GLOBAL_STATE.CCTLibLogFile,"\n RestoreSigLongJmpCtxt2 tlsLongJmpHoldBuf = %lu",tData->tlsLongJmpHoldBuf);
}

static int GetInstructionLength(ADDRINT ip) {
    // Get the instruction in a string
    xed_decoded_inst_t xedd;
    /// XED state
    xed_decoded_inst_zero_set_mode(&xedd, &GLOBAL_STATE.cct_xed_state);

    if (XED_ERROR_NONE == xed_decode(&xedd, (const xed_uint8_t*)(ip), 15)) {
        return xed_decoded_inst_get_length(&xedd);
    } else {
        assert(0 && "failed to disassemble instruction");
        return 0;
    }
}

static bool IsCallInstruction(ADDRINT ip) {
    // Get the instruction in a string
    xed_decoded_inst_t xedd;
    /// XED state
    xed_decoded_inst_zero_set_mode(&xedd, &GLOBAL_STATE.cct_xed_state);

    if (XED_ERROR_NONE == xed_decode(&xedd, (const xed_uint8_t*)(ip), 15)) {
        return XED_CATEGORY_CALL == xed_decoded_inst_get_category(&xedd);
    } else {
        assert(0 && "failed to disassemble instruction");
        return false;
    }
}

// -----------------------------------------------------------------------------
// C++ exception (Itanium ABI / DWARF2) hook implementation.
//
// The reliable landing-pad-delivery signal is the pair (`_Unwind_SetIP`
// entry, next Pin trace entry whose first IP == the target IP). At
// `_Unwind_SetIP` entry, the personality function has just installed
// the resume IP; libgcc's driver will next call `uw_install_context`,
// which is a macro expanding to `__builtin_eh_return` that pops N
// frames and JMPs to that IP -- no `ret` instruction fires, so the
// prior "reset on _Unwind_RaiseException's last RET" scheme silently
// missed every caught exception. See ~/gcc/libgcc/unwind.inc:140,
// ~/gcc/libgcc/unwind-dw2.c:1398-1407 and Itanium C++ ABI §1.6.
//
// This section replaces the pre-existing (and pre-existingly-broken)
// heuristic `IsIpPresentInTrace` / `FindNearestCallerCoveringIP` /
// `X86_*_CALL_SITE_ADDR_FROM_RETURN_ADDR` / `SetCurTraceNodeAfterException*`
// with a two-part protocol:
//   (a) At _Unwind_SetIP entry, CaptureLandingPadTarget records the
//       target IP, identifies the handler frame by walking cctlib's
//       parent chain for a TraceNode whose ipShadow slots fall inside
//       the target function (via RTN_FindByAddress on the target IP),
//       and stashes (target_ip, frame, ctxt) in TLS as pending.
//   (b) At the top of InstrumentTraceEntry (below), if the current
//       trace's first IP matches the pending landing pad, re-anchor
//       tlsCurrentTraceNode to the handler frame and take the sibling
//       branch so the landing pad's Pin trace becomes a SIBLING of the
//       handler's own trace under the same parent. The landing pad's
//       first-insn IP resolves via RTN_FindNameByAddress to the
//       handler's function name, so downstream chains read
//       `handler-caller -> handler -> ...` correctly.
// -----------------------------------------------------------------------------

// True iff some slot of `trace` holds an IP that falls in [lo, hi).
// Cheaper than RTN_FindByAddress per slot -- we already have the raw
// IPs in the traceShadowMap.
static bool TraceIsInAddressRange(TraceNode* trace, ADDRINT lo, ADDRINT hi) {
    ADDRINT* ips = (ADDRINT*)GLOBAL_STATE.traceShadowMap[trace->traceKey];
    if (!ips)
        return false;
    for (uint32_t i = 0; i < trace->nSlots; ++i) {
        if (ips[i] >= lo && ips[i] < hi)
            return true;
    }
    return false;
}

// Walk tData's CCT parent chain looking for the OUTERMOST TraceNode
// that is inside the address range of the routine containing
// `landingPadIp`. Outermost (not innermost) because on the second
// unwind iteration of a `try{}catch{}` loop, an earlier iteration's
// landing-pad Pin trace is also inside the handler function's
// address range -- picking THAT one would nest each iteration's
// re-anchor under the previous one and chains would grow linearly
// with iteration count. Walking to the root and keeping the LAST
// match gives us the ORIGINAL handler frame every time.
//
// Returns NULL if the routine can't be identified (stripped / foreign
// image) or no ancestor matches. Callers on the NULL path skip
// re-anchoring, which is a benign degradation.
static TraceNode* FindHandlerFrameForLandingPad(ADDRINT landingPadIp,
                                                ADDRINT* outHandlerLo,
                                                ADDRINT* outHandlerHi,
                                                ThreadData* tData) {
    PIN_LockClient();
    RTN targetRtn = RTN_FindByAddress(landingPadIp);
    ADDRINT lo = 0, hi = 0;
    if (RTN_Valid(targetRtn)) {
        lo = RTN_Address(targetRtn);
        hi = lo + RTN_Size(targetRtn);
    }
    PIN_UnlockClient();
    if (lo == hi)
        return NULL; // unrecognized image / stripped

    TraceNode* best = NULL;
    TraceNode* cur = tData->tlsCurrentTraceNode;
    while (cur) {
        if (TraceIsInAddressRange(cur, lo, hi)) {
            best = cur; // keep walking -- want the OUTERMOST match
        }
        if (cur == tData->tlsRootTraceNode)
            break;
        cur = GLOBAL_STATE.preAllocatedContextBuffer[cur->callerCtxtHndl].parentTraceNode;
    }
    if (best) {
        if (outHandlerLo)
            *outHandlerLo = lo;
        if (outHandlerHi)
            *outHandlerHi = hi;
    }
    return best;
}

static VOID CaptureLandingPadTarget(VOID* /*exceptionCallerContext*/, ADDRINT landingPadIp, THREADID threadId) {
    // The IP being written by _Unwind_SetIP is passed as the SECOND
    // argument. We hook at IPOINT_BEFORE, so reading the context's IP
    // via _Unwind_GetIP() would return the OLD value (the throwing call's
    // return address), NOT the landing pad. Taking the second argument
    // directly gives us the actual jump target that libgcc's
    // uw_install_context will __builtin_eh_return to next.
    //
    // Bonus: we don't touch the _Unwind_Context struct, so the historic
    // Pin-vs-libgcc _Unwind_Context layout hazard (which used to require
    // an image-load-time RTN lookup of the application's _Unwind_GetIP)
    // is irrelevant here.

    ThreadData* tData = CCTLibGetTLS(threadId);
    ADDRINT lo = 0, hi = 0;
    TraceNode* handler = FindHandlerFrameForLandingPad(landingPadIp, &lo, &hi, tData);
    if (!handler) {
        // Can't identify the handler frame -- either the landing pad
        // is in an unrecognized image or the parent chain is empty of
        // matching frames. Skip the reset; the pre-existing anchor
        // stays put and the CCT for this unwind may be less precise
        // but is not corrupted.
        tData->tlsPendingLandingPadIp = 0;
        tData->tlsPendingHandlerFrame = NULL;
        tData->tlsPendingHandlerCtxt = 0;
        return;
    }
    tData->tlsPendingLandingPadIp = landingPadIp;
    tData->tlsPendingHandlerFrame = handler;
    tData->tlsPendingHandlerCtxt = handler->childCtxtStartIdx;
}

inline VOID TakeLock() {
    do {
        while (GLOBAL_STATE.DSLock)
            ;
    } while (!__sync_bool_compare_and_swap(&GLOBAL_STATE.DSLock, false, true));
}

inline VOID ReleaseLock() {
    GLOBAL_STATE.DSLock = false;
}


// Pauses creator thread from thread creation until
// the previously created child thread has noted its parent.
static inline void ThreadCreatePoint(THREADID threadId) {
    while (true) {
        TakeLock();

        if (GLOBAL_STATE.threadCreateCount > GLOBAL_STATE.threadCaptureCount)
            ReleaseLock();
        else
            break;
    }

    GLOBAL_STATE.threadCreatorTraceNode = CCTLibGetTLS(threadId)->tlsCurrentTraceNode;
    GLOBAL_STATE.threadCreatorCtxtHndl = CCTLibGetTLS(threadId)->tlsCurrentCtxtHndl;
    //fprintf(GLOBAL_STATE.CCTLibLogFile, "\n ThreadCreatePoint, parent Trace = %p, parent ip = %p", GLOBAL_STATE.threadCreatorTraceNode, GLOBAL_STATE.threadCreatorCtxtHndl);
    GLOBAL_STATE.threadCreateCount++;
    ReleaseLock();
}


// Sets the child thread's CCT's parent to its creator thread's CCT node.
static inline void ThreadCapturePoint(ThreadData* tdata) {
    TakeLock();

    if (GLOBAL_STATE.threadCreateCount == GLOBAL_STATE.threadCaptureCount) {
        // Base thread, no parent
        //fprintf(GLOBAL_STATE.CCTLibLogFile, "\n ThreadCapturePoint, no parent ");
    } else {
        tdata->tlsParentThreadTraceNode = (TraceNode*)GLOBAL_STATE.threadCreatorTraceNode;
        tdata->tlsParentThreadCtxtHndl = GLOBAL_STATE.threadCreatorCtxtHndl;
        //fprintf(GLOBAL_STATE.CCTLibLogFile, "\n ThreadCapturePoint, parent Trace = %p, parent ip = %p", GLOBAL_STATE.threadCreatorTraceNode, GLOBAL_STATE.threadCreatorCtxtHndl);
        GLOBAL_STATE.threadCaptureCount++;
    }

    ReleaseLock();
}


static inline ContextHandle_t GetNextIPVecBuffer(uint32_t num) {
    uint64_t oldBufIndex = __sync_fetch_and_add(&GLOBAL_STATE.curPreAllocatedContextBufferIndex, num);

    if (oldBufIndex + num >= MAX_IPNODES) {
        //printf("\nPreallocated IPNodes exhausted. CCTLib couldn't fit your application in its memory. Try a smaller program.\n");
        fprintf(GLOBAL_STATE.CCTLibLogFile, "\nPreallocated IPNodes exhausted. CCTLib couldn't fit your application in its memory. Try a smaller program.\n");
        PIN_ExitProcess(-1);
    }

    return (ContextHandle_t)oldBufIndex;
}

/*
            Description:
                    Client tools call this API when they need the char string for a symbol from string pool index.
            Arguments:
                    index: a string pool index 
    */
char* GetStringFromStringPool(const uint32_t index) {
    return GLOBAL_STATE.preAllocatedStringPool + index;
}

static inline uint32_t GetNextStringPoolIndex(char* name) {
    uint32_t len = strlen(name) + 1;
    uint64_t oldStringPoolIndex = __sync_fetch_and_add(&GLOBAL_STATE.curPreAllocatedStringPoolIndex, len);

    if (oldStringPoolIndex + len >= MAX_STRING_POOL_NODES) {
        fprintf(GLOBAL_STATE.CCTLibLogFile, "\nPreallocated String Pool exhausted. CCTLib couldn't fit your application in its memory. Try by changing MAX_STRING_POOL_NODES macro.\n");
        PIN_ExitProcess(-1);
    }

    // copy contents
    strncpy(GLOBAL_STATE.preAllocatedStringPool + oldStringPoolIndex, name, len);
    return oldStringPoolIndex;
}

static inline void CCTLibInitThreadData(ThreadData* const tdata, CONTEXT* ctxt, THREADID threadId) {
    TraceNode* t = new TraceNode();
    t->callerCtxtHndl = 0;
    t->nSlots = 1;
    t->childCtxtStartIdx = GetNextIPVecBuffer(1);
    IPNode* ipNode = GET_IPNODE_FROM_CONTEXT_HANDLE(t->childCtxtStartIdx);
    ipNode->parentTraceNode = t;
#ifdef USE_SPLAY_TREE
    ipNode->calleeTraceNodes = nullptr;
#else
    ipNode->calleeTraceNodes = new sparse_hash_map<ADDRINT, TraceNode*>();
#endif
#ifdef HAVE_METRIC_PER_IPNODE
    ipNode->metric = NULL;
#endif
    tdata->tlsThreadId = threadId;
    tdata->tlsRootTraceNode = t;
    tdata->tlsRootCtxtHndl = t->childCtxtStartIdx;
    UpdateCurTraceAndIp(tdata, t);
    tdata->tlsParentThreadCtxtHndl = 0;
    tdata->tlsParentThreadTraceNode = nullptr;
    tdata->tlsInitiatedCall = true;
    tdata->curSlotNo = 0;
    tdata->tlsPendingLandingPadIp = 0;
    tdata->tlsPendingHandlerFrame = NULL;
    tdata->tlsPendingHandlerCtxt = 0;
    // init the dummy root for hpcrun format
    tdata->tlsHPCRunCCTRoot = NULL;

    // Set stack sizes if data-centric is needed
    if (GLOBAL_STATE.doDataCentric) {
        ADDRINT s = PIN_GetContextReg(ctxt, REG_STACK_PTR);
        tdata->tlsStackBase = (void*)s;
        struct rlimit rlim;

        if (getrlimit(RLIMIT_STACK, &rlim)) {
            cerr << "\n Failed to getrlimit()\n";
            PIN_ExitProcess(-1);
        }

        if (rlim.rlim_cur == RLIM_INFINITY) {
            cerr << "\n Need a finite stack size. Dont use unlimited.\n";
            PIN_ExitProcess(-1);
        }

        tdata->tlsStackEnd = (void*)(s - rlim.rlim_cur);
    }

#ifdef USE_TREE_BASED_FOR_DATA_CENTRIC
    tdata->tlsMallocDSAccessStatus = END_READING;
#endif
}

static VOID CCTLibThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    PIN_GetLock(&GLOBAL_STATE.lock, threadid + 1);
    GLOBAL_STATE.numThreads++;
    PIN_ReleaseLock(&GLOBAL_STATE.lock);
    ThreadData* tdata = new ThreadData();
    CCTLibInitThreadData(tdata, ctxt, threadid);
    PIN_SetThreadData(GLOBAL_STATE.CCTLibTlsKey, tdata, threadid);
    ThreadCapturePoint(tdata);
}

// Classify a routine's direct self-recursive call sites. Called once
// per routine at instrumentation time; the result is cached in
// GLOBAL_STATE.rtnSelfRecMap. hasSelfRec is true when the routine
// contains at least one direct call whose immediate target equals its
// own entry address. selfRecReturnAddrs is the exact set of
// INS_NextAddress(callIns) for each such site -- used at RET-time to
// distinguish a return unwinding a collapsed recursion frame (target
// in set -> no-op) from a return to the actual caller (target not in
// set -> normal pop). The set is derived from decoded CALL immediates
// -- independent of RTN_Size or any symbol/loader-derived metadata,
// so it works on stripped binaries and around function padding.
//
// The map is guarded by a reader-writer lock: the common path (a
// routine we've already classified) takes only the read lock and lets
// concurrent Pin worker threads instrument in parallel. The write
// lock is taken exactly once per routine, on first classification.
static const RtnInfo* GetOrClassifyRoutine(RTN rtn) {
    ADDRINT rtnStart = RTN_Address(rtn);

    // Fast path: reader lock. Iterator remains valid across insert as
    // long as we hold at least a read lock -- but we release the read
    // lock before the walk, so we don't hold locks during RTN_Open,
    // instruction decode, or malloc. The pointer we return points at
    // an entry in an unordered_map; std::unordered_map guarantees
    // reference/pointer stability across insert (only iterators over
    // buckets can be invalidated on rehash). Callers hold no reference
    // beyond the instrumentation callback's scope.
    PIN_RWMutexReadLock(&GLOBAL_STATE.rtnSelfRecRWMutex);
    auto it = GLOBAL_STATE.rtnSelfRecMap.find(rtnStart);
    if (it != GLOBAL_STATE.rtnSelfRecMap.end()) {
        const RtnInfo* p = &it->second;
        PIN_RWMutexUnlock(&GLOBAL_STATE.rtnSelfRecRWMutex);
        return p;
    }
    PIN_RWMutexUnlock(&GLOBAL_STATE.rtnSelfRecRWMutex);

    // Slow path: walk the routine's instructions to collect direct
    // self-call sites. Done outside any lock -- expensive and
    // idempotent; a losing racer just discards its result.
    // RTN_Open/RTN_Close scopes access to RTN_InsHead/INS_Next.
    RTN_Open(rtn);
    std::vector<ADDRINT> rets;
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
        if (INS_IsProcedureCall(ins) &&
            INS_IsDirectControlFlow(ins) &&
            INS_DirectControlFlowTargetAddress(ins) == rtnStart) {
            rets.push_back(INS_NextAddress(ins));
        }
    }
    RTN_Close(rtn);

    RtnInfo info;
    info.rtnStart = rtnStart;
    info.hasSelfRec = !rets.empty();
    // uint16_t is plenty; a routine with 65535 direct self-call sites
    // is not realistic. Silently cap and pretend we saw fewer to keep
    // the RET fast-path bounded.
    info.nReturnAddrs = (uint16_t)(rets.size() > UINT16_MAX ? UINT16_MAX : rets.size());
    if (info.nReturnAddrs > 0) {
        info.selfRecReturnAddrs = (ADDRINT*)malloc(sizeof(ADDRINT) * info.nReturnAddrs);
        for (uint16_t i = 0; i < info.nReturnAddrs; ++i) {
            info.selfRecReturnAddrs[i] = rets[i];
        }
    } else {
        info.selfRecReturnAddrs = nullptr;
    }

    PIN_RWMutexWriteLock(&GLOBAL_STATE.rtnSelfRecRWMutex);
    // Another thread may have raced us; std::unordered_map::emplace
    // returns an iterator to the existing element in that case and we
    // leak our freshly-allocated array. Compare-and-set to avoid it.
    auto ins = GLOBAL_STATE.rtnSelfRecMap.emplace(rtnStart, info);
    if (!ins.second) {
        // We lost the race. Free our copy; return theirs.
        if (info.selfRecReturnAddrs)
            free(info.selfRecReturnAddrs);
    }
    const RtnInfo* p = &ins.first->second;
    PIN_RWMutexUnlock(&GLOBAL_STATE.rtnSelfRecRWMutex);
    return p;
}

// Analysis routine called on making a function call
static inline VOID SetCallInitFlag(uint32_t slot, THREADID threadId) {
    ThreadData* tData = CCTLibGetTLS(threadId);
    tData->tlsInitiatedCall = true;
    tData->tlsCurrentCtxtHndl = tData->tlsCurrentChildContextStartIndex + slot;
#if 0
        ADDRINT* tracesIPs = (ADDRINT*)GLOBAL_STATE.traceShadowMap[tData->tlsCurrentTraceNode->traceKey];
        printf("\n Calling from IP = %p", tracesIPs[slot]);
#endif
}

// Analysis routine called on function return.
// Point gCurrentContext to its parent, if we reach the root, set tlsInitiatedCall.
static inline VOID GoUpCallChain(THREADID threadId) {
    ThreadData* tData = CCTLibGetTLS(threadId);

    // If we reach the root trace, then fake the call
    if (tData->tlsCurrentTraceNode->callerCtxtHndl == tData->tlsRootCtxtHndl) {
        tData->tlsInitiatedCall = true;
    }

    tData->tlsCurrentCtxtHndl = tData->tlsCurrentTraceNode->callerCtxtHndl;
    UpdateCurTraceOnly(tData, GET_IPNODE_FROM_CONTEXT_HANDLE(tData->tlsCurrentCtxtHndl)->parentTraceNode);
    // RET & CALL end a trace hence the target should trigger a new trace entry for us ... pray pray.
#if 0
        ADDRINT* tracesIPs = (ADDRINT*)GLOBAL_STATE.traceShadowMap[tData->tlsCurrentTraceNode->traceKey];
        int offset =  tData->tlsCurrentCtxtHndl - tData->tlsCurrentTraceNode->childCtxtStartIdx;
        printf("\n Returning to the caller IP = %p", tracesIPs[offset]);
#endif
}

// Analysis routine for RET in routines with hasSelfRec=true. If the
// return target matches any INS_NextAddress(callIns) of a direct self
// call in this routine, we are unwinding a collapsed recursion frame
// and must NOT walk up the CCT -- doing so would strand tData at an
// ancestor of the true caller when the outermost RET fires. If the
// target is not in the set, this is the outermost RET (returning to
// the actual caller); behave like GoUpCallChain.
//
// n is bounded (typically 1-4, hard-capped at UINT16_MAX by the
// classifier) so the linear scan is trivially cheap and, per Pin
// conventions, kept off the pointer-chasing path when possible.
static inline VOID MaybeGoUpCallChain(ADDRINT retTarget,
                                      const ADDRINT* returnAddrs, uint32_t n,
                                      THREADID threadId) {
    for (uint32_t i = 0; i < n; ++i) {
        if (returnAddrs[i] == retTarget)
            return; // recursion-return: no-op
    }
    ThreadData* tData = CCTLibGetTLS(threadId);
    if (tData->tlsCurrentTraceNode->callerCtxtHndl == tData->tlsRootCtxtHndl) {
        tData->tlsInitiatedCall = true;
    }
    tData->tlsCurrentCtxtHndl = tData->tlsCurrentTraceNode->callerCtxtHndl;
    UpdateCurTraceOnly(tData,
                       GET_IPNODE_FROM_CONTEXT_HANDLE(tData->tlsCurrentCtxtHndl)->parentTraceNode);
}

// Analysis routine called interesting instructions to remember the slot no.
static inline VOID RememberSlotNoInTLS(uint32_t slot, THREADID threadId) {
    ThreadData* tData = CCTLibGetTLS(threadId);
    tData->curSlotNo = slot;
}

/*
    static inline uint32_t GetNumInsInTrace(const TRACE& trace) {
        uint32_t count = 0;

        for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
            for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
                count++;
            }
        }

        return count;
    }
*/

static inline uint32_t GetNumInterestingInsInTrace(const TRACE& trace, IsInterestingInsFptr isInterestingIns) {
    uint32_t count = 0;

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            // cal ret are always interesting for us :)
            if (IsCallOrRetIns(ins) || isInterestingIns(ins))
                count++;
        }
    }

    return count;
}

// Record the data about this image in a table
// Not written thread safe, but PIN guarantees that instrumentation functions are not called concurrently.
static inline VOID CCTLibInstrumentImageLoad(IMG img, VOID* v) {
    UINT32 id = IMG_Id(img);
    ModuleInfo mi;
    if (IMG_IsMainExecutable(img))
        mi.id = 1;
    else
        mi.id = 0;
    mi.moduleName = IMG_Name(img);
    mi.imgLoadOffset = IMG_LoadOffset(img);
    GLOBAL_STATE.ModuleInfoMap[id] = mi;
}


// Called each time a new trace is JITed.
// Given a trace this function adds instruction to each instruction in the trace.
// It also adds the trace to a hash table "GLOBAL_STATE.traceShadowMap" to maintain the reverse mapping from an (interesting) instruction's position in CCT back to its IP.
static inline VOID PopulateIPReverseMapAndAccountTraceInstructions(TRACE trace, uint32_t traceKey, uint32_t numInterestingInstInTrace, IsInterestingInsFptr isInterestingIns, const RtnInfo* rinfo) {
    // if there were 0 numInterestingInstInTrace, then let us simply return since it makes no sense to record anything about it.
    if (numInterestingInstInTrace == 0)
        return;

    ADDRINT* ipShadow = (ADDRINT*)malloc((2 + numInterestingInstInTrace) * sizeof(ADDRINT)); // +1 to hold the number of slots as a metadata and ++1 to hold module id
    // Record the number of instructions in the trace as the first entry
    ipShadow[0] = numInterestingInstInTrace;
    // Record the module id as 2nd entry
    ipShadow[1] = IMG_Id(IMG_FindByAddress(TRACE_Address(trace)));
    uint32_t slot = 0;
    GLOBAL_STATE.traceShadowMap[traceKey] = &ipShadow[2]; // 0th entry is 2 behind

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            // If it is a call/ret instruction, we need to adjust the CCT.
            // manage context
            if (INS_IsProcedureCall(ins)) {
                // Fold direct self-recursion: at a direct call whose
                // immediate target is the enclosing routine's entry,
                // suppress SetCallInitFlag so the callee's
                // InstrumentTraceEntry takes its sibling-branch and
                // splays under the same collapsed frame. See design
                // notes at RtnInfo/MaybeGoUpCallChain above.
                bool isDirectSelfRec = rinfo && rinfo->hasSelfRec && INS_IsDirectControlFlow(ins) && INS_DirectControlFlowTargetAddress(ins) == rinfo->rtnStart;
                if (!isDirectSelfRec) {
                    // INS_InsertPredicatedCall if the call is not made, we should not set the flag
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)SetCallInitFlag, IARG_UINT32, slot, IARG_THREAD_ID, IARG_END);
                }

                if (GLOBAL_STATE.userInstrumentationCallback) {
                    // Call user instrumentation passing the flag
                    if (isInterestingIns(ins))
                        GLOBAL_STATE.userInstrumentationCallback(ins, GLOBAL_STATE.userInstrumentationCallbackArg, slot);
                } else {
                    // TLS will remember your slot no.
                    // TODO: should this be INS_InsertPredicatedCall? not sure. One can argue either ways.
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RememberSlotNoInTLS, IARG_UINT32, slot, IARG_THREAD_ID, IARG_END);
                }

                // put next slot in corresponding ins start location;
                ipShadow[slot + 2] = INS_Address(ins); // +2 because the first 2 entries hold metadata
                slot++;
            } else if (INS_IsRet(ins)) {
                // INS_InsertPredicatedCall if the RET is not made, we should not change CCT node
                // CALL_ORDER_LAST because we want update context after all analysis routines for RET have executed.
                if (rinfo && rinfo->hasSelfRec) {
                    // Fold direct self-recursion: a RET whose target is
                    // in the routine's set of direct-self-call return
                    // addresses is unwinding a collapsed frame -- no-op.
                    // The outermost RET returns to the actual caller,
                    // whose address is outside the routine's body and
                    // therefore never in the set: exactly one pop fires.
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)MaybeGoUpCallChain,
                                             IARG_CALL_ORDER, CALL_ORDER_LAST,
                                             IARG_BRANCH_TARGET_ADDR,
                                             IARG_PTR, rinfo->selfRecReturnAddrs,
                                             IARG_UINT32, (uint32_t)rinfo->nReturnAddrs,
                                             IARG_THREAD_ID, IARG_END);
                } else {
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)GoUpCallChain, IARG_CALL_ORDER, CALL_ORDER_LAST, IARG_THREAD_ID, IARG_END);
                }

                if (GLOBAL_STATE.userInstrumentationCallback) {
                    // Call user instrumentation passing the flag
                    if (isInterestingIns(ins))
                        GLOBAL_STATE.userInstrumentationCallback(ins, GLOBAL_STATE.userInstrumentationCallbackArg, slot);
                } else {
                    // TLS will remember your slot no.
                    // TODO: should this be INS_InsertPredicatedCall? not sure. One can argue either ways.
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RememberSlotNoInTLS, IARG_UINT32, slot, IARG_THREAD_ID, IARG_END);
                }

                // put next slot in corresponding ins start location;
                ipShadow[slot + 2] = INS_Address(ins); // +2 because the first 2 entries hold metadata
                slot++;
            } else if (isInterestingIns(ins)) {
                if (GLOBAL_STATE.userInstrumentationCallback) {
                    // Call user instrumentation passing the flag
                    GLOBAL_STATE.userInstrumentationCallback(ins, GLOBAL_STATE.userInstrumentationCallbackArg, slot);
                } else {
                    // If, it is an interesting Ins, then we need to hold on to the slot number.
                    // TLS will remember your slot no.
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RememberSlotNoInTLS, IARG_UINT32, slot, IARG_THREAD_ID, IARG_END);
                }

                // put next slot in corresponding ins start location;
                ipShadow[slot + 2] = INS_Address(ins); // +2 because the first 2 entries hold metadata
                slot++;
            } else {
                // NOP
            }
        }
    }
}

static struct TraceSplay* splay(struct TraceSplay* root, ADDRINT ip) {
    REGULAR_SPLAY_TREE(TraceSplay, root, ip, key, left, right);
    return root;
}


// Does necessary work on a trace entry (called during runtime)
// 1. If landed here due to function call, then go down in CCT.
// 2. Look up the current trace under the CCT node creating new if if needed.
// 3. Update iterators and curXXXX pointers.

static inline void InstrumentTraceEntry(uint32_t traceKey, uint32_t numInterestingInstInTrace, ADDRINT traceFirstIp, THREADID threadId) {
    ThreadData* tData = CCTLibGetTLS(threadId);

    // Post-exception landing-pad re-anchor. See the design notes above
    // CaptureLandingPadTarget: if a _Unwind_SetIP call armed a pending
    // landing pad and THIS trace's first IP matches, libgcc just
    // context-restored into the handler frame and we need to move
    // tlsCurrentTraceNode back to that frame BEFORE the sibling/normal
    // branch logic below runs. tlsInitiatedCall=false forces the
    // sibling branch so the landing pad's own Pin trace becomes a
    // sibling of the handler's own trace under the same parent --
    // giving chains like `handler_caller -> handler(landing pad) -> C`
    // for the post-catch path (landing pad's function name resolves
    // to the handler's since its IP lies inside the handler's body).
    if (tData->tlsPendingLandingPadIp != 0 &&
        tData->tlsPendingLandingPadIp == traceFirstIp) {
        // Re-anchor as a CHILD of the handler frame (normal branch)
        // rather than a sibling. Sibling placement was ambiguous
        // because Pin can produce multiple "main"-labeled Pin traces
        // (loop body vs post-return continuation) with different
        // callerCtxtHndl values, so which parent we'd splay under
        // depended on which handler-labeled TraceNode the walker
        // returned. Normal-branch places the landing pad
        // deterministically as a child of the specific handler
        // TraceNode. The landing pad's function name still resolves
        // to the handler's own name (its IP lies inside the handler
        // function's body), so chain function-names read
        // `... -> handler -> handler(landing pad) -> C` which is
        // exactly the shape the user asked for -- C's immediate
        // parent function-name is the handler.
        UpdateCurTraceOnly(tData, tData->tlsPendingHandlerFrame);
        tData->tlsCurrentChildContextStartIndex = tData->tlsPendingHandlerFrame->childCtxtStartIdx;
        tData->tlsCurrentCtxtHndl = tData->tlsPendingHandlerCtxt;
        tData->tlsInitiatedCall = true; // NORMAL branch: landing pad becomes CHILD of handler
        tData->tlsPendingLandingPadIp = 0;
        tData->tlsPendingHandlerFrame = NULL;
        tData->tlsPendingHandlerCtxt = 0;
    }

    // if landed here w/o a call instruction, then let's make this trace a sibling.
    // The trick to do it is to go to the parent TraceNode and make this trace a child of it
    if (!tData->tlsInitiatedCall) {
        tData->tlsCurrentCtxtHndl = tData->tlsCurrentTraceNode->callerCtxtHndl;
    } else {
        // tlsCurrentCtxtHndl must be pointing to the call IP in the parent trace
        tData->tlsInitiatedCall = false;
    }

    // if the current trace is a child of currentIPNode, then let's set ourselves to that
#ifdef USE_SPLAY_TREE
    TraceSplay* found = splay(GET_IPNODE_FROM_CONTEXT_HANDLE(tData->tlsCurrentCtxtHndl)->calleeTraceNodes, traceKey);

    // Check if a trace node with traceKey already exists under this context node
    if (found && (traceKey == found->key)) {
        GET_IPNODE_FROM_CONTEXT_HANDLE(tData->tlsCurrentCtxtHndl)->calleeTraceNodes = found;
        // already present, so set current trace to it
        UpdateCurTraceAndIp(tData, found->value);
    } else {
        // Create new trace node and insert under the IPNode.
        TraceNode* newChild = new TraceNode();
#if 0
            static uint64_t traceNodeCnt = 0;
            traceNodeCnt++;

            if((traceNodeCnt % 100000) == 0)
                printf("\n Trace traceNodeCnt=%lu", traceNodeCnt);

#endif
        newChild->callerCtxtHndl = tData->tlsCurrentCtxtHndl;
        newChild->traceKey = traceKey;

        if (numInterestingInstInTrace) {
            // if CONTINUOUS_DEADINFO is set, then all ip vecs come from a fixed 4GB buffer
            // might need a lock in MT case
            newChild->childCtxtStartIdx = GetNextIPVecBuffer(numInterestingInstInTrace);
            newChild->nSlots = numInterestingInstInTrace;
            IPNode* ipNode = GET_IPNODE_FROM_CONTEXT_HANDLE(newChild->childCtxtStartIdx);

            //cerr<<"\n***:"<<numInterestingInstInTrace;
            for (uint32_t i = 0; i < numInterestingInstInTrace; i++) {
                ipNode[i].parentTraceNode = newChild;
                ipNode[i].calleeTraceNodes = nullptr;
            }
        } else {
            // This can happen since we may hot a trace with 0 interesting instructions.
            //assert(0 && "I never expect traces to have 0 instructions");
            newChild->nSlots = 0;
            newChild->childCtxtStartIdx = 0;
        }

        TraceSplay* newNode = new TraceSplay();
        newNode->key = traceKey;
        newNode->value = newChild;
        GET_IPNODE_FROM_CONTEXT_HANDLE(tData->tlsCurrentCtxtHndl)->calleeTraceNodes = newNode;

        if (!found) {
            newNode->left = NULL;
            newNode->right = NULL;
        } else if (traceKey < found->key) {
            newNode->left = found->left;
            newNode->right = found;
            found->left = NULL;
        } else { // addr > addr of found
            newNode->left = found;
            newNode->right = found->right;
            found->right = NULL;
        }

        UpdateCurTraceAndIp(tData, newChild);
    }

#else
     assert 0 && "not maintained");
#endif
}


// Instrument a trace, take the first instruction in the first BBL and insert the analysis function before that
static void CCTLibInstrumentTrace(TRACE trace, void* isInterestingIns) {
    BBL bbl = TRACE_BblHead(trace);
    INS ins = BBL_InsHead(bbl);
    uint32_t numInterestingInstInTrace = GetNumInterestingInsInTrace(trace, (IsInterestingInsFptr)isInterestingIns);
    uint32_t traceKey = GetNextTraceKey();
    // Classify the enclosing routine for direct self-recursion. If Pin
    // has no valid RTN for this trace (data-in-code, unbacked JIT, etc.)
    // rinfo is null and instrumentation falls back to today's behavior.
    RTN rtn = TRACE_Rtn(trace);
    const RtnInfo* rinfo = RTN_Valid(rtn) ? GetOrClassifyRoutine(rtn) : nullptr;
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)InstrumentTraceEntry, IARG_UINT32, traceKey, IARG_UINT32, numInterestingInstInTrace, IARG_ADDRINT, TRACE_Address(trace), IARG_THREAD_ID, IARG_END);
    PopulateIPReverseMapAndAccountTraceInstructions(trace, traceKey, numInterestingInstInTrace, (IsInterestingInsFptr)isInterestingIns, rinfo);
}


static void OnSig(THREADID threadId, CONTEXT_CHANGE_REASON reason, const CONTEXT* ctxtFrom,
                  CONTEXT* ctxtTo, INT32 sig, VOID* v) {
    ThreadData* tData = CCTLibGetTLS(threadId);

    switch (reason) {
    case CONTEXT_CHANGE_REASON_FATALSIGNAL:
        cerr << "\n FATAL SIGNAL";

    case CONTEXT_CHANGE_REASON_SIGNAL:
        //cerr<<"\n SIGNAL";
        // rest will be set as we enter the signal callee
        tData->tlsInitiatedCall = true;
        break;

    case CONTEXT_CHANGE_REASON_SIGRETURN: {
        // nothig  needs to be done! works like magic!!
        //cerr<<"\n SIG RET";
        //assert(0 && "NYI");
        break;
    }

    default:
        assert(0 && "\n BAD CONTEXT SWITCH");
    }
}


IPNode* GetPINCCTCurrentContext(THREADID id) {
    ThreadData* tData = CCTLibGetTLS(id);
    uint32_t slot = tData->curSlotNo;
    assert(slot < tData->tlsCurrentTraceNode->nSlots);
    return GET_IPNODE_FROM_CONTEXT_HANDLE(tData->tlsCurrentTraceNode->childCtxtStartIdx + slot);
}


IPNode* GetPINCCTCurrentContextWithSlot(THREADID id, uint32_t slot) {
    ThreadData* tData = CCTLibGetTLS(id);
    assert(slot < tData->tlsCurrentTraceNode->nSlots);
    return GET_IPNODE_FROM_CONTEXT_HANDLE(tData->tlsCurrentTraceNode->childCtxtStartIdx + slot);
}

ContextHandle_t GetContextHandle(const THREADID id, const uint32_t slot) {
    ThreadData* tData = CCTLibGetTLS(id);
    assert(slot < tData->tlsCurrentTraceNode->nSlots);
    return tData->tlsCurrentTraceNode->childCtxtStartIdx + slot;
}

#ifdef HAVE_METRIC_PER_IPNODE
void** GetIPNodeMetric(const THREADID id, const uint32_t slot) {
    ThreadData* tData = CCTLibGetTLS(id);
    assert(slot < tData->tlsCurrentTraceNode->nSlots);
    return &(GET_IPNODE_FROM_CONTEXT_HANDLE(tData->tlsCurrentTraceNode->childCtxtStartIdx + slot)->metric);
}
#endif

ContextHandle_t GetPINCCT32BitContextIndex(IPNode* node) {
    return node - GLOBAL_STATE.preAllocatedContextBuffer;
}

inline IPNode* GetPINCCTContextFrom32BitIndex(ContextHandle_t index) {
    return &GLOBAL_STATE.preAllocatedContextBuffer[index];
}

static void SegvHandler(int sig) {
    longjmp(GLOBAL_STATE.env, 1);
}


// On program termination output all gathered data and statistics
static VOID CCTLibFini(INT32 code, VOID* v) {
    // byte count
    //fprintf(GLOBAL_STATE.CCTLibLogFile, "\n#eof");
    //fclose(GLOBAL_STATE.CCTLibLogFile);
}

#if 0
// Visit all nodes of the splay tree of child traces.
    static void VisitAllNodesOfSplayTree(TraceSplay* node, FILE* const fp) {
        if(node == NULL)
            return;

        // visit left
        VisitAllNodesOfSplayTree(node->left, fp);
        // process self
        SerializeCCTNode(node->value, fp);
        // visit right
        VisitAllNodesOfSplayTree(node->right, fp);
    }

    static void SerializeCCTNode(TraceNode* traceNode, FILE* const fp) {
        // if traceNode had 0 interesting childCtxtStartIdx, then we are at a leaf trace so, we can simply return.
        if(traceNode->nSlots == 0)
            return;

        IPNode* parentIPNode = traceNode->callerCtxtHndl ? traceNode->callerCtxtHndl : 0;
        ADDRINT* traceIPs = (ADDRINT*)(GLOBAL_STATE.traceShadowMap[traceNode->traceKey]);
        ADDRINT moduleId = traceIPs[-1];
        ADDRINT loadOffset =   GLOBAL_STATE.ModuleInfoMap[moduleId].imgLoadOffset;

        // Iterate over all IPNodes in this trace
        for(uint32_t i = 0 ; i < traceNode->nSlots; i++) {
            fprintf(fp, "\n%p:%p:%p:%lu", &traceNode->childCtxtStartIdx[i], (void*)(traceIPs[i] - loadOffset), parentIPNode, moduleId);
        }

        // Iterate over all IPNodes
        for(uint32_t i = 0 ; i < traceNode->nSlots; i++) {
            // Iterate over all decendent TraceNode of traceNode->childCtxtStartIdx[i]
            VisitAllNodesOfSplayTree((traceNode->childCtxtStartIdx[i]).calleeTraceNodes, fp);
        }
    }

    static void SerializeAllCCTs() {
        for(uint32_t id = 0 ; id < GLOBAL_STATE.numThreads; id++) {
            ThreadData* tData = CCTLibGetTLS(id);
            std::stringstream cctMapFilePath;
            cctMapFilePath << GLOBAL_STATE.CCTLibFilePathPrefix << "-Thread" << id << "-CCTMap.txt";
            FILE* fp = fopen(cctMapFilePath.str().c_str(), "w");
            fprintf(fp, "NodeId:IP:ParentId:ModuleId");
            SerializeCCTNode(tData->tlsRootTraceNode, fp);
            fclose(fp);
        }
    }

#endif

// Serialization of CCTs, module info, and trace IPs. Previously guarded by
// USE_BOOST as an opt-in; now always compiled in since Boost is gone.

// Visit all nodes of the splay tree of child traces.
static void VisitAllNodesOfSplayTree(TraceSplay* node, FILE* const fp) {
    // process self
    SerializeCCTNode(node->value, fp);

    // visit left
    if (node->left)
        VisitAllNodesOfSplayTree(node->left, fp);

    // visit right
    if (node->right)
        VisitAllNodesOfSplayTree(node->right, fp);
}

static uint32_t NO_MORE_TRACE_NODES_IN_SPLAY_TREE = UINT_MAX;

static void SerializeCCTNode(TraceNode* traceNode, FILE* const fp) {
    SerializedTraceNode serializedTraceNode = {traceNode->traceKey, traceNode->nSlots, traceNode->childCtxtStartIdx};
    fwrite(&serializedTraceNode, sizeof(SerializedTraceNode), 1, fp);

    // Iterate over all IPNodes
    IPNode* ipNode = GET_IPNODE_FROM_CONTEXT_HANDLE(traceNode->childCtxtStartIdx);
    for (uint32_t i = 0; i < traceNode->nSlots; i++) {
        if ((ipNode[i]).calleeTraceNodes == NULL) {
            fwrite(&NO_MORE_TRACE_NODES_IN_SPLAY_TREE, sizeof(NO_MORE_TRACE_NODES_IN_SPLAY_TREE), 1, fp);
        } else {
            // Iterate over all decendent TraceNode of traceNode->childCtxtStartIdx[i]
            VisitAllNodesOfSplayTree((ipNode[i]).calleeTraceNodes, fp);
            fwrite(&NO_MORE_TRACE_NODES_IN_SPLAY_TREE, sizeof(NO_MORE_TRACE_NODES_IN_SPLAY_TREE), 1, fp);
        }
    }
}

static TraceNode* DeserializeCCTNode(ContextHandle_t parentCtxtHndl, FILE* const fp) {
    uint32_t noMoreTrace;

    if (fread(&noMoreTrace, sizeof(noMoreTrace), 1, fp) != 1) {
        fprintf(stderr, "\n Failed to read at line %d\n", __LINE__);
        PIN_ExitProcess(-1);
    }

    if (noMoreTrace == NO_MORE_TRACE_NODES_IN_SPLAY_TREE) {
        return NULL;
    }

    // go back 4 bytes;
    fseek(fp, -sizeof(noMoreTrace), SEEK_CUR);
    SerializedTraceNode serializedTraceNode;

    if (fread(&serializedTraceNode, sizeof(SerializedTraceNode), 1, fp) != 1) {
        fprintf(stderr, "\n Failed to read at line %d\n", __LINE__);
        PIN_ExitProcess(-1);
    }

    TraceNode* traceNode = new TraceNode();
    traceNode->traceKey = serializedTraceNode.traceKey;
    traceNode->nSlots = serializedTraceNode.nSlots;
    traceNode->childCtxtStartIdx = serializedTraceNode.childCtxtStartIdx;
    traceNode->callerCtxtHndl = parentCtxtHndl;

    // Iterate over all IPNodes
    IPNode* ipNode = GET_IPNODE_FROM_CONTEXT_HANDLE(traceNode->childCtxtStartIdx);
    for (uint32_t i = 0; i < traceNode->nSlots; i++) {
        ipNode[i].parentTraceNode = traceNode;

        while (true) {
            TraceNode* childTrace = DeserializeCCTNode(traceNode->childCtxtStartIdx + i, fp);

            if (childTrace == NULL)
                break;

            // add childTrace to the splay tree at traceNode->childCtxtStartIdx[i]
            TraceSplay* newNode = new TraceSplay();
            newNode->key = childTrace->traceKey;
            newNode->value = childTrace;

            // if no children
            IPNode* childIPNode = GET_IPNODE_FROM_CONTEXT_HANDLE(traceNode->childCtxtStartIdx + i);
            if (childIPNode->calleeTraceNodes == NULL) {
                childIPNode->calleeTraceNodes = newNode;
                newNode->left = NULL;
                newNode->right = NULL;
            } else {
                TraceSplay* found = splay(childIPNode->calleeTraceNodes, childTrace->traceKey);

                // Install newNode as the new splay root -- mirrors the
                // live-instrumentation insertion path (search for the
                // sibling site in this file). Without this line, newNode
                // is unreachable and leaked, and the tree still points at
                // `found`, so the newly deserialized child is never found.
                childIPNode->calleeTraceNodes = newNode;
                if (childTrace->traceKey < found->key) {
                    newNode->left = found->left;
                    newNode->right = found;
                    found->left = NULL;
                } else { // addr > addr of found
                    newNode->left = found;
                    newNode->right = found->right;
                    found->right = NULL;
                }
            }
        }
    }

    return traceNode;
}


static void SerializeAllCCTs() {
    for (uint32_t id = 0; id < GLOBAL_STATE.numThreads; id++) {
        ThreadData* tData = CCTLibGetTLS(id);
        std::stringstream cctMapFilePath;
        cctMapFilePath << GLOBAL_STATE.serializationDirectory << SERIALIZED_CCT_FILE_PREFIX << id << SERIALIZED_CCT_FILE_SUFFIX;
        FILE* fp = fopen(cctMapFilePath.str().c_str(), "wb");

        if (fp == NULL) {
            fprintf(stderr, "\n Failed to open %s in line %d. Exiting\n", cctMapFilePath.str().c_str(), __LINE__);
            PIN_ExitProcess(-1);
        }

        //record thread id
        uint32_t threadId = tData->tlsThreadId;
        fwrite(&threadId, sizeof(tData->tlsThreadId), 1, fp);
        // record path of the parent
        ContextHandle_t parentCtxtHndl = tData->tlsParentThreadCtxtHndl;
        fwrite(&parentCtxtHndl, sizeof(ContextHandle_t), 1, fp);
        SerializeCCTNode(tData->tlsRootTraceNode, fp);
        fclose(fp);
    }
}


static bool IsDirectory(const char* path) {
    struct stat statbuf;
    if (stat(path, &statbuf) != 0)
        return false;
    return S_ISDIR(statbuf.st_mode);
}

static bool endsWithExtn(const string& base, const string& ext) {
    if (ext.size() > base.size())
        return false;
    return std::equal(base.begin() + base.size() - ext.size(), base.end(), ext.begin());
}

// return the filenames of all files that have the specified extension
// in the specified directory and all subdirectories
static void GetAllFilesInDirWithExtn(const string& root, const string& ext, vector<string>& ret) {
    char resolvedPath[PATH_MAX];
    realpath(root.c_str(), resolvedPath);
    DIR* dirp = opendir(resolvedPath);
    if (NULL == dirp) {
        // TODO(preexisting-bug): the original code throws here.
        // Pin's analysis-dispatch loop does not unwind through C++
        // exceptions even under `-fexceptions`; an unhandled throw
        // will terminate the tool with std::terminate rather than a
        // clean error. Convert to an error-return contract (or wrap
        // the caller under PIN_LockClient with a try/catch). Not
        // reached by `make check`; restoring the original throw to
        // scope this change strictly to porting.
        throw string("Directory does not exits" + root);
    }
    struct dirent* dp;
    while ((dp = readdir(dirp)) != NULL) {
        char concatedPath[PATH_MAX];
        // Bounded concatenation of resolvedPath + "/" + dp->d_name.
        // snprintf always null-terminates and reports truncation via
        // its return value; skip entries that don't fit rather than
        // silently truncating a filename we might later try to open.
        int written = snprintf(concatedPath, sizeof(concatedPath),
                               "%s/%s", resolvedPath, dp->d_name);
        if (written < 0 || (size_t)written >= sizeof(concatedPath))
            continue;
        if (IsDirectory(concatedPath))
            continue;
        if (!endsWithExtn(string(concatedPath), ext))
            continue;
        ret.push_back(string(concatedPath));
    }
    closedir(dirp);
}

static void DeserializeAllCCTs() {
    // Get all files with
    vector<string> serializedCCTFiles;
    GetAllFilesInDirWithExtn(GLOBAL_STATE.serializationDirectory, SERIALIZED_CCT_FILE_EXTN, serializedCCTFiles);
    for (uint32_t id = 0; id < serializedCCTFiles.size(); id++) {
        std::stringstream cctMapFilePath;
        cctMapFilePath << serializedCCTFiles[id];
        //fprintf(stderr, "\nexists = %d\n", 0);
        FILE* fp = fopen(cctMapFilePath.str().c_str(), "rb");

        if (fp == NULL) {
            perror("fopen:");
            fprintf(stderr, "\n Failed to open %s in line %d. Exiting\n", cctMapFilePath.str().c_str(), __LINE__);
            PIN_ExitProcess(-1);
        }

        // Get thread id
        uint32_t threadId;

        if (fread(&threadId, sizeof(threadId), 1, fp) != 1) {
            fprintf(stderr, "\n Failed to read at line %d\n", __LINE__);
            PIN_ExitProcess(-1);
        }

        // record path of the parent
        ContextHandle_t parentCtxtHndl;

        if (fread(&parentCtxtHndl, sizeof(ContextHandle_t), 1, fp) != 1) {
            fprintf(stderr, "\n Failed to read at line %d\n", __LINE__);
            PIN_ExitProcess(-1);
        }

        TraceNode* rootTrace = DeserializeCCTNode(parentCtxtHndl, fp);
#ifndef NDEBUG
        // we should be at the end of file now
        uint8_t dummy;
        assert(fread(&dummy, sizeof(uint8_t), 1, fp) == 0);
#endif
        fclose(fp);
        // Add a ThreadData record to GLOBAL_STATE.deserializedCCTs
        ThreadData tdata;
        //bzero(&tdata, sizeof(tdata));
        tdata.tlsThreadId = threadId;
        tdata.tlsParentThreadCtxtHndl = parentCtxtHndl;
        tdata.tlsRootTraceNode = rootTrace;
        tdata.tlsRootCtxtHndl = rootTrace->childCtxtStartIdx;
        GLOBAL_STATE.deserializedCCTs.push_back(tdata);
        // Update the number of threads
        GLOBAL_STATE.numThreads++;
    }
}

static void DottifyCCTNode(TraceNode* traceNode, uint64_t parentDotId, FILE* const fp);

static uint64_t gDotId;
#if 0
// Visit all nodes of the splay tree of child traces.
    static void DottifyAllNodesOfSplayTree(TraceSplay* node, uint64_t curDotId, FILE* const fp) {
        if(node == NULL)
            return;

        // visit left
        DottifyAllNodesOfSplayTree(node->left, curDotId, fp);
        // process self
        DottifyCCTNode(node->value, curDotId, fp);
        // visit right
        DottifyAllNodesOfSplayTree(node->right, curDotId, fp);
    }
#endif

// Visit all nodes of the splay tree of child traces.
static void ListAllNodesOfSplayTree(TraceSplay* node, vector<TraceNode*>& childTraces) {
    if (node == NULL)
        return;

    // visit left
    ListAllNodesOfSplayTree(node->left, childTraces);
    childTraces.push_back(node->value);
    // visit right
    ListAllNodesOfSplayTree(node->right, childTraces);
}


static void DottifyCCTNode(TraceNode* traceNode, uint64_t parentDotId, FILE* const fp) {
    // if traceNode had 0 interesting childCtxtStartIdx, then we are at a leaf trace so, we can simply return.
    if (traceNode->nSlots == 0) {
        return;
    }

    uint64_t myDotId = ++gDotId;
    fprintf(fp, "\"%" PRIx64 "\" -> \"%" PRIx64 "\";\n", parentDotId, myDotId);
    vector<TraceNode*> childTraces;

    // Iterate over all IPNodes
    for (uint32_t i = 0; i < traceNode->nSlots; i++) {
        // Iterate over all decendent TraceNode of traceNode->childCtxtStartIdx[i]
        //DottifyAllNodesOfSplayTree((traceNode->childCtxtStartIdx[i]).calleeTraceNodes, childTraceDotId, fp);
        ListAllNodesOfSplayTree(GET_IPNODE_FROM_CONTEXT_HANDLE(traceNode->childCtxtStartIdx + i)->calleeTraceNodes, childTraces);
    }

    for (vector<TraceNode*>::iterator it = childTraces.begin(); it != childTraces.end(); it++) {
        DottifyCCTNode(*it, myDotId, fp);
    }
}


void DottifyAllCCTs() {
    std::stringstream cctMapFilePath;
    cctMapFilePath << GLOBAL_STATE.serializationDirectory << "./CCTMap.dot";
    FILE* fp = fopen(cctMapFilePath.str().c_str(), "w");

    if (fp == NULL) {
        fprintf(stderr, "\n Failed to open %s in line %d. Exiting\n", cctMapFilePath.str().c_str(), __LINE__);
        PIN_ExitProcess(-1);
    }

    fprintf(fp, "digraph CCTLibGraph {\n");

    for (uint32_t id = 0; id < GLOBAL_STATE.numThreads; id++) {
        ThreadData* tData = CCTLibGetTLS(id);
        DottifyCCTNode(tData->tlsRootTraceNode, gDotId, fp);
    }

    fprintf(fp, "\n}");
    fclose(fp);
}


#define SERIALIZED_MODULE_MAP_SUFFIX "/ModuleMap.txt"

static void SerializeMouleInfo() {
    string moduleFilePath = GLOBAL_STATE.serializationDirectory + SERIALIZED_MODULE_MAP_SUFFIX;
    FILE* fp = fopen(moduleFilePath.c_str(), "w");

    if (fp == NULL) {
        perror("Error:");
        fprintf(stderr, "\n Failed to open %s in line %d. Exiting\n", moduleFilePath.c_str(), __LINE__);
        PIN_ExitProcess(-1);
    }

    unordered_map<UINT32, ModuleInfo>::iterator it;
    fprintf(fp, "ModuleId\tModuleFile\tLoadOffset");

    for (it = GLOBAL_STATE.ModuleInfoMap.begin(); it != GLOBAL_STATE.ModuleInfoMap.end(); ++it) {
        fprintf(fp, "\n%u\t%s\t%p", it->first, (it->second).moduleName.c_str(), (void*)((it->second).imgLoadOffset));
    }

    fclose(fp);
}

static void DeserializeMouleInfo() {
    string moduleFilePath = GLOBAL_STATE.serializationDirectory + SERIALIZED_MODULE_MAP_SUFFIX;
    FILE* fp = fopen(moduleFilePath.c_str(), "r");

    if (fp == NULL) {
        perror("Error");
        fprintf(stderr, "\n Failed to open %s in line %d. Exiting\n", moduleFilePath.c_str(), __LINE__);
        PIN_ExitProcess(-1);
    }

    // read header and thow it away
    uint32_t moduleId;
    ADDRINT offset;
    char path[MAX_FILE_PATH];
    //fprintf(fp, "ModuleId\tModuleFile\tLoadOffset");
    fscanf(fp, "%s%s%s", path, path, path);

    while (EOF != fscanf(fp, "%u%s%p", &moduleId, path, (void**)&offset)) {
        ModuleInfo minfo;
        minfo.moduleName = path;
        minfo.imgLoadOffset = offset;
        GLOBAL_STATE.ModuleInfoMap[moduleId] = minfo;
    }

    fclose(fp);
}


static void SerializeTraceIps() {
    string traceMapFilePath = GLOBAL_STATE.serializationDirectory + SERIALIZED_SHADOW_TRACE_IP_FILE_SUFFIX;
    FILE* fp = fopen(traceMapFilePath.c_str(), "wb");

    if (fp == NULL) {
        fprintf(stderr, "\n Failed to open %s in line %d. Exiting\n", traceMapFilePath.c_str(), __LINE__);
        PIN_ExitProcess(-1);
    }

    unordered_map<uint32_t, void*>::iterator it;
    //fprintf(fp, "TraceKey:NumSlots:ModuleId:[ip1][ip2]..[ipNumSlots]");

    for (it = GLOBAL_STATE.traceShadowMap.begin(); it != GLOBAL_STATE.traceShadowMap.end(); ++it) {
        // traceId
        fwrite(&(it->first), sizeof(it->first), 1, fp);
        ADDRINT* ptr = (ADDRINT*)(it->second);
        uint32_t moduleId = (uint32_t)ptr[-1];
        ADDRINT offset = GLOBAL_STATE.ModuleInfoMap[moduleId].imgLoadOffset;
        ADDRINT nSlots = ptr[-2];

        // Normalize all IPs
        // NOTE --- once this update has happened, the traceShadowMapp[traceId] is rendered unusables without adding the offset in this run.
        // It must be used in post mortem analysis from this point onwards.
        for (ADDRINT i = 0; i < nSlots; i++) {
            ptr[i] = ptr[i] - offset;
        }

        // Write all slots
        fwrite(ptr - 2, sizeof(ADDRINT), ptr[-2] + 2, fp);
    }

    fclose(fp);
}


static void DeserializeTraceIps() {
    string traceMapFilePath = GLOBAL_STATE.serializationDirectory + SERIALIZED_SHADOW_TRACE_IP_FILE_SUFFIX;
    FILE* fp = fopen(traceMapFilePath.c_str(), "rb");

    if (fp == NULL) {
        fprintf(stderr, "\n Failed to open %s in line %d. Exiting\n", traceMapFilePath.c_str(), __LINE__);
        PIN_ExitProcess(-1);
    }

    unordered_map<uint32_t, void*>::iterator it;
    //fprintf(fp, "TraceKey:NumSlots:ModuleId:[ip1][ip2]..[ipNumSlots]");
    uint32_t traceKey;

    while (fread(&traceKey, sizeof(traceKey), 1, fp) == 1) {
        // read num entries
        ADDRINT numSlots;

        if (fread(&numSlots, sizeof(ADDRINT), 1, fp) != 1) {
            fprintf(stderr, "\n Failed to read in line %d. Exiting\n", __LINE__);
            PIN_ExitProcess(-1);
        }

        // allocate the shadow ips
        ADDRINT* array = (ADDRINT*)malloc((numSlots + 2) * sizeof(ADDRINT));
        array[0] = numSlots;

        // read remaining entires
        if (fread(&array[1], sizeof(ADDRINT), numSlots + 1, fp) != (numSlots + 1)) {
            fprintf(stderr, "\n Failed to read in line %d. Exiting\n", __LINE__);
            PIN_ExitProcess(-1);
        }

        // Insert into the shadow map
        GLOBAL_STATE.traceShadowMap[traceKey] = (void*)(&array[2]); // 2 because first 2 entries are behind as in runtime.
    }

    fclose(fp);
}


void SerializeMetadata(const string& directoryForSerializationFiles) {
    if (!directoryForSerializationFiles.empty()) {
        GLOBAL_STATE.serializationDirectory = directoryForSerializationFiles;
    } else {
        // construct one
        std::stringstream ss;
        char hostname[MAX_FILE_PATH];
        gethostname(hostname, MAX_FILE_PATH);
        pid_t pid = getpid();
        ss << CCTLIB_SERIALIZATION_DEFAULT_DIR_NAME << hostname << "-" << pid;
        GLOBAL_STATE.serializationDirectory = ss.str();
    }

    // create directory. Using system("mkdir -p ...") here spawns /bin/sh,
    // which Pin has to follow into via ptrace. On modern kernels with
    // ptrace_scope=1 that attach is denied. Use direct syscalls instead.
    {
        const string& dir = GLOBAL_STATE.serializationDirectory;
        struct stat st;
        if (stat(dir.c_str(), &st) != 0) {
            size_t pos = 0;
            while (pos != string::npos) {
                pos = dir.find('/', pos + 1);
                string sub = (pos == string::npos) ? dir : dir.substr(0, pos);
                if (sub.empty())
                    continue;
                if (mkdir(sub.c_str(), 0755) != 0 && errno != EEXIST) {
                    fprintf(stderr, "\n failed to create directory %s: %s", sub.c_str(), strerror(errno));
                    break;
                }
            }
        }
    }

    SerializeAllCCTs();
    SerializeMouleInfo();
    SerializeTraceIps();
}

void DeserializeMetadata(const string& directoryForSerializationFiles) {
    GLOBAL_STATE.serializationDirectory = directoryForSerializationFiles;
    DeserializeAllCCTs();
    DeserializeTraceIps();
    DeserializeMouleInfo();
}

/**
     * Returns the peak (maximum so far) resident set size (physical
     * memory use) measured in KB, or zero if the value cannot be
     * determined on this OS.
     */
size_t getPeakRSS() {
    struct rusage rusage;
    getrusage(RUSAGE_SELF, &rusage);
    return (size_t)(rusage.ru_maxrss);
}


static void PrintStats() {
    fprintf(GLOBAL_STATE.CCTLibLogFile, "\nTotal call paths=%" PRIu64, GLOBAL_STATE.curPreAllocatedContextBufferIndex);
    // Peak resource usage
    fprintf(GLOBAL_STATE.CCTLibLogFile, "\nPeak RSS=%zu", getPeakRSS());
}


// This function is called when the application exits
VOID Fini(INT32 code, VOID* v) {
    //SerializeMetadata();
    //DottifyAllCCTs();
    PrintStats();
}

// Given a pointer (i.e. slot) within a trace node, returns the IP corresponding to that slot
static inline ADDRINT GetIPFromInfo(ContextHandle_t ctxtHndle) {
    // GET_IPNODE_FROM_CONTEXT_HANDLE is the UNCHECKED variant that does
    // pointer arithmetic on a base allocated during InitBuffers(); it
    // never returns null for a valid handle. Analyzer can't infer the invariant.
    TraceNode* traceNode = GET_IPNODE_FROM_CONTEXT_HANDLE(ctxtHndle)->parentTraceNode; // NOLINT(clang-analyzer-core.NullDereference)
    assert(ctxtHndle >= traceNode->childCtxtStartIdx);
    assert(ctxtHndle < traceNode->childCtxtStartIdx + traceNode->nSlots);
    // what is my slot id ?
    uint32_t slotNo = ctxtHndle - traceNode->childCtxtStartIdx;

    ADDRINT* ip = (ADDRINT*)GLOBAL_STATE.traceShadowMap[traceNode->traceKey];
    return ip[slotNo];
}
// Given a pointer (i.e. slot) within a trace node, set the IP corresponding to that slot
// Used for creating dummy root by eliding all frames above "main"
static inline void SetIPFromInfo(ContextHandle_t ctxtHndle, ADDRINT val) {
    TraceNode* traceNode = GET_IPNODE_FROM_CONTEXT_HANDLE(ctxtHndle)->parentTraceNode;
    assert(ctxtHndle >= traceNode->childCtxtStartIdx);
    assert(ctxtHndle < traceNode->childCtxtStartIdx + traceNode->nSlots);
    // what is my slot id ?
    uint32_t slotNo = ctxtHndle - traceNode->childCtxtStartIdx;
    ADDRINT* ip = (ADDRINT*)GLOBAL_STATE.traceShadowMap[traceNode->traceKey];
    ip[slotNo] = val;
}


// Given a pointer (i.e. slot) within a trace node, returns the module name corresponding to that slot
static inline const string& GetModulePathFromInfo(IPNode* ipNode) {
    TraceNode* traceNode = ipNode->parentTraceNode;
    ADDRINT* ptr = (ADDRINT*)GLOBAL_STATE.traceShadowMap[traceNode->traceKey];
    UINT32 moduleId = ptr[-1]; // module id is stored one behind.
    return GLOBAL_STATE.ModuleInfoMap[moduleId].moduleName;
}


// Given a pointer (i.e. slot) within a trace node, returns the Line number corresponding to that slot
static inline void GetLineFromInfo(const ADDRINT& ip, uint32_t& lineNo, string& filePath) {
    PIN_GetSourceLocation(ip, NULL, (INT32*)&lineNo, &filePath);
}

static void GetDecodedInstFromIP(ADDRINT ip) {
    // Get the instruction in a string
    xed_decoded_inst_t xedd;
    GLOBAL_STATE.disassemblyBuff[0] = 0;
    xed_decoded_inst_zero_set_mode(&xedd, &GLOBAL_STATE.cct_xed_state);

    if (XED_ERROR_NONE == xed_decode(&xedd, (const xed_uint8_t*)(ip), 15)) {
        if (0 == xed_format_context(XED_SYNTAX_ATT, &xedd, GLOBAL_STATE.disassemblyBuff, 200, ip, nullptr, nullptr))
            strcpy(GLOBAL_STATE.disassemblyBuff, "xed_decoded_inst_dump_att_format failed");
    } else {
        strcpy(GLOBAL_STATE.disassemblyBuff, "xed_decode failed");
    }
}

// Returns true if the given address belongs to one of the loaded binaries
static inline bool IsValidIP(ADDRINT ip) {
    for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
        if (ip >= IMG_LowAddress(img) && ip <= IMG_HighAddress(img)) {
            return true;
        }
    }

    return false;
}
#if 0
// Returns true if the given deadinfo belongs to one of the loaded binaries
    static inline bool IsValidIP(DeadInfo  di) {
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
#endif

// Returns true if the address in the given context node corresponds to a sinature (assembly code: ) that corresponds to a .PLT section
// Sample PLt signatire : ff 25 c2 24 21 00       jmpq   *2172098(%rip)        # 614340 <quoting_style_args+0x2a0>
static inline bool IsValidPLTSignature(const ADDRINT& ip) {
    return (*((unsigned char*)ip) == 0xff) && (*((unsigned char*)ip + 1) == 0x25);
}


#define NOT_ROOT_CTX (-1)
// Return true if the given ContextNode is one of the root context nodes
static int IsARootIPNode(ContextHandle_t curCtxtHndle) {
    // if it is runing monitoring we will use CCTLibGetTLS
    if (GLOBAL_STATE.cctLibUsageMode == CCT_LIB_MODE_COLLECTION) {
        for (uint32_t id = 0; id < GLOBAL_STATE.numThreads; id++) {
            ThreadData* tData = CCTLibGetTLS(id);

            if (tData->tlsRootCtxtHndl == curCtxtHndle)
                return id;
        }
    } else {
        //CCT_LIB_MODE_POSTMORTEM
        for (uint32_t id = 0; id < GLOBAL_STATE.numThreads; id++) {
            if (GLOBAL_STATE.deserializedCCTs[id].tlsRootCtxtHndl == curCtxtHndle)
                return GLOBAL_STATE.deserializedCCTs[id].tlsThreadId;
        }
    }

    return NOT_ROOT_CTX;
}


#if 0

    static VOID PrintFullCallingContext(IPNode* curIPNode);
// Given a context node (curContext), traverses up in the chain till the root and prints the entire calling context

    static VOID PrintFullCallingContext(IPNode* curIPNode) {
        int depth = 0;
#ifdef MULTI_THREADED
        int root;
#endif // end MULTI_THREADED

    // set sig handler
        struct sigaction old;
        sigaction(SIGSEGV, &GLOBAL_STATE.sigAct, &old);

        // Dont print if the depth is more than MAX_CCT_PRINT_DEPTH since files become too large
        while(curIPNode && (depth ++ < MAX_CCT_PRINT_DEPTH)) {
            int threadCtx = 0;

            if((threadCtx = IsARootIPNode(curIPNode)) != NOT_ROOT_CTX) {
                fprintf(GLOBAL_STATE.CCTLibLogFile, "\nTHREAD[%d]_ROOT_CTXT", threadCtx);
                // if the thread has a parent, recurse over it.
                IPNode* parentThreadIPNode = CCTLibGetTLS(threadCtx)->tlsParentThreadCtxtHndl;

                if(parentThreadIPNode)
                    PrintFullCallingContext(parentThreadIPNode);

                break;
            } else {
                ADDRINT ip = GetIPFromInfo(curIPNode);

                if(IsValidIP(ip)) {
                    if(PIN_UndecorateSymbolName(RTN_FindNameByAddress(ip), UNDECORATION_COMPLETE) == ".plt") {
                        if(setjmp(GLOBAL_STATE.env) == 0) {
                            if(IsValidPLTSignature(ip)) {
                                uint64_t nextByte = (uint64_t) ip + 2;
                                int* offset = (int*) nextByte;
                                uint64_t nextInst = (uint64_t) ip + 6;
                                ADDRINT loc = *((uint64_t*)(nextInst + *offset));

                                if(IsValidIP(loc)) {
                                    string filePath;
                                    uint32_t lineNo;
                                    GetLineFromInfo(ip, lineNo, filePath);
                                    GetDecodedInstFromIP(ip);
                                    fprintf(GLOBAL_STATE.CCTLibLogFile, "\n%u:!%p:%s:%s:%s:%u", GET_CONTEXT_HANDLE_FROM_IP_NODE(curIPNode), (void*)ip, GLOBAL_STATE.disassemblyBuff, PIN_UndecorateSymbolName(RTN_FindNameByAddress(loc), UNDECORATION_COMPLETE).c_str(), filePath.c_str(), lineNo);
                                } else {
                                    fprintf(GLOBAL_STATE.CCTLibLogFile, "\nIN PLT BUT NOT VALID GOT");
                                }
                            } else {
                                fprintf(GLOBAL_STATE.CCTLibLogFile, "\nUNRECOGNIZED PLT SIGNATURE");
                                //fprintf(GLOBAL_STATE.CCTLibLogFile,"\n plt plt plt %x", * ((UINT32*)curContext->address));
                                //for(int i = 1; i < 4 ; i++)
                                //	fprintf(GLOBAL_STATE.CCTLibLogFile," %x",  ((UINT32 *)curContext->address)[i]);
                            }
                        } else {
                            fprintf(GLOBAL_STATE.CCTLibLogFile, "\nCRASHED !!");
                        }
                    } else {
                        string filePath;
                        uint32_t lineNo;
                        GetLineFromInfo(ip, lineNo, filePath);
                        GetDecodedInstFromIP(ip);
#if 0
                        fprintf(GLOBAL_STATE.CCTLibLogFile, "\n%p:%s:%s:%s", (void*)ip, GLOBAL_STATE.disassemblyBuff, PIN_UndecorateSymbolName(RTN_FindNameByAddress(ip), UNDECORATION_COMPLETE).c_str(), line.c_str());
#else
                        // also print the IPNode handle so that I can debug deserialization
                        fprintf(GLOBAL_STATE.CCTLibLogFile, "\n%u:%p:%s:%s:%s:%u", GET_CONTEXT_HANDLE_FROM_IP_NODE(curIPNode), (void*)ip, GLOBAL_STATE.disassemblyBuff, PIN_UndecorateSymbolName(RTN_FindNameByAddress(ip), UNDECORATION_COMPLETE).c_str(), filePath.c_str(), lineNo);
#endif
                    }
                } else {
                    fprintf(GLOBAL_STATE.CCTLibLogFile, "\nBAD IP ");
                }

                curIPNode = curIPNode->parentTraceNode->callerCtxtHndl;
            }
        }

        //reset sig handler
        sigaction(SIGSEGV, &old, 0);
    }
#endif

VOID GetParentIPs(ContextHandle_t ctxtHandle, vector<ADDRINT>& parentIPs) {
    int depth = 0;
    while (IS_VALID_CONTEXT(ctxtHandle) && depth++ < MAX_CCT_PRINT_DEPTH) {
        ADDRINT ip = GetIPFromInfo(ctxtHandle);
        if (IsValidIP(ip)) {
            parentIPs.push_back(ip);
        }
        ctxtHandle = GET_IPNODE_FROM_CONTEXT_HANDLE(ctxtHandle)->parentTraceNode->callerCtxtHndl;
    }
}

static VOID GetFullCallingContextInSitu(ContextHandle_t curCtxtHndle, vector<Context>& contextVec) {
    int depth = 0;
#ifdef MULTI_THREADED
    int root;
#endif //end MULTI_THREADED
    // set sig handler
    struct sigaction old;
    sigaction(SIGSEGV, &GLOBAL_STATE.sigAct, &old);

    // Dont print if the depth is more than MAX_CCT_PRINT_DEPTH since files become too large
    while (IS_VALID_CONTEXT(curCtxtHndle) && (depth++ < MAX_CCT_PRINT_DEPTH)) {
        int threadCtx = 0;

        if ((threadCtx = IsARootIPNode(curCtxtHndle)) != NOT_ROOT_CTX) {
            // if the thread has a parent, recur over it.
            ContextHandle_t parentThreadCtxtHndl = CCTLibGetTLS(threadCtx)->tlsParentThreadCtxtHndl;
            Context ctxt = {"THREAD[" + std::to_string(threadCtx) + "]_ROOT_CTXT" /*functionName*/, "" /*filePath */, "" /*disassembly*/, curCtxtHndle /*ctxtHandle*/, 0 /*lineNo*/, 0 /*ip*/};
            contextVec.push_back(ctxt);

            if (parentThreadCtxtHndl)
                GetFullCallingContextInSitu(parentThreadCtxtHndl, contextVec);

            break;
        } else {
            ADDRINT ip = GetIPFromInfo(curCtxtHndle);

            if (IsValidIP(ip)) {
                if (PIN_UndecorateSymbolName(RTN_FindNameByAddress(ip), UNDECORATION_COMPLETE) == ".plt") {
                    if (setjmp(GLOBAL_STATE.env) == 0) {
                        if (IsValidPLTSignature(ip)) {
                            uint64_t nextByte = (uint64_t)ip + 2;
                            int* offset = (int*)nextByte;
                            uint64_t nextInst = (uint64_t)ip + 6;
                            ADDRINT loc = *((uint64_t*)(nextInst + *offset));

                            if (IsValidIP(loc)) {
                                string filePath;
                                uint32_t lineNo;
                                GetLineFromInfo(ip, lineNo, filePath);
                                GetDecodedInstFromIP(ip);
                                Context ctxt = {PIN_UndecorateSymbolName(RTN_FindNameByAddress(loc), UNDECORATION_COMPLETE) /*functionName*/, filePath /*filePath */, string(GLOBAL_STATE.disassemblyBuff) /*disassembly*/, curCtxtHndle /*ctxtHandle*/, lineNo /*lineNo*/, ip /*ip*/};
                                contextVec.push_back(ctxt);
                            } else {
                                GetDecodedInstFromIP(ip);
                                Context ctxt = {"IN PLT BUT NOT VALID GOT" /*functionName*/, "" /*filePath */, string(GLOBAL_STATE.disassemblyBuff) /*disassembly*/, curCtxtHndle /*ctxtHandle*/, 0 /*lineNo*/, ip /*ip*/};
                                contextVec.push_back(ctxt);
                            }
                        } else {
                            GetDecodedInstFromIP(ip);
                            Context ctxt = {"UNRECOGNIZED PLT SIGNATURE" /*functionName*/, "" /*filePath */, string(GLOBAL_STATE.disassemblyBuff) /*disassembly*/, curCtxtHndle /*ctxtHandle*/, 0 /*lineNo*/, ip /*ip*/};
                            contextVec.push_back(ctxt);
                            //fprintf(GLOBAL_STATE.CCTLibLogFile,"\n plt plt plt %x", * ((UINT32*)curContext->address));
                            //for(int i = 1; i < 4 ; i++)
                            //      fprintf(GLOBAL_STATE.CCTLibLogFile," %x",  ((UINT32 *)curContext->address)[i]);
                        }
                    } else {
                        Context ctxt = {"CRASHED !!" /*functionName*/, "" /*filePath */, "" /*disassembly*/, curCtxtHndle /*ctxtHandle*/, 0 /*lineNo*/, ip /*ip*/};
                        contextVec.push_back(ctxt);
                    }
                } else {
                    string filePath;
                    uint32_t lineNo;
                    GetLineFromInfo(ip, lineNo, filePath);
                    GetDecodedInstFromIP(ip);
#if 0
                        fprintf(GLOBAL_STATE.CCTLibLogFile, "\n%p:%s:%s:%s", (void*)ip, GLOBAL_STATE.disassemblyBuff, PIN_UndecorateSymbolName(RTN_FindNameByAddress(ip), UNDECORATION_COMPLETE).c_str(), li
                                ne.c_str());
#else
                     // also print the IPNode handle so that I can debug deserialization
                     Context ctxt = {PIN_UndecorateSymbolName(RTN_FindNameByAddress(ip), UNDECORATION_COMPLETE) /*functionName*/, filePath /*filePath */, string(GLOBAL_STATE.disassemblyBuff) /*disassembly*/, curCtxtHndle /*ctxtHandle*/, lineNo /*lineNo*/, ip /*ip*/};
                     contextVec.push_back(ctxt);
#endif
                }
            } else {
                Context ctxt = {"BAD IP !!" /*functionName*/, "" /*filePath */, "" /*disassembly*/, curCtxtHndle /*ctxtHandle*/, 0 /*lineNo*/, ip /*ip*/};
                contextVec.push_back(ctxt);
            }

            curCtxtHndle = GET_IPNODE_FROM_CONTEXT_HANDLE(curCtxtHndle)->parentTraceNode->callerCtxtHndl;

            if (depth >= MAX_CCT_PRINT_DEPTH) {
                Context ctxt = {"Truncated call path (due to deep call chain)" /*functionName*/, "" /*filePath */, "" /*disassembly*/, curCtxtHndle /*ctxtHandle*/, 0 /*lineNo*/, 0 /*ip*/};
                contextVec.push_back(ctxt);
            }
        }
    }

    //reset sig handler
    sigaction(SIGSEGV, &old, nullptr);
}


static VOID GetFullCallingContextPostmortem(ContextHandle_t curCtxtHndle, vector<Context>& contextVec) {
    int depth = 0;
#ifdef MULTI_THREADED
    int root;
#endif //end MULTI_THREADED
    // set sig handler
    struct sigaction old;
    sigaction(SIGSEGV, &GLOBAL_STATE.sigAct, &old);

    // Dont print if the depth is more than MAX_CCT_PRINT_DEPTH since files become too large
    while (IS_VALID_CONTEXT(curCtxtHndle) && (depth++ < MAX_CCT_PATH_DEPTH)) {
        int threadCtx = 0;

        if ((threadCtx = IsARootIPNode(curCtxtHndle)) != NOT_ROOT_CTX) {
            Context ctxt = {"THREAD[" + std::to_string(threadCtx) + "]_ROOT_CTXT" /*functionName*/, "" /*filePath */, "" /*disassembly*/, curCtxtHndle /*ctxtHandle*/, 0 /*lineNo*/, 0 /*ip*/};
            contextVec.push_back(ctxt);
            // if the thread has a parent, recurse over it.
            ContextHandle_t parentThreadCtxtHndl = GLOBAL_STATE.deserializedCCTs[threadCtx].tlsParentThreadCtxtHndl;

            if (parentThreadCtxtHndl)
                GetFullCallingContextPostmortem(parentThreadCtxtHndl, contextVec);

            break;
        } else {
            ADDRINT ip = GetIPFromInfo(curCtxtHndle);
            const string& modulePath = GetModulePathFromInfo(GET_IPNODE_FROM_CONTEXT_HANDLE(curCtxtHndle));
            std::stringstream command;
            command << "addr2line -C -f -e " << modulePath << " " << std::hex << ip;
            FILE* fp = popen(command.str().c_str(), "r");
            char functionName[MAX_FILE_PATH];
            char fileName[MAX_FILE_PATH];
            uint32_t lineNo;

            if (setjmp(GLOBAL_STATE.env) == 0) {
                if (fgets(functionName, MAX_FILE_PATH, fp) == NULL) {
                    strcpy(functionName, "FAILED_TO_READ");
                    strcpy(fileName, "FAILED_TO_READ");
                    lineNo = 0;
                } else {
                    if (fgets(fileName, MAX_FILE_PATH, fp) == NULL) {
                        strcpy(fileName, "FAILED_TO_READ");
                        lineNo = 0;
                    } else {
                        // Look for last ":"
                        int len = strlen(fileName);
                        int linePos;

                        for (linePos = len - 1; linePos >= 0; linePos--) {
                            if (fileName[linePos] == ':')
                                break;
                        }

                        lineNo = atoi(&fileName[linePos + 1]);
                        fileName[linePos] = '\0';
                    }
                }
            } else {
                strcpy(functionName, "CRASHED!");
                strcpy(fileName, "CRASHED!");
                lineNo = 0;
            }

            pclose(fp);
            string fnName(functionName);
            CCTLibTrimInPlace(fnName);
            string flName(fileName);
            CCTLibTrimInPlace(flName);
            Context ctxt = {
                fnName /*functionName*/, flName /*filePath */, "TODO-Disassmebly" /*disassembly*/, curCtxtHndle /*ctx
tHandle*/
                ,
                lineNo /*lineNo*/, ip /*ip*/
            };
            contextVec.push_back(ctxt);
            curCtxtHndle = GET_IPNODE_FROM_CONTEXT_HANDLE(curCtxtHndle)->parentTraceNode->callerCtxtHndl;
        }
    }

    //reset sig handler
    sigaction(SIGSEGV, &old, nullptr);
}


VOID GetFullCallingContext(ContextHandle_t curCtxtHndle, vector<Context>& contextVec) {
    if (GLOBAL_STATE.cctLibUsageMode == CCT_LIB_MODE_POSTMORTEM)
        GetFullCallingContextPostmortem(curCtxtHndle, contextVec);
    else
        GetFullCallingContextInSitu(curCtxtHndle, contextVec);
}

VOID PrintFullCallingContext(const ContextHandle_t ctxtHandle) {
    vector<Context> contextVec;

    if (GLOBAL_STATE.cctLibUsageMode == CCT_LIB_MODE_POSTMORTEM)
        GetFullCallingContextPostmortem(ctxtHandle, contextVec);
    else
        GetFullCallingContextInSitu(ctxtHandle, contextVec);

    for (uint32_t i = 0; i < contextVec.size(); i++) {
        fprintf(GLOBAL_STATE.CCTLibLogFile, "\n%u:%p:%s:%s:%s:%u", contextVec[i].ctxtHandle, (void*)contextVec[i].ip, contextVec[i].disassembly.c_str(), contextVec[i].functionName.c_str(), contextVec[i].filePath.c_str(), contextVec[i].lineNo);
    }
}

void AppendLoadModulesToStream(iostream& ios) {
    unordered_map<UINT32, ModuleInfo>::iterator it;
    for (it = GLOBAL_STATE.ModuleInfoMap.begin(); it != GLOBAL_STATE.ModuleInfoMap.end(); ++it) {
        ios << "\n"
            << it->first << ":" << (void*)((it->second).imgLoadOffset) << ":" << (it->second).moduleName;
    }
}
struct NormalizedIP {
    int lm_id;
    ADDRINT offset;
};

static void GetNormalizedIpVectorClippedToMainOneAheadIp(vector<NormalizedIP>& ctxt, ContextHandle_t curCtxtHndle) {
    int depth = 0;
    // Dont print if the depth is more than MAX_CCT_PRINT_DEPTH since files become too large
    while (IS_VALID_CONTEXT(curCtxtHndle) && (depth++ < MAX_CCT_PRINT_DEPTH)) {
        int threadCtx = 0;
        if ((threadCtx = IsARootIPNode(curCtxtHndle)) != NOT_ROOT_CTX) {
            // if the thread has a parent, recur over it.
            ContextHandle_t parentThreadCtxtHndl = CCTLibGetTLS(threadCtx)->tlsParentThreadCtxtHndl;
            if (parentThreadCtxtHndl) {
                fprintf(stderr, "\n Multi threading not supported for this prototype feature. Exiting\n");
                PIN_ExitProcess(-1);
            }
            break;
        } else {
            TraceNode* traceNode = GET_IPNODE_FROM_CONTEXT_HANDLE(curCtxtHndle)->parentTraceNode;
            // what is my slot id ?
            uint32_t slotNo = curCtxtHndle - traceNode->childCtxtStartIdx;

            ADDRINT* ptr = (ADDRINT*)GLOBAL_STATE.traceShadowMap[traceNode->traceKey];
            UINT32 moduleId = ptr[-1]; // module id is stored one behind.
            ADDRINT ip = ptr[slotNo];
            ip += GetInstructionLength(ip);
            NormalizedIP nip;
            nip.lm_id = moduleId;
            nip.offset = ip - GLOBAL_STATE.ModuleInfoMap[moduleId].imgLoadOffset;
            ctxt.push_back(nip);

            // if we are already in main, we are done
            RTN r = RTN_FindByAddress(ip);
            if (RTN_Invalid() != r && RTN_Name(r) == "main")
                return;
        }
        curCtxtHndle = GET_IPNODE_FROM_CONTEXT_HANDLE(curCtxtHndle)->parentTraceNode->callerCtxtHndl;
    }
}

void LogContexts(iostream& ios, ContextHandle_t ctxt1, ContextHandle_t ctxt2) {
    vector<NormalizedIP> c1;
    vector<NormalizedIP> c2;
    GetNormalizedIpVectorClippedToMainOneAheadIp(c1, ctxt1);
    GetNormalizedIpVectorClippedToMainOneAheadIp(c2, ctxt2);
    for (uint32_t i = 0; i < c1.size(); i++)
        ios << c1[i].lm_id << "-" << (void*)c1[i].offset << ",";
    ios << "SEP";
    for (uint32_t i = 0; i < c2.size(); i++)
        ios << "," << c2[i].lm_id << "-" << (void*)c2[i].offset;
}

// Initialize the needed data structures before launching the target program
static void InitBuffers() {
    // prealloc IPNodeVec so that they all come from a continuous memory region.
    // IMPROVEME ... actually this can be as high as 24 GB since lower 3 bits are always zero for pointers
    GLOBAL_STATE.preAllocatedContextBuffer = (IPNode*)mmap(nullptr, MAX_IPNODES * sizeof(IPNode), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    // start from index 1 so that we can use 0 as empty key for the google hash table
    GLOBAL_STATE.curPreAllocatedContextBufferIndex = 1;
    // Init the string pool
    GLOBAL_STATE.preAllocatedStringPool = (char*)mmap(nullptr, MAX_STRING_POOL_NODES * sizeof(char), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    // start from index 1 so that we can use 0 as a special value
    GLOBAL_STATE.curPreAllocatedStringPoolIndex = 1;
}


#if 0
// Initialize RW locks
    static void InitLocks() {
//        PIN_RWMutexInit(&gStaticVarRWLock);
//        PIN_RWMutexInit(&gMallocVarRWLock);
    }
#endif

static void InitLogFile(FILE* logFile) {
    GLOBAL_STATE.CCTLibLogFile = logFile;
}

static void InitMapFilePrefix() {
    char* envPath = getenv("OUTPUT_FILE");

    if (envPath) {
        // assumes max of MAX_FILE_PATH
        GLOBAL_STATE.CCTLibFilePathPrefix = string(envPath) + "-";
    }

    std::stringstream ss;
    char hostname[MAX_FILE_PATH];
    gethostname(hostname, MAX_FILE_PATH);
    pid_t pid = getpid();
    ss << hostname << "-" << pid;
    GLOBAL_STATE.CCTLibFilePathPrefix += ss.str();
}


static void InitSegHandler() {
    // Init the  segv handler that may happen (due to PIN bug) when unwinding the stack during the printing
    memset(&GLOBAL_STATE.sigAct, 0, sizeof(struct sigaction));
    GLOBAL_STATE.sigAct.sa_handler = SegvHandler;
    GLOBAL_STATE.sigAct.sa_flags = SA_NODEFER;
}

static void InitXED() {
    // Init XED for decoding instructions
    xed_state_init(&GLOBAL_STATE.cct_xed_state, XED_MACHINE_MODE_LONG_64, (xed_address_width_enum_t)0, XED_ADDRESS_WIDTH_64b);
    // removed from  Xed v.67254 xed_decode_init();
}


//DO_DATA_CENTRIC

#ifdef USE_SHADOW_FOR_DATA_CENTRIC
static ConcurrentShadowMemory<DataHandle_t> sm;

static void InitShadowSpaceForDataCentric(VOID* addr, uint32_t accessLen, DataHandle_t* initializer) {
    uint64_t endAddr = (uint64_t)addr + accessLen;
    uint32_t numInited = 0;

    for (uint64_t curAddr = (uint64_t)addr; curAddr < endAddr; curAddr += SHADOW_PAGE_SIZE) {
        DataHandle_t* status = GetOrCreateShadowAddress<0>(sm, (size_t)curAddr);
        int maxBytesInThisPage = SHADOW_PAGE_SIZE - PAGE_OFFSET((uint64_t)addr);

        for (int i = 0; (i < maxBytesInThisPage) && numInited < accessLen; numInited++, i++) {
            status[i] = *initializer;
        }
    }
}

DataHandle_t GetDataObjectHandle(VOID* addr, THREADID threadId) {
    DataHandle_t dataHandle;
    ThreadData* tData = CCTLibGetTLS(threadId);

    // if it is a stack location, set so and return
    if (addr > tData->tlsStackEnd && addr < tData->tlsStackBase) {
        dataHandle.objectType = STACK_OBJECT;
        return dataHandle;
    }

    dataHandle = *(GetOrCreateShadowAddress<0>(sm, (size_t)addr));
    return dataHandle;
}

#elif defined(USE_TREE_BASED_FOR_DATA_CENTRIC)
DataHandle_t GetDataObjectHandle(VOID* addr, THREADID threadId) {
     DataHandle_t record;
     ThreadData* tData = CCTLibGetTLS(threadId);

     // if it is a stack location, set so and return
     if (addr > tData->tlsStackEnd && addr < tData->tlsStackBase) {
         record.objectType = STACK_OBJECT;
         return record;
     }

     // publish the most recent MallocVarSet that this thread sees. This allows the concurrent writer to make progress.
     // This is placed here so that we dont update this on each stack access. We favor reader progress.
     tData->tlsLatestConcurrentTree = (ConcurrentReaderWriterTree_t*)GLOBAL_STATE.latestConcurrentTree;
     varSet* curTree = &(tData->tlsLatestConcurrentTree->tree);
     tData->tlsMallocDSAccessStatus = START_READING;
     // first check dymanically allocated variables
     //ReadLock mallocRWlock(gMallocVarRWLock);
     // gMallocVarRWLock.lock_read();
     // ReadLock(&(tData->rwLockStatus));
     varSet::iterator node = curTree->lower_bound(varType(addr, addr, 0 /*handle*/, UNKNOWN_OBJECT));

     if (node != curTree->begin() && node->start != addr)
         node--;

     if (node != curTree->end() && (addr < node->start || addr >= node->end))
         node = curTree->end();

     if (node != curTree->end()) {
         record.objectType = node->objectType;
         record.pathHandle = node->pathHandle;
// Milind - Commented this since thsi consumes too much space.
// Need to discuss with Xu on how to maintain this efficiently.
#ifdef USE_TREE_WITH_ADDR
         record.beg_addr = (uint64_t)node->start;
         record.end_addr = (uint64_t)node->end;
#endif
     } else {
         record.objectType = UNKNOWN_OBJECT;
     }

     tData->tlsMallocDSAccessStatus = END_READING;
     return record;
}


#else
DataHandle_t GetDataObjectHandle(VOID* addr, THREADID threadId) {
    assert(0 && "should never reach here");
}

#endif

static VOID CaptureMallocSize(size_t arg0, THREADID threadId) {
    // Remember the CCT node and the allocation size
    ThreadData* tData = CCTLibGetTLS(threadId);
    tData->tlsDynamicMemoryAllocationSize = arg0;
    tData->tlsDynamicMemoryAllocationPathHandle = GetContextHandle(threadId, 0);
}

static VOID CaptureCallocSize(size_t arg0, size_t arg1, THREADID threadId) {
    // Remember the CCT node and the allocation size
    ThreadData* tData = CCTLibGetTLS(threadId);
    tData->tlsDynamicMemoryAllocationSize = arg0 * arg1;
    tData->tlsDynamicMemoryAllocationPathHandle = GetContextHandle(threadId, 0);
}

//Fwd declaration;
static void CaptureFree(void* ptr, THREADID threadId);

static VOID CaptureReallocSize(void* ptr, size_t arg1, THREADID threadId) {
    // Remember the CCT node and the allocation size
    ThreadData* tData = CCTLibGetTLS(threadId);
    tData->tlsDynamicMemoryAllocationSize = arg1;
    tData->tlsDynamicMemoryAllocationPathHandle = GetContextHandle(threadId, 0);
#ifdef USE_TREE_BASED_FOR_DATA_CENTRIC
    // Simulate free(ptr);
    CaptureFree(ptr, threadId);
#endif
}


#ifdef USE_TREE_BASED_FOR_DATA_CENTRIC

#if 0
    static void DUMP_STATUS(THREADID threadId, int stuckon, int calledFrom) {
        printf("\n STUCK! threadId = %d, stack waiting for %d, called from %s", threadId, stuckon, calledFrom == 0 ? "malloc" : "free");

        for(uint32_t i = 0; i < GLOBAL_STATE.numThreads; i++) {
            ThreadData* tData = CCTLibGetTLS(i);
            printf("\n Thread %d,  tlsLatestMallocVarSet = %p, tlsMallocDSAccessStatus = %d", i, tData->tlsLatestMallocVarSet , tData->tlsMallocDSAccessStatus);
        }

        fflush(stdout);
    }

    static void WaitTillAllThreadsProgressIntoNewSet(varSet* latestVarSet, THREADID threadId, int calledFrom) {
        // TODO: if the thread exists in the mean time, it might not have seen the update. We need to ignore such threads.
        for(uint32_t i = 0; i < GLOBAL_STATE.numThreads; i++) {
            ThreadData* tData = CCTLibGetTLS(i);
            uint64_t j = 0;

            while((tData->tlsLatestMallocVarSet != latestVarSet) && (tData->tlsMallocDSAccessStatus == START_READING)) {
                // spin
                if(j++ == 0xffffff) {
                    DUMP_STATUS(threadId, i, calledFrom);
                }
            }
        }
    }
#else

QNode* volatile MCSLock = NULL;

static void MCSAcquire(QNode* volatile* L, QNode* I) {
    I->next = NULL;
    I->status = LOCKED;
    QNode* pred = (QNode*)__sync_lock_test_and_set((uint64_t*)L, (uint64_t)I);

    if (pred) {
        pred->next = I;

        while (I->status == LOCKED)
            ; // spin
    }
}

static void MCSRelease(QNode* volatile* L, QNode* I, uint8_t releaseVal) {
    if (I->next == NULL) {
        if (__sync_bool_compare_and_swap((uint64_t*)L, (uint64_t)I, (uint64_t)NULL))
            return;

        while (I->next == NULL)
            ; // spin

        // wait till some successor
    }

    I->next->status = releaseVal;
}


static void WaitTillAllThreadsProgressIntoNewSet(ConcurrentReaderWriterTree_t* latestTree) {
    // TODO: if the thread exists in the mean time, it might not have seen the update. We need to ignore such threads.
    for (uint32_t i = 0; i < GLOBAL_STATE.numThreads; i++) {
        ThreadData* tData = CCTLibGetTLS(i);

        while ((tData->tlsLatestConcurrentTree != latestTree) && (tData->tlsMallocDSAccessStatus == START_READING)) {
            // spin
        }
    }
}

static void ApplyPendingOperationsToTree(ConcurrentReaderWriterTree_t* threadFreeTree) {
    for (uint32_t i = 0; i < threadFreeTree->pendingOps.size(); i++) {
        switch (threadFreeTree->pendingOps[i].operation) {
        case INSERT: {
            //fprintf(stderr,"\n Inserting %1d %p - %p",threadFreeTree->pendingOps[i].var.objectType, threadFreeTree->pendingOps[i].var.start, threadFreeTree->pendingOps[i].var.end);
            threadFreeTree->tree.insert(threadFreeTree->pendingOps[i].var);
            break;
        }

        case DELETE: {
            //fprintf(stderr,"\n Deleting %1d %p\n", threadFreeTree->pendingOps[i].var.objectType, threadFreeTree->pendingOps[i].var.start);
            varSet::const_iterator iterThreadFreeTree = threadFreeTree->tree.lower_bound(threadFreeTree->pendingOps[i].var);

            //assert(iterThreadFreeTree != threadFreeTree->tree.end());
            //assert(threadFreeTree->pendingOps[i].var.start >= iterThreadFreeTree->start);
            //assert(threadFreeTree->pendingOps[i].var.start < iterThreadFreeTree->end);
            if (threadFreeTree->pendingOps[i].var.start == iterThreadFreeTree->start) {
                threadFreeTree->tree.erase(*iterThreadFreeTree);
            } else {
                fprintf(stderr, "\n Can't delete %1d %p\n", threadFreeTree->pendingOps[i].var.objectType, threadFreeTree->pendingOps[i].var.start);
            }

            break;
        }

        default:
            assert(0 && "Should not reach here");
            break;
        }
    }

    //clear list
    threadFreeTree->pendingOps.clear();
}
#endif


static void UpdateLockLessTree(THREADID threadId, const vector<PendingOps_t>& ops) {
    static ThreadData dummyThreadData; // we use it when GLOBAL_STATE.applicationStarted is false
    ThreadData* tData;

    if (!GLOBAL_STATE.applicationStarted) {
        tData = &dummyThreadData;
    } else {
        tData = CCTLibGetTLS(threadId);
    }

    // tell that this thread is waiting to write
    tData->tlsMallocDSAccessStatus = WAITING_WRITE;
    QNode mcsNode;
    MCSAcquire(&MCSLock, &mcsNode);
    // Not waiting anymore
    tData->tlsMallocDSAccessStatus = WRITE_STARTED;
    ConcurrentReaderWriterTree_t* curTree = (ConcurrentReaderWriterTree_t*)GLOBAL_STATE.latestConcurrentTree;
    ConcurrentReaderWriterTree_t* newTree = (curTree == (&GLOBAL_STATE.concurrentReaderWriterTree[0])) ? (&GLOBAL_STATE.concurrentReaderWriterTree[1]) : (&GLOBAL_STATE.concurrentReaderWriterTree[0]);
    // Queue up "ops" to both trees
    curTree->pendingOps.insert(curTree->pendingOps.end(), ops.begin(), ops.end());
    newTree->pendingOps.insert(newTree->pendingOps.end(), ops.begin(), ops.end());
#if 0

        // Write batching optimization is disabled since it can cause writer to not find its inserted item immediately if it becomes a reader.
        if(mcsNode.status != UNLOCKED_AND_PREDECESSOR_WAS_WRITER /* first writer*/) {
            // Wait for all threads to make progress into curTree
            WaitTillAllThreadsProgressIntoNewSet(curTree);
        }

#else
    // Wait for all threads to make progress into curTree
    WaitTillAllThreadsProgressIntoNewSet(curTree);
#endif
    // All threads will be in curTree, so we can modify newTree
    // Apply pending operations to newTree
    ApplyPendingOperationsToTree(newTree);
#if 0

        // Write batching optimization is disabled since it can cause writer to not find its inserted item immediately if it becomes a reader.
        if(mcsNode.next == NULL  /* last writer */) {
            // Publish newTree.
            GLOBAL_STATE.latestConcurrentTree = newTree;
            // set self tlsLatestMallocVarSet to be newTree
            tData->tlsLatestConcurrentTree = newTree;
            MCSRelease(&MCSLock, &mcsNode, UNLOCKED);
        } else {
            MCSRelease(&MCSLock, &mcsNode, UNLOCKED_AND_PREDECESSOR_WAS_WRITER);
        }

#else
    // Publish newTree.
    GLOBAL_STATE.latestConcurrentTree = newTree;
    // set self tlsLatestMallocVarSet to be newTree
    tData->tlsLatestConcurrentTree = newTree;
    MCSRelease(&MCSLock, &mcsNode, UNLOCKED);
#endif
}


#endif


static VOID CaptureMallocPointer(void* ptr, THREADID threadId) {
    ThreadData* tData = CCTLibGetTLS(threadId);
#ifdef USE_SHADOW_FOR_DATA_CENTRIC
    DataHandle_t dataHandle;
    dataHandle.objectType = DYNAMIC_OBJECT;
    dataHandle.pathHandle = tData->tlsDynamicMemoryAllocationPathHandle;
    InitShadowSpaceForDataCentric(ptr, tData->tlsDynamicMemoryAllocationSize, &dataHandle);
#elif defined(USE_TREE_BASED_FOR_DATA_CENTRIC)
     varType v(ptr, (void*)((char*)ptr + (tData->tlsDynamicMemoryAllocationSize)), tData->tlsDynamicMemoryAllocationPathHandle, DYNAMIC_OBJECT);
     vector<PendingOps_t> ops(1, PendingOps_t(INSERT, v));
     UpdateLockLessTree(threadId, ops);
#else
    assert(0 && "Should not reach here");
#endif
}

static void CaptureFree(void* ptr, THREADID threadId) {
#ifdef USE_SHADOW_FOR_DATA_CENTRIC
    //NOP
#elif defined(USE_TREE_BASED_FOR_DATA_CENTRIC)

     if (ptr) {
         varType v(ptr, ptr, 0 /* handle */, DYNAMIC_OBJECT);
         vector<PendingOps_t> ops(1, PendingOps_t(DELETE, v));
         UpdateLockLessTree(threadId, ops);
     } // else NOP .. free() does nothing for NULL ptr

#else
    assert(0 && "Should not reach here");
#endif
}


// compute static variables
// each image has a splay tree to include all static variables
// that reside in the image. All images are linked as a link list

static void compute_static_var(char* filename, IMG img) {
#ifdef USE_TREE_BASED_FOR_DATA_CENTRIC
    vector<PendingOps_t> ops;
    UINT32 imgId = IMG_Id(img);
#endif
    //Elf32_Ehdr* elf_header;         /* ELF header */
    Elf* elf; /* Our Elf pointer for libelf */
    Elf_Scn* scn = NULL; /* Section Descriptor */
    Elf_Data* edata = NULL; /* Data Descriptor */
    GElf_Sym sym; /* Symbol */
    GElf_Shdr shdr; /* Section Header */
    char* base_ptr; // ptr to our object in memory
    struct stat elf_stats; // fstat struct
    int i, symbol_count;
    int fd = open(filename, O_RDONLY);

    if ((fstat(fd, &elf_stats))) {
        printf("bss: could not fstat, so not monitor static variables\n");
        close(fd);
        return;
    }

    if ((base_ptr = (char*)malloc(elf_stats.st_size)) == NULL) {
        printf("could not malloc\n");
        close(fd);
        PIN_ExitProcess(-1);
    }

    if ((read(fd, base_ptr, elf_stats.st_size)) < elf_stats.st_size) {
        printf("could not read\n");
        free(base_ptr);
        close(fd);
        PIN_ExitProcess(-1);
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        printf("WARNING Elf Library is out of date!\n");
    }

    //elf_header = (Elf32_Ehdr*) base_ptr;    // point elf_header at our object in memory
    elf = elf_begin(fd, ELF_C_READ, NULL); // Initialize 'elf' pointer to our file descriptor

    // Iterate each section until symtab section for object symbols
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        gelf_getshdr(scn, &shdr);

        if (shdr.sh_type == SHT_SYMTAB) {
            edata = elf_getdata(scn, edata);
            symbol_count = shdr.sh_size / shdr.sh_entsize;

            for (i = 0; i < symbol_count; i++) {
                if (gelf_getsym(edata, i, &sym) == NULL) {
                    printf("gelf_getsym return NULL\n");
                    printf("%s\n", elf_errmsg(elf_errno()));
                    PIN_ExitProcess(-1);
                }

                if ((sym.st_size == 0) || (ELF32_ST_TYPE(sym.st_info) != STT_OBJECT)) { //not a variable
                    continue;
                }

#ifdef USE_SHADOW_FOR_DATA_CENTRIC
                DataHandle_t dataHandle;
                dataHandle.objectType = STATIC_OBJECT;
                char* symname = elf_strptr(elf, shdr.sh_link, sym.st_name);
                dataHandle.symName = symname ? GetNextStringPoolIndex(symname) : 0;
                InitShadowSpaceForDataCentric((void*)((IMG_LoadOffset(img)) + sym.st_value), (uint32_t)sym.st_size, &dataHandle);
#elif defined(USE_TREE_BASED_FOR_DATA_CENTRIC)
                 char* symname = elf_strptr(elf, shdr.sh_link, sym.st_name);
                 uint32_t handle = symname ? GetNextStringPoolIndex(symname) : 0;
                 varType vInsert((void*)((IMG_LoadOffset(img)) + sym.st_value), (void*)((IMG_LoadOffset(img)) + sym.st_value + sym.st_size), handle, STATIC_OBJECT);
                 varType vDelete((void*)((IMG_LoadOffset(img)) + sym.st_value), (void*)((IMG_LoadOffset(img)) + sym.st_value), handle, STATIC_OBJECT);
                 ops.push_back(PendingOps_t(INSERT, vInsert));
                 // record for later deletion
                 GLOBAL_STATE.staticVariablesInModule[imgId].push_back(PendingOps_t(INSERT, vDelete));
#else
                assert(0 && "Should not reach here");
#endif
            }
        }
    }

#ifdef USE_TREE_BASED_FOR_DATA_CENTRIC
    UpdateLockLessTree(PIN_ThreadId(), ops);
#endif
}

static VOID
DeleteStaticVar(IMG img, VOID* v) {
#ifdef USE_SHADOW_FOR_DATA_CENTRIC
    //NOP
#else
     UpdateLockLessTree(PIN_ThreadId(), GLOBAL_STATE.staticVariablesInModule[IMG_Id(img)]);
#endif
}

static VOID ComputeVarBounds(IMG img, VOID* v) {
    char filename[PATH_MAX];
    char* result = realpath(IMG_Name(img).c_str(), filename);

    if (result == NULL) {
        fprintf(stderr, "\n failed to resolve path");
    }

    compute_static_var(filename, img);
}

// end DO_DATA_CENTRIC #endif

VOID CCTLibImage(IMG img, VOID* v) {
    //  Find the pthread_create() function.
#define PTHREAD_CREATE_RTN "pthread_create"
#define ARCH_LONGJMP_RTN "__longjmp"
#define SETJMP_RTN "_setjmp"
//#define LONGJMP_RTN "longjmp"
#define LONGJMP_RTN ARCH_LONGJMP_RTN
#define SIGSETJMP_RTN "sigsetjmp"
//#define SIGLONGJMP_RTN "siglongjmp"
#define SIGLONGJMP_RTN ARCH_LONGJMP_RTN
#define UNWIND_SETIP "_Unwind_SetIP"
#define UNWIND_RAISEEXCEPTION "_Unwind_RaiseException"
#define UNWIND_RESUME "_Unwind_Resume"
#define UNWIND_FORCEUNWIND "_Unwind_ForcedUnwind"
#define UNWIND_RESUME_OR_RETHROW "_Unwind_Resume_or_Rethrow"
    RTN pthread_createRtn = RTN_FindByName(img, PTHREAD_CREATE_RTN);
    RTN setjmpRtn = RTN_FindByName(img, SETJMP_RTN);
    RTN longjmpRtn = RTN_FindByName(img, LONGJMP_RTN);
    RTN sigsetjmpRtn = RTN_FindByName(img, SIGSETJMP_RTN);
    RTN siglongjmpRtn = RTN_FindByName(img, SIGLONGJMP_RTN);
    RTN archlongjmpRtn = RTN_FindByName(img, ARCH_LONGJMP_RTN);
    RTN unwindSetIpRtn = RTN_FindByName(img, UNWIND_SETIP);
    // _Unwind_RaiseException / _Unwind_Resume / _Unwind_ForcedUnwind
    // are no longer hooked -- their pre-existing "reset on last RET"
    // schemes were dead for caught exceptions (libgcc uses
    // __builtin_eh_return, which is not a RET). The new scheme reaches
    // every landing pad via the _Unwind_SetIP entry hook alone.
    //RTN unwindResumeOrRethrowRtn = RTN_FindByName(img, UNWIND_RESUME_OR_RETHROW);
#if 0
        cout << "\n Image name" << IMG_Name(img);
#endif

    if (RTN_Valid(pthread_createRtn)) {
        //fprintf(GLOBAL_STATE.CCTLibLogFile, "\n Found RTN %s",PTHREAD_CREATE_RTN);
        RTN_Open(pthread_createRtn);
        // Instrument malloc() to print the input argument value and the return value.
        RTN_InsertCall(pthread_createRtn, IPOINT_AFTER, (AFUNPTR)ThreadCreatePoint, IARG_THREAD_ID, IARG_END);
        RTN_Close(pthread_createRtn);
    }

#if 0

        if(RTN_Valid(setjmpRtn)) {
            //fprintf(GLOBAL_STATE.CCTLibLogFile, "\n Found RTN %s",SETJMP_RTN);
            RTN_ReplaceSignature(setjmpRtn, AFUNPTR(SetJmpOverride),  IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_ORIG_FUNCPTR, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
        }

#endif

    // Look for setjmp and longjmp routines present in libc.so.x file only
    if (strstr(IMG_Name(img).c_str(), "libc.so")) {
        if (RTN_Valid(setjmpRtn)) {
            //fprintf(GLOBAL_STATE.CCTLibLogFile, "\n Found RTN %s",SETJMP_RTN);
            RTN_Open(setjmpRtn);
            RTN_InsertCall(setjmpRtn, IPOINT_BEFORE, (AFUNPTR)CaptureSigSetJmpCtxt, IARG_CALL_ORDER, CALL_ORDER_LAST, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_THREAD_ID, IARG_END);
            RTN_Close(setjmpRtn);
        }

        if (RTN_Valid(longjmpRtn)) {
            //fprintf(GLOBAL_STATE.CCTLibLogFile, "\n Found RTN %s",LONGJMP_RTN);
            RTN_Open(longjmpRtn);
            RTN_InsertCall(longjmpRtn, IPOINT_BEFORE, (AFUNPTR)HoldLongJmpBuf, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_THREAD_ID, IARG_END);
            RTN_Close(longjmpRtn);
        }

        if (RTN_Valid(sigsetjmpRtn)) {
            //fprintf(GLOBAL_STATE.CCTLibLogFile, "\n Found RTN %s",SIGSETJMP_RTN);
            RTN_Open(sigsetjmpRtn);
            //CALL_ORDER_LAST so that cctlib's trace level instrumentation has updated the tlsCurrentCtxtHndl
            RTN_InsertCall(sigsetjmpRtn, IPOINT_BEFORE, (AFUNPTR)CaptureSigSetJmpCtxt, IARG_CALL_ORDER, CALL_ORDER_LAST, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_THREAD_ID, IARG_END);
            RTN_Close(sigsetjmpRtn);
        }

        if (RTN_Valid(siglongjmpRtn)) {
            //fprintf(GLOBAL_STATE.CCTLibLogFile, "\n Found RTN %s",SIGLONGJMP_RTN);
            RTN_Open(siglongjmpRtn);
            RTN_InsertCall(siglongjmpRtn, IPOINT_BEFORE, (AFUNPTR)HoldLongJmpBuf, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_THREAD_ID, IARG_END);
            RTN_Close(siglongjmpRtn);
        }

        if (RTN_Valid(archlongjmpRtn)) {
            //fprintf(GLOBAL_STATE.CCTLibLogFile, "\n Found RTN %s",ARCH_LONGJMP_RTN);
            RTN_Open(archlongjmpRtn);
            // Insert after the last JMP Inst.
            INS lastIns = RTN_InsTail(archlongjmpRtn);
            assert(INS_Valid(lastIns));
            assert(INS_IsBranch(lastIns));
            assert(!INS_IsDirectBranch(lastIns));
            INS_InsertCall(lastIns, IPOINT_TAKEN_BRANCH, (AFUNPTR)RestoreSigLongJmpCtxt, IARG_THREAD_ID, IARG_END);
            //RTN_InsertCall(siglongjmpRtn, IPOINT_BEFORE, (AFUNPTR)RestoreSigLongJmpCtxt, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_THREAD_ID, IARG_END);
            RTN_Close(archlongjmpRtn);
        }
    }

//#if DISABLE_EXCEPTION_HANDLING
#if 1

    // C++ exception (Itanium ABI) hookpoint: intercept `_Unwind_SetIP`
    // at entry. That's the ONLY function libgcc's driver uses to install
    // a resume IP (see ~/gcc/libgcc/unwind-dw2.c:368 — grep confirms it's
    // called nowhere in the driver itself, only from personality
    // routines). CaptureLandingPadTarget reads the pending resume IP,
    // walks cctlib's parent chain to identify the handler frame by
    // routine-address containment, and arms a pending re-anchor that
    // fires on the next Pin trace entry whose first IP matches. That
    // pairing is the reliable substitute for the pre-existing "reset on
    // _Unwind_RaiseException's last RET" scheme, which silently missed
    // every caught exception because libgcc uses __builtin_eh_return
    // (a non-RET epilogue) to jump to landing pads. Same hook covers
    // cleanup landing pads (dtor unwind) and handler landing pads
    // (catch clauses) uniformly, because personality functions call
    // _Unwind_SetIP for both.
    if (strstr(IMG_Name(img).c_str(), "libgcc_s.so")) {
        if (RTN_Valid(unwindSetIpRtn)) {
#ifdef DEBUG_CCTLIB
            fprintf(GLOBAL_STATE.CCTLibLogFile, "\n %s found in %s", UNWIND_SETIP, IMG_Name(img).c_str());
#endif
            RTN_Open(unwindSetIpRtn);
            RTN_InsertCall(unwindSetIpRtn, IPOINT_BEFORE, (AFUNPTR)CaptureLandingPadTarget, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_THREAD_ID, IARG_END);
            RTN_Close(unwindSetIpRtn);
        }
        // _Unwind_Resume, _Unwind_RaiseException, _Unwind_ForcedUnwind,
        // _Unwind_Resume_or_Rethrow: no hooks needed. The pre-existing
        // "reset on last RET" schemes on these routines were dead code
        // for caught exceptions (libgcc __builtin_eh_returns to the
        // landing pad without executing a real RET). All landing pads
        // -- cleanup and handler alike -- are covered by the
        // _Unwind_SetIP entry hook above.
    } // end strstr

#endif
    //end DISABLE_EXCEPTION_HANDLING

    // For new DW2 exception handling, we need to reset the shadow stack to the current handler in the following functions:
    // 1. _Unwind_Reason_Code _Unwind_RaiseException ( struct _Unwind_Exception *exception_object );
    // 2. _Unwind_Reason_Code _Unwind_ForcedUnwind ( struct _Unwind_Exception *exception_object, _Unwind_Stop_Fn stop, void *stop_parameter );
    // 3. void _Unwind_Resume (struct _Unwind_Exception *exception_object); *** INSTALL UNCONDITIONALLY, SINCE THIS NEVER RETURNS ***
    // 4. _Unwind_Reason_Code LIBGCC2_UNWIND_ATTRIBUTE _Unwind_Resume_or_Rethrow (struct _Unwind_Exception *exc) *** I AM NOT IMPLEMENTING THIS UNTILL I HIT A CODE THAT NEEDS IT ***

    // These functions call "uw_install_context" at the end of the routine just before returning, which overwrite the return address.
    // uw_install_context itself is a static function inlined or macroed. So we would rely on the more externally visible functions.
    // There are multiple returns in these (_Unwind_RaiseException, _Unwind_ForcedUnwind, _Unwind_Resume_or_Rethrow) functions. Only if the return value is "_URC_INSTALL_CONTEXT" shall we reset the shadow stack.

    // if data centric is enabled, capture allocation routines
    if (GLOBAL_STATE.doDataCentric) {
        RTN mallocRtn = RTN_FindByName(img, MALLOC_FN_NAME);

        if (RTN_Valid(mallocRtn)) {
            RTN_Open(mallocRtn);
            // Capture the allocation size and CCT node
            RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)CaptureMallocSize, IARG_CALL_ORDER, CALL_ORDER_LAST, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_THREAD_ID, IARG_END);
            // capture the allocated pointer and initialize the memory with CCT node.
            RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)CaptureMallocPointer, IARG_FUNCRET_EXITPOINT_VALUE, IARG_THREAD_ID, IARG_END);
            RTN_Close(mallocRtn);
        }

        RTN callocRtn = RTN_FindByName(img, CALLOC_FN_NAME);

        if (RTN_Valid(callocRtn)) {
            RTN_Open(callocRtn);
            // Capture the allocation size and CCT node
            RTN_InsertCall(callocRtn, IPOINT_BEFORE, (AFUNPTR)CaptureCallocSize, IARG_CALL_ORDER, CALL_ORDER_LAST, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_THREAD_ID, IARG_END);
            // capture the allocated pointer and initialize the memory with CCT node.
            RTN_InsertCall(callocRtn, IPOINT_AFTER, (AFUNPTR)CaptureMallocPointer, IARG_FUNCRET_EXITPOINT_VALUE, IARG_THREAD_ID, IARG_END);
            RTN_Close(callocRtn);
        }

        RTN reallocRtn = RTN_FindByName(img, REALLOC_FN_NAME);

        if (RTN_Valid(reallocRtn)) {
            RTN_Open(reallocRtn);
            // Capture the allocation size and CCT node
            RTN_InsertCall(reallocRtn, IPOINT_BEFORE, (AFUNPTR)CaptureReallocSize, IARG_CALL_ORDER, CALL_ORDER_LAST, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_THREAD_ID, IARG_END);
            // capture the allocated pointer and initialize the memory with CCT node.
            RTN_InsertCall(reallocRtn, IPOINT_AFTER, (AFUNPTR)CaptureMallocPointer, IARG_FUNCRET_EXITPOINT_VALUE, IARG_THREAD_ID, IARG_END);
            RTN_Close(reallocRtn);
        }

        RTN freeRtn = RTN_FindByName(img, FREE_FN_NAME);

        if (RTN_Valid(freeRtn)) {
            RTN_Open(freeRtn);
            RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)CaptureFree, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_THREAD_ID, IARG_END);
            RTN_Close(freeRtn);
        }
    }

    // Get the first instruction of main
    if (GLOBAL_STATE.skip) {
        RTN mainRtn = RTN_FindByName(img, "main");
        if (!RTN_Valid(mainRtn)) {
            mainRtn = RTN_FindByName(img, "MAIN");
            if (!RTN_Valid(mainRtn)) {
                mainRtn = RTN_FindByName(img, "MAIN_");
            }
        }
        if (RTN_Valid(mainRtn)) {
            GLOBAL_STATE.mainIP = RTN_Address(mainRtn);
        }
    }
}


//DO_DATA_CENTRIC
static void InitDataCentric() {
    // For shadow memory based approach initialize the L1 page table LEVEL_1_PAGE_TABLE_SIZE
    GLOBAL_STATE.doDataCentric = true;
#ifdef USE_SHADOW_FOR_DATA_CENTRIC
#endif // end USE_SHADOW_FOR_DATA_CENTRIC
    // This will perform hpc_var_bounds functionality on each image load
    IMG_AddInstrumentFunction(ComputeVarBounds, nullptr);
    // delete image from the list at the unloading callback
    IMG_AddUnloadFunction(DeleteStaticVar, nullptr);
#ifdef USE_TREE_BASED_FOR_DATA_CENTRIC
    // make gLatestMallocVarSet point to one of mallocVarSets.
    GLOBAL_STATE.latestConcurrentTree = &(GLOBAL_STATE.concurrentReaderWriterTree[0]);
#endif
}

VOID CCTLibAppStartNotification(void* v) {
    GLOBAL_STATE.applicationStarted = true;
}

// Main for DeadSpy, initialize the tool, register instrumentation functions and call the target program.

int PinCCTLibInit(IsInterestingInsFptr isInterestingIns, FILE* logFile, CCTLibInstrumentInsCallback userCallback, VOID* userCallbackArg, BOOL doDataCentric) {
    if (GLOBAL_STATE.cctLibUsageMode == CCT_LIB_MODE_POSTMORTEM) {
        fprintf(stderr, "\n CCTLib was initialized for postmortem analysis using PinCCTLibInitForPostmortemAnalysis! Exiting...\n");
        PIN_ExitApplication(-1);
    }

    GLOBAL_STATE.cctLibUsageMode = CCT_LIB_MODE_COLLECTION;
    // Initialize Symbols, we need them to report functions and lines
    PIN_InitSymbols();
    // Guard rtnSelfRecMap against concurrent JIT (Pin JITs traces on
    // any thread). Init before TRACE_AddInstrumentFunction below.
    PIN_RWMutexInit(&GLOBAL_STATE.rtnSelfRecRWMutex);
    // Intialize
    InitBuffers();
    InitLogFile(logFile);
    InitMapFilePrefix();
    InitSegHandler();
    InitXED();
    //InitLocks();
    // Obtain  a key for TLS storage.
    GLOBAL_STATE.CCTLibTlsKey = PIN_CreateThreadDataKey(nullptr /*TODO have a destructor*/);
    // remember user instrumentation callback
    GLOBAL_STATE.userInstrumentationCallback = userCallback;
    GLOBAL_STATE.userInstrumentationCallbackArg = userCallbackArg;
    // Register ThreadStart to be called when a thread starts.
    PIN_AddThreadStartFunction(CCTLibThreadStart, nullptr);
    // Register for context change in case of signals .. Actually this is never used. // Todo: - fix me
    PIN_AddContextChangeFunction(OnSig, nullptr);
    // Initialize ModuleInfoMap
    //ModuleInfoMap.set_empty_key(UINT_MAX);
    // Record Module information on each Image load.
    IMG_AddInstrumentFunction(CCTLibInstrumentImageLoad, nullptr);

    if (doDataCentric) {
        InitDataCentric();
    }

    // Since some functions may not be known, instrument every "trace"
    TRACE_AddInstrumentFunction(CCTLibInstrumentTrace, (void*)isInterestingIns);
    // Register Image to be called to instrument functions.
    IMG_AddInstrumentFunction(CCTLibImage, nullptr);
    // Add a function to report entire stats at the termination.
    PIN_AddFiniFunction(CCTLibFini, nullptr);
    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, nullptr);
    // We need to know if the applicated has started
    PIN_AddApplicationStartFunction(CCTLibAppStartNotification, nullptr);
    return 0;
}


int PinCCTLibInitForPostmortemAnalysis(FILE* logFile, const string& serializedFilesDirectory) {
    if (GLOBAL_STATE.cctLibUsageMode == CCT_LIB_MODE_COLLECTION) {
        fprintf(stderr, "\n CCTLib was initialized for online collection using PinCCTLibInit! Exiting...\n");
        PIN_ExitApplication(-1);
    }

    GLOBAL_STATE.cctLibUsageMode = CCT_LIB_MODE_POSTMORTEM;
    // Initialize Symbols, we need them to report functions and lines
    PIN_InitSymbols();
    // Intialize
    InitBuffers();
    InitLogFile(logFile);
    InitMapFilePrefix();
    InitSegHandler();
    InitXED();
    //InitLocks();
    // Obtain  a key for TLS storage.
    GLOBAL_STATE.CCTLibTlsKey = PIN_CreateThreadDataKey(nullptr /*TODO have a destructor*/);
    DeserializeMetadata(serializedFilesDirectory);
    return 0;
}

#ifdef HAVE_METRIC_PER_IPNODE
static void BottomUpTraverse(TraceNode* node, void (*opFunc)(const THREADID threadid, ContextHandle_t myHandle, ContextHandle_t parentHandle, void** myMetric, void** parentMetric), const THREADID threadid);

static void BottomUpTraverseHelper(TraceSplay* node, void (*opFunc)(const THREADID threadid, ContextHandle_t myHandle, ContextHandle_t parentHandle, void** myMetric, void** parentMetric), const THREADID threadid) {
    if (!node)
        return;

    BottomUpTraverseHelper(node->left, opFunc, threadid);
    BottomUpTraverse(node->value, opFunc, threadid);
    BottomUpTraverseHelper(node->right, opFunc, threadid);
}
static void BottomUpTraverse(TraceNode* node, void (*opFunc)(const THREADID threadid, ContextHandle_t myHandle, ContextHandle_t parentHandle, void** myMetric, void** parentMetric), const THREADID threadid) {
    if (!node) {
        return;
    }
    for (uint32_t i = 0; i < node->nSlots; i++) {
        if (GET_IPNODE_FROM_CONTEXT_HANDLE(node->childCtxtStartIdx + i)->calleeTraceNodes) {
            // Iterate over all decendent TraceNode of traceNode->childCtxtStartIdx[i]
            BottomUpTraverseHelper(GET_IPNODE_FROM_CONTEXT_HANDLE(node->childCtxtStartIdx + i)->calleeTraceNodes, opFunc, threadid);
        }
        // do anything here
        assert(node->callerCtxtHndl);
        if (node->callerCtxtHndl) {
            ContextHandle_t myHandle = node->childCtxtStartIdx + i;
            ContextHandle_t parentHandle = node->callerCtxtHndl;
            opFunc(threadid, myHandle, parentHandle, &(GET_IPNODE_FROM_CONTEXT_HANDLE(node->childCtxtStartIdx + i)->metric), &(GET_IPNODE_FROM_CONTEXT_HANDLE(node->callerCtxtHndl)->metric));
        }
    }
}

void TraverseCCTBottomUp(const THREADID threadid, void (*opFunc)(const THREADID threadid, ContextHandle_t myHandle, ContextHandle_t parentHandle, void** myMetric, void** parentMetric)) {
    ThreadData* tData = CCTLibGetTLS(threadid);
    BottomUpTraverse(tData->tlsRootTraceNode, opFunc, threadid);
}
#endif

bool HaveSameCallerPrefix(ContextHandle_t ctxt1, ContextHandle_t ctxt2) {
    if (ctxt1 == ctxt2)
        return true;
    ContextHandle_t t1 = GET_IPNODE_FROM_CONTEXT_HANDLE(ctxt1)->parentTraceNode->callerCtxtHndl;
    ContextHandle_t t2 = GET_IPNODE_FROM_CONTEXT_HANDLE(ctxt2)->parentTraceNode->callerCtxtHndl;
    return t1 == t2;
}

ContextHandle_t GetTraceStartHandle(ContextHandle_t ctxtHandle) {
    if (!ctxtHandle)
        return 0;
    return GET_IPNODE_FROM_CONTEXT_HANDLE(ctxtHandle)->parentTraceNode->childCtxtStartIdx;
}

bool IsSameSourceLine(ContextHandle_t ctxt1, ContextHandle_t ctxt2) {
    if (ctxt1 == ctxt2)
        return true;

    ADDRINT ip1 = GetIPFromInfo(ctxt1);
    ADDRINT ip2 = GetIPFromInfo(ctxt2);

    if (ip1 == ip2)
        return true;

    uint32_t lineNo1, lineNo2;
    string filePath1, filePath2;

    PIN_GetSourceLocation(ip1, NULL, (INT32*)&lineNo1, &filePath1);
    PIN_GetSourceLocation(ip2, NULL, (INT32*)&lineNo2, &filePath2);

    return static_cast<bool>(filePath1 == filePath2 && lineNo1 == lineNo2);
}

/* ==================================hpcviewer support===================================*/
/*
 * This support is added by Xiaonan Hu and tailored by Xu Liu at College of William and Mary.
 */

// necessary macros
#define HASH_PRIME 2001001003
#define HASH_GEN 4001
#define SPINLOCK_UNLOCKED_VALUE (0L)
#define SPINLOCK_LOCKED_VALUE (1L)
#define OSUtil_hostid_NULL (-1)
#define INITIALIZE_SPINLOCK(x) \
    { .thelock = (x) }
#define SPINLOCK_UNLOCKED INITIALIZE_SPINLOCK(SPINLOCK_UNLOCKED_VALUE)
#define SPINLOCK_LOCKED INITIALIZE_SPINLOCK(SPINLOCK_LOCKED_VALUE)

#define HPCRUN_FMT_NV_prog "program-name"
#define HPCRUN_FMT_NV_progPath "program-path"
#define HPCRUN_FMT_NV_envPath "env-path"
#define HPCRUN_FMT_NV_jobId "job-id"
#define HPCRUN_FMT_NV_mpiRank "mpi-id"
#define HPCRUN_FMT_NV_tid "thread-id"
#define HPCRUN_FMT_NV_hostid "host-id"
#define HPCRUN_FMT_NV_pid "process-id"
#define HPCRUN_SAMPLE_PROB "HPCRUN_PROCESS_FRACTION"
#define HPCRUN_FMT_NV_traceMinTime "trace-min-time"
#define HPCRUN_FMT_NV_traceMaxTime "trace-max-time"

#define FILENAME_TEMPLATE "%s/%s-%06u-%03d-%08lx-%u-%d.%s"
#define TEMPORARY "%s/%s-"
#define RANK 0

#define FILES_RANDOM_GEN 4
#define FILES_MAX_GEN 11
#define FILES_EARLY 0x1
#define FILES_LATE 0x2
#define DEFAULT_PROB 0.1

// *** atomic-op-asm.h && atomic-op-gcc.h ***
#if defined(LL_BODY) && defined(SC_BODY)

#define read_modify_write(type, addr, expn, result)                               \
    {                                                                             \
        type __new;                                                               \
        do {                                                                      \
            result = (type)load_linked((unsigned long*)addr);                     \
            __new = expn;                                                         \
        } while (!store_conditional((unsigned long*)addr, (unsigned long)__new)); \
    }
#else

#define read_modify_write(type, addr, expn, result)                \
    {                                                              \
        type __new;                                                \
        do {                                                       \
            result = *addr;                                        \
            __new = expn;                                          \
        } while (compare_and_swap(addr, result, __new) != result); \
    }
#endif

#define compare_and_swap(addr, oldval, newval) \
    __sync_val_compare_and_swap(addr, oldval, newval)

// ***********************

// create a new node type to substitute IPNode and TraceNode
struct NewIPNode {
    vector<NewIPNode*> childIPNodes;
    // TODO(preexisting-perf): findSameIP scans childIPNodes linearly on every
    // insertion, making tranverseIPs / mergeIP total cost O(N^2) in
    // per-parent child count. For workloads whose CCT has many unique
    // callee IPs under one caller (e.g. reuseApp's JIT'd NOP sleds) this
    // makes newCCT_hpcrun_write functionally non-terminating. Fix by
    // mirroring inserts into an unordered_map<ADDRINT, NewIPNode*> for
    // O(1) findSameIP. Not required for `make check`.
    NewIPNode* parentIPNode;
    ADDRINT IPAddress;
    int32_t parentID;
    int32_t ID;
    TraceSplay* tmpSplay;
    void* metric;
    uint64_t* metricVal;
};

using size_t = uint16_t;


using MetricFlags_Ty_t = enum {
    MetricFlags_Ty_NULL = 0,
    MetricFlags_Ty_Raw,
    MetricFlags_Ty_Final,
    MetricFlags_Ty_Derived
};


using MetricFlags_ValTy_t = enum {
    MetricFlags_ValTy_NULL = 0,
    MetricFlags_ValTy_Incl,
    MetricFlags_ValTy_Excl
};


using MetricFlags_ValFmt_t = enum {
    MetricFlags_ValFmt_NULL = 0,
    MetricFlags_ValFmt_Int,
    MetricFlags_ValFmt_Real,
};


using epoch_flags_bitfield = struct epoch_flags_bitfield {
    bool isLogicalUnwind : 1;
    uint64_t unused : 63;
};


using epoch_flags_t = union epoch_flags_t {
    epoch_flags_bitfield fields;
    uint64_t bits; // for reading/writing
};


using metric_desc_properties_t = struct metric_desc_properties_t {
    unsigned time : 1;
    unsigned cycles : 1;
};


using hpcrun_metricFlags_fields = struct hpcrun_metricFlags_fields {
    MetricFlags_Ty_t ty : 8;
    MetricFlags_ValTy_t valTy : 8;
    MetricFlags_ValFmt_t valFmt : 8;
    uint8_t unused0;
    uint16_t partner;
    uint8_t /*bool*/ show;
    uint8_t /*bool*/ showPercent;
    uint64_t unused1;
};


using hpcrun_metricFlags_t = union hpcrun_metricFlags_t {
    hpcrun_metricFlags_fields fields;
    uint8_t bits[2 * 8]; // for reading/writing
    uint64_t bits_big[2]; // for easy initialization
};

using metric_desc_t = struct metric_desc_t {
    char* name;
    char* description;
    //uint8_t bits[2 * 8];
    //uint64_t bits_big[2];
    hpcrun_metricFlags_t flags;
    uint64_t period;
    metric_desc_properties_t properties;
    char* formula;
    char* format;
    bool is_frequency_metric;
};


using metric_set_t = struct metric_set_t;


using spinlock_t = struct spinlock_s {
    volatile long thelock;
};


struct fileid {
    int done;
    long host;
    int gen;
};


extern const metric_desc_t metricDesc_NULL;

const metric_desc_t metricDesc_NULL = {
    NULL, // name
    NULL, // description
    MetricFlags_Ty_NULL,
    MetricFlags_ValTy_NULL,
    MetricFlags_ValFmt_NULL,
    0, // fields.unused0
    0, // fields.partner
    (uint8_t) true, // fields.show
    (uint8_t) true, // fields.showPercent
    0, // unused 1
    0, // period
    0, // properties.time
    0, // properties.cycles
    NULL,
    NULL,
};


extern const hpcrun_metricFlags_t hpcrun_metricFlags_NULL;

const hpcrun_metricFlags_t hpcrun_metricFlags_NULL = {
    MetricFlags_Ty_NULL,
    MetricFlags_ValTy_NULL,
    MetricFlags_ValFmt_NULL,
    0, // fields.unused0
    0, // fields.partner
    (uint8_t) true, // fields.show
    (uint8_t) true, // fields.showPercent
    0, // unused 1
};


static epoch_flags_t epoch_flags = {
    .bits = 0x0000000000000000};

static const uint64_t default_measurement_granularity = 1;
static const uint32_t default_ra_to_callsite_distance = 1;

// ***************** file ************************
static spinlock_t files_lock = SPINLOCK_UNLOCKED;
static pid_t mypid = 0;
static struct fileid earlyid;
static struct fileid lateid;
static int log_done = 0;
static int log_rename_done = 0;
static int log_rename_ret = 0;
// ***********************************************
/*   for HPCViewer output format     */
std::string dirName;
std::string* filename;

// *************************************** format ****************************************
static const char HPCRUN_FMT_Magic[] = "HPCRUN-profile____";
static const int HPCRUN_FMT_MagicLen = (sizeof(HPCRUN_FMT_Magic) - 1);
static const char HPCRUN_FMT_Endian[] = "b";
static const int HPCRUN_FMT_EndianLen = (sizeof(HPCRUN_FMT_Endian) - 1);
static const char HPCRUN_ProfileFnmSfx[] = "hpcrun";
static const char HPCRUN_FMT_Version[] = "02.00";
static const char HPCRUN_FMT_VersionLen = (sizeof(HPCRUN_FMT_Version) - 1);
static const char HPCRUN_FMT_EpochTag[] = "EPOCH___";
static const int HPCRUN_FMT_EpochTagLen = (sizeof(HPCRUN_FMT_EpochTag) - 1);
const uint bufSZ = 32; // sufficient to hold a 64-bit integer in base 10
int hpcfmt_str_fwrite(const char* str, FILE* outfs);
int hpcrun_fmt_hdrwrite(FILE* fs);
int hpcrun_fmt_hdr_fwrite(FILE* fs, const char* arg1, const char* arg2);
int hpcrun_open_profile_file(int thread, const char* fileName);
static int hpcrun_open_file(int thread, const char* suffix, int flags, const char* fileName);
extern int fputs(const char* __restrict __s, FILE* __restrict __stream);
int hpcrun_fmt_loadmap_fwrite(FILE* fs, const std::string& filename);
int hpcrun_fmt_epochHdr_fwrite(FILE* fs, epoch_flags_t flags,
                               uint64_t measurementGranularity, uint32_t raToCallsiteOfst);
static void hpcrun_files_init();
uint OSUtil_pid();
const char* OSUtil_jobid();
long OSUtil_hostid();
void hpcrun_set_metric_info_w_fn(int metric_id, const char* name,
                                 MetricFlags_ValFmt_t valFmt, size_t period, FILE* fs);
size_t hpcio_be2_fwrite(const uint16_t* val, FILE* fs);
size_t hpcio_be4_fwrite(const uint32_t* val, FILE* fs);
size_t hpcio_be8_fwrite(const uint64_t* val, FILE* fs);
size_t hpcio_beX_fwrite(uint8_t* val, size_t size, FILE* fs);
//string GetFileName(std::string & pathname);
// ******************************************************************************************

// ****************Merge splay trees **************************************************
NewIPNode* constructIPNode(NewIPNode* parentIP, IPNode* oldIPNode, uint32_t parentID, uint64_t* nodeCount);
void tranverseIPs(NewIPNode* curIPNode, TraceSplay* childCtxtStartIdx, uint64_t* nodeCount);
NewIPNode* findSameIP(vector<NewIPNode*> nodes, IPNode* node);
void mergeIP(NewIPNode* prev, IPNode* cur, uint64_t* nodeCount);
uint32_t GetID();
// ************************************************************************************

// ****************Print merged splay tree*********************************************
void IPNode_fwrite(NewIPNode* node, FILE* fs);
void tranverseNewCCT(vector<NewIPNode*> nodes, FILE* fs);
// ************************************************************************************

uint OSUtil_pid() {
    pid_t pid = getpid();
    return (uint)pid;
}


const char* OSUtil_jobid() {
    char* jid = NULL;

    // Cobalt
    jid = getenv("COBALT_JOB_ID");
    if (jid)
        return jid;

    // PBS
    jid = getenv("PBS_JOB_ID");
    if (jid)
        return jid;

    // SLURM
    jid = getenv("SLURM_JOB_ID");
    if (jid)
        return jid;

    // Sun Grid Engine
    jid = getenv("JOB_ID");
    if (jid)
        return jid;

    return jid;
}


long OSUtil_hostid() {
    static long hostid = OSUtil_hostid_NULL;

    if (hostid == OSUtil_hostid_NULL) {
        // gethostid returns a 32-bit id. treat it as unsigned to prevent useless sign extension
        hostid = (uint32_t)gethostid();
    }

    return hostid;
}

static inline int
hpcfmt_int2_fwrite(uint16_t val, FILE* outfs) {
    if (sizeof(uint16_t) != hpcio_be2_fwrite(&val, outfs)) {
        return 0;
    }
    return 1;
}


static inline int
hpcfmt_int4_fwrite(uint32_t val, FILE* outfs) {
    if (sizeof(uint32_t) != hpcio_be4_fwrite(&val, outfs)) {
        return 0;
    }
    return 1;
}


static inline int
hpcfmt_int8_fwrite(uint64_t val, FILE* outfs) {
    if (sizeof(uint64_t) != hpcio_be8_fwrite(&val, outfs)) {
        return 0;
    }
    return 1;
}


static inline int
hpcfmt_intX_fwrite(uint8_t* val, size_t size, FILE* outfs) {
    if (size != hpcio_beX_fwrite(val, size, outfs)) {
        return 0;
    }
    return 1;
}


int hpcio_fclose(FILE* fs) {
    if (fs && fclose(fs) == EOF) {
        return 1;
    }
    return 0;
}

static void hpcrun_files_init() {
    pid_t cur_pid = getpid();

    if (mypid != cur_pid) {
        mypid = cur_pid;
        earlyid.done = 0;
        earlyid.host = OSUtil_hostid();
        earlyid.gen = 0;
        lateid = earlyid;
        log_done = 0;
        log_rename_done = 0;
        log_rename_ret = 0;
    }
}


// Replace "id" with the next unique id if possible. Normally, (hostid, pid, gen)
// works after one or two iteration. To be extra robust (eg, hostid is not unique),
// at some point, give up and pick a random hostid.
// Returns: 0 on success, else -1 on failure.
static int hpcrun_files_next_id(struct fileid* id) {
    struct timeval tv;
    int fd;

    if (id->done || id->gen >= FILES_MAX_GEN) {
        // failure, out of options
        return -1;
    }

    id->gen++;
    if (id->gen >= FILES_RANDOM_GEN) {
        // give up and use a random host id
        fd = open("/dev/urandom", O_RDONLY);
        printf("Inside hpcrun_files_next_id fd = %d\n", fd);
        if (fd >= 0) {
            read(fd, &id->host, sizeof(id->host));
            close(fd);
        }
        gettimeofday(&tv, NULL);
        id->host += (tv.tv_sec << 20) + tv.tv_usec;
        id->host &= 0x00ffffffff;
    }
    return 0;
}

static int hpcrun_open_file(int thread, const char* suffix, int flags, const char* fileName) {
    char name[PATH_MAX];
    struct fileid* id;
    int fd, ret;

    id = (flags & FILES_EARLY) ? &earlyid : &lateid;

    for (;;) {
        errno = 0;
        ret = snprintf(name, PATH_MAX, FILENAME_TEMPLATE, dirName.c_str(), fileName, RANK, thread, id->host, mypid, id->gen, suffix);

        if (ret >= PATH_MAX) {
            fd = -1;
            errno = ENAMETOOLONG;
            break;
        }

        fd = open(name, O_WRONLY | O_CREAT | O_EXCL, 0644);

        if (fd >= 0) {
            // sucess
            break;
        }

        if (errno != EEXIST || hpcrun_files_next_id(id) != 0) {
            // failure, out of options
            fd = -1;
            break;
        }
    }

    id->done = 1;

    if (flags & FILES_EARLY) {
        // late id starts where early id is chosen
        lateid = earlyid;
        lateid.done = 0;
    }

    if (fd < 0) {
        printf("cctlib_hpcrun: unable to open %s file: '%s': %s", suffix, name, strerror(errno));
    }

    return fd;
}

static int unsigned long fetch_and_store(volatile long* addr, long newval) {
    long result;
    read_modify_write(long, addr, newval, result);
    return result;
}


static inline void spinlock_unlock(spinlock_t* l) {
    l->thelock = SPINLOCK_UNLOCKED_VALUE;
}


static inline void spinlock_lock(spinlock_t* l) {
    /* test-and-test-and-set lock*/
    for (;;) {
        while (l->thelock != SPINLOCK_UNLOCKED_VALUE)
            ;

        if (fetch_and_store(&l->thelock, SPINLOCK_LOCKED_VALUE) == SPINLOCK_UNLOCKED_VALUE) {
            break;
        }
    }
}


// Write out the format for metric table. Needs updates
void hpcrun_set_metric_info_w_fn(int metric_id, const char* name, size_t period, FILE* fs) {
    // Write out the number of metric table in the program
    metric_desc_t mdesc = metricDesc_NULL;
    mdesc.flags = hpcrun_metricFlags_NULL;

    for (int i = 0; i < 16; i++) {
        mdesc.flags.bits[i] = (uint8_t)0x00;
    }

    mdesc.name = (char*)name;
    mdesc.description = (char*)name; // TODO
    mdesc.period = period;
    mdesc.flags.fields.ty = MetricFlags_Ty_Raw;
    MetricFlags_ValFmt_t valFmt = (MetricFlags_ValFmt_t)1;
    mdesc.flags.fields.valFmt = valFmt;
    mdesc.flags.fields.show = true;
    mdesc.flags.fields.showPercent = true;
    mdesc.formula = NULL;
    mdesc.format = NULL;
    mdesc.is_frequency_metric = false;

    hpcfmt_str_fwrite(mdesc.name, fs);
    hpcfmt_str_fwrite(mdesc.description, fs);
    hpcfmt_intX_fwrite(mdesc.flags.bits, sizeof(mdesc.flags), fs); // Write metric flags bits for reading/writing
    hpcfmt_int8_fwrite(mdesc.period, fs);
    hpcfmt_str_fwrite(mdesc.formula, fs);
    hpcfmt_str_fwrite(mdesc.format, fs);
    hpcfmt_int2_fwrite(mdesc.is_frequency_metric, fs);

    // write auxaliary description to the table.
    // These values are only related to perf, not applicable to cctlib, so set all to 0
    hpcfmt_int2_fwrite(0, fs);
    hpcfmt_int8_fwrite(0, fs);
    hpcfmt_int8_fwrite(0, fs);
}

// Get the filename from pathname
//string GetFileName(std::string & pathname) {
//  size_t index = pathname.find_last_of("/");
//  string fileName = pathname.substr(index + 1);
//  return fileName;
//}


// Initialize binary file and write hpcrun header
FILE* lazy_open_data_file(int tID, std::string* filename) {
    FILE* fs; // = file;

    //  const char* pathCharName = pathname.c_str();
    //  string fileName = GetFileName(pathname);
    const char* fileCharName = filename->c_str();

    int fd = hpcrun_open_profile_file(tID, fileCharName);
    fs = fdopen(fd, "w");

    if (fs == NULL)
        return NULL;

    const char* jobIdStr = OSUtil_jobid();

    if (!jobIdStr)
        jobIdStr = "";

    char mpiRankStr[bufSZ];
    mpiRankStr[0] = '0';
    snprintf(mpiRankStr, bufSZ, "%d", 0);
    char tidStr[bufSZ];
    snprintf(tidStr, bufSZ, "%d", tID);
    char hostidStr[bufSZ];
    snprintf(hostidStr, bufSZ, "%lx", OSUtil_hostid());
    char pidStr[bufSZ];
    snprintf(pidStr, bufSZ, "%u", OSUtil_pid());
    char traceMinTimeStr[bufSZ];
    snprintf(traceMinTimeStr, bufSZ, "%" PRIu64, (unsigned long int)0);
    char traceMaxTimeStr[bufSZ];
    snprintf(traceMaxTimeStr, bufSZ, "%" PRIu64, (unsigned long int)0);

    // ======  file hdr  =====
    hpcrun_fmt_hdrwrite(fs);
    static int global_arg_len = 9;
    hpcfmt_int4_fwrite(global_arg_len, fs);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_prog, fileCharName);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_progPath, filename->c_str());
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_envPath, getenv("PATH"));
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_jobId, jobIdStr);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_tid, tidStr);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_hostid, hostidStr);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_pid, pidStr);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_traceMinTime, traceMinTimeStr);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_traceMaxTime, traceMaxTimeStr);
    hpcrun_fmt_epochHdr_fwrite(fs, epoch_flags, default_measurement_granularity, default_ra_to_callsite_distance);
    // log the number of metrics
    hpcfmt_int4_fwrite((uint32_t)GLOBAL_STATE.nmetric - 1, fs);
    // log each metric
    for (int i = 1; i < GLOBAL_STATE.nmetric; i++)
        hpcrun_set_metric_info_w_fn(i, GLOBAL_STATE.metrics[i], 1, fs);
    hpcrun_fmt_loadmap_fwrite(fs, *filename);
    return fs;
}

int hpcrun_fmt_loadmap_fwrite(FILE* fs, const std::string& filename) {
    uint16_t num = 2;
    // Write loadmap size
    hpcfmt_int4_fwrite((uint32_t)GLOBAL_STATE.ModuleInfoMap.size(), fs); // Write loadmap size

    unordered_map<UINT32, ModuleInfo>::iterator it, ito;
    // First print out the load module of the executable binary
    for (it = GLOBAL_STATE.ModuleInfoMap.begin(); it != GLOBAL_STATE.ModuleInfoMap.end(); ++it) {
        if (it->second.id == 1) {
            // Write loadmap information
            hpcfmt_int2_fwrite(1, fs); // Write loadmap id of the main executbale
            hpcfmt_str_fwrite(it->second.moduleName.c_str(), fs); // Write loadmap name
            hpcfmt_int8_fwrite((uint64_t)0, fs); // Write loadmap flags
            break;
        }
    }

    // write other load modules
    for (it = GLOBAL_STATE.ModuleInfoMap.begin(); it != GLOBAL_STATE.ModuleInfoMap.end(); ++it) {
        // currently only print out the load module of the executable binary
        if (it->second.id == 1) {
            continue;
        }

        // Write loadmap information of other modules
        it->second.id = num;
        hpcfmt_int2_fwrite(num++, fs); // Write loadmap id
        hpcfmt_str_fwrite(it->second.moduleName.c_str(), fs); // Write loadmap name
        hpcfmt_int8_fwrite((uint64_t)0, fs); // Write loadmap flags
    }

    return 0;
}


int hpcrun_open_profile_file(int thread, const char* fileName) {
    int ret;
    spinlock_lock(&files_lock);
    hpcrun_files_init();
    ret = hpcrun_open_file(thread, HPCRUN_ProfileFnmSfx, FILES_LATE, fileName);
    spinlock_unlock(&files_lock);
    return ret;
}


int hpcrun_fmt_hdrwrite(FILE* fs) {
    fwrite(HPCRUN_FMT_Magic, 1, HPCRUN_FMT_MagicLen, fs);
    fwrite(HPCRUN_FMT_Version, 1, HPCRUN_FMT_VersionLen, fs);
    fwrite(HPCRUN_FMT_Endian, 1, HPCRUN_FMT_EndianLen, fs);
    return 1;
}


int hpcrun_fmt_epochHdr_fwrite(FILE* fs, epoch_flags_t flags,
                               uint64_t measurementGranularity, uint32_t raToCallsiteOfst) {
    fwrite(HPCRUN_FMT_EpochTag, 1, HPCRUN_FMT_EpochTagLen, fs);
    hpcfmt_int8_fwrite(flags.bits, fs);
    hpcfmt_int8_fwrite(measurementGranularity, fs);
    hpcfmt_int4_fwrite(raToCallsiteOfst, fs);
    hpcfmt_int4_fwrite((uint32_t)1, fs);
    hpcrun_fmt_hdr_fwrite(fs, "TODO:epoch-name", "TODO:epoch-value");
    return 1;
}


int hpcrun_fmt_hdr_fwrite(FILE* fs, const char* arg1, const char* arg2) {
    hpcfmt_str_fwrite(arg1, fs);
    hpcfmt_str_fwrite(arg2, fs);
    return 1;
}

int hpcfmt_str_fwrite(const char* str, FILE* outfs) {
    unsigned int i;
    uint32_t len = (str) ? strlen(str) : 0;
    hpcfmt_int4_fwrite(len, outfs);

    for (i = 0; i < len; i++) {
        int c = fputc(str[i], outfs);

        if (c == EOF)
            return 0;
    }

    return 1;
}


size_t hpcio_be2_fwrite(const uint16_t* val, FILE* fs) {
    uint16_t v = *val; // local copy of val
    int shift = 0, num_write = 0, c;

    for (shift = 8; shift >= 0; shift -= 8) {
        c = fputc(((v >> shift) & 0xff), fs);

        if (c == EOF) {
            break;
        }

        num_write++;
    }

    return num_write;
}


size_t hpcio_be4_fwrite(const uint32_t* val, FILE* fs) {
    uint32_t v = *val; // local copy of val
    int shift = 0, num_write = 0, c;

    for (shift = 24; shift >= 0; shift -= 8) {
        c = fputc(((v >> shift) & 0xff), fs);

        if (c == EOF) {
            break;
        }
        num_write++;
    }

    return num_write;
}

size_t hpcio_be8_fwrite(const uint64_t* val, FILE* fs) {
    uint64_t v = *val; // local copy of val
    int shift = 0, num_write = 0, c;

    for (shift = 56; shift >= 0; shift -= 8) {
        c = fputc(((v >> shift) & 0xff), fs);

        if (c == EOF) {
            break;
        }

        num_write++;
    }

    return num_write;
}


size_t hpcio_beX_fwrite(uint8_t* val, size_t size, FILE* fs) {
    size_t num_write = 0;

    for (uint i = 0; i < size; ++i) {
        int c = fputc(val[i], fs);

        if (c == EOF)
            break;
        num_write++;
    }

    return num_write;
}


// Construct NewIPNode
NewIPNode* constructIPNode(NewIPNode* parentIP, IPNode* oldIPNode, uint32_t parentID, uint64_t* nodeCount) {
    if (NULL == oldIPNode)
        return NULL;

    NewIPNode* curIP = new NewIPNode();
    curIP->parentIPNode = parentIP;
    curIP->IPAddress = GetIPFromInfo(GET_CONTEXT_HANDLE_FROM_IP_NODE_CHECKED(oldIPNode));
    curIP->parentID = parentID;
    curIP->tmpSplay = oldIPNode->calleeTraceNodes;
#ifdef HAVE_METRIC_PER_IPNODE
    curIP->metric = oldIPNode->metric;
#endif

    if (curIP->tmpSplay)
        curIP->ID = GetID();
    else
        curIP->ID = -GetID();

    (*nodeCount)++;
    return curIP;
}

// Inorder tranversal of the previous splay tree and create the new tree
void tranverseIPs(NewIPNode* curIPNode, TraceSplay* childCtxtStartIdx, uint64_t* nodeCount) {
    if (NULL == childCtxtStartIdx)
        return;

    TraceNode* tNode = childCtxtStartIdx->value;
    uint32_t i;
    tranverseIPs(curIPNode, childCtxtStartIdx->left, nodeCount);

    for (i = 0; i < tNode->nSlots; i++) {
        NewIPNode* sameIP = findSameIP(curIPNode->childIPNodes, GET_IPNODE_FROM_CONTEXT_HANDLE_CHECKED(tNode->childCtxtStartIdx + i));
        if (sameIP) {
            mergeIP(sameIP, GET_IPNODE_FROM_CONTEXT_HANDLE_CHECKED(tNode->childCtxtStartIdx + i), nodeCount);
        } else {
            NewIPNode* nNode = constructIPNode(curIPNode, GET_IPNODE_FROM_CONTEXT_HANDLE_CHECKED(tNode->childCtxtStartIdx + i), curIPNode->ID, nodeCount);
            curIPNode->childIPNodes.push_back(nNode);

            if (nNode->tmpSplay) {
                tranverseIPs(nNode, nNode->tmpSplay, nodeCount);
            }
        }
    }
    tranverseIPs(curIPNode, childCtxtStartIdx->right, nodeCount);
}


// Check to see whether another IPNode has the same address under the same parent.
NewIPNode* findSameIP(vector<NewIPNode*> nodes, IPNode* node) {
    std::size_t i;
    ADDRINT address = GetIPFromInfo(GET_CONTEXT_HANDLE_FROM_IP_NODE_CHECKED(node));

    for (i = 0; i < nodes.size(); i++) {
        if (nodes.at(i)->IPAddress == address)
            return nodes.at(i);
    }

    return NULL;
}

// Merging the children of two nodes
void mergeIP(NewIPNode* prev, IPNode* cur, uint64_t* nodeCount) {
    if (!cur)
        return;
#ifdef HAVE_METRIC_PER_IPNODE
    void* m = prev->metric;
    void* n = cur->metric;
    if (m && n) {
        if (GLOBAL_STATE.mergeFunc)
            GLOBAL_STATE.mergeFunc(m, n);
    } else if (!m && n) {
        prev->metric = n;
    }
#endif

    if (cur->calleeTraceNodes) {
        tranverseIPs(prev, cur->calleeTraceNodes, nodeCount);
    }
}


// Helper function to assign ID for each node
uint32_t GetID() {
    // begin with 2 because 0 is the common root
    static uint32_t IDGlobal = 2;
    uint32_t id = __sync_fetch_and_add(&IDGlobal, 2);
    return id;
}

// Write out each IP's id, parent id, loadmodule id (1) and address
void IPNode_fwrite(NewIPNode* node, FILE* fs) {
    if (!node)
        return;
    hpcfmt_int4_fwrite(node->ID, fs);
    hpcfmt_int4_fwrite(node->parentID, fs);
    // adjust the IPaddress to point to return address of the callsite (internal nodes) for hpcrun requirement
    if (node->ID > 0)
        node->IPAddress++;

    IMG im = IMG_FindByAddress(node->IPAddress);
    if (node->IPAddress == 0 || IMG_Id(im) == 0) {
        hpcfmt_int2_fwrite(0, fs);
        hpcfmt_int8_fwrite(node->IPAddress, fs);
    } else {
        hpcfmt_int2_fwrite(GLOBAL_STATE.ModuleInfoMap[IMG_Id(im)].id, fs); // Set loadmodule id to 1
        // normalize the IP offset to the beginning of the load module and write out
        hpcfmt_int8_fwrite(node->IPAddress - GLOBAL_STATE.ModuleInfoMap[IMG_Id(im)].imgLoadOffset, fs);
    }

    // this uses .metric field in the NewIPNode, which means we have per IPNode metric
    // for this case, by default, we only have one metric
    if (GLOBAL_STATE.computeMetricVal) {
        hpcfmt_int8_fwrite(GLOBAL_STATE.computeMetricVal(node->metric), fs);
    } else { // not necessarily have per IPNode metric
        for (int i = 1; i < GLOBAL_STATE.nmetric; i++)
            hpcfmt_int8_fwrite(node->metricVal[i], fs);
    }
}


// Tranverse and print the calling context tree (nodes first)
// Pass `nodes` by const reference; the original by-value signature copied
// the whole child vector on every recursive call and made hpcrun emission
// quadratic in tree size.
void tranverseNewCCT(vector<NewIPNode*> nodes, FILE* fs) {
    if (nodes.empty())
        return;
    std::size_t i;

    for (i = 0; i < nodes.size(); i++) {
        IPNode_fwrite(nodes.at(i), fs);
    }

    for (i = 0; i < nodes.size(); i++) {
        if (!nodes.at(i)->childIPNodes.empty()) {
            tranverseNewCCT(nodes.at(i)->childIPNodes, fs);
        }
    }
}

static void findMain(IPNode* curIPNode, TraceSplay* childCtxtStartIdx, IPNode** mainNode) {
    if (NULL == childCtxtStartIdx)
        return;

    TraceNode* tNode = childCtxtStartIdx->value;
    uint32_t i;
    findMain(curIPNode, childCtxtStartIdx->left, mainNode);

    for (i = 0; i < tNode->nSlots; i++) {
        if (GetIPFromInfo((tNode->childCtxtStartIdx + i)) == GLOBAL_STATE.mainIP) {
            *mainNode = GET_IPNODE_FROM_CONTEXT_HANDLE_CHECKED(tNode->childCtxtStartIdx + i);
            return;
        }
        IPNode* childNode = GET_IPNODE_FROM_CONTEXT_HANDLE_CHECKED(tNode->childCtxtStartIdx + i);
        if (childNode && childNode->calleeTraceNodes) {
            findMain(childNode, childNode->calleeTraceNodes, mainNode);
        }
    }
    findMain(curIPNode, childCtxtStartIdx->right, mainNode);
}

NewIPNode* findSameIPbyIP(vector<NewIPNode*> nodes, ADDRINT address) {
    std::size_t i;
    for (i = 0; i < nodes.size(); i++) {
        if (nodes.at(i)->IPAddress == address)
            return nodes.at(i);
    }
    return NULL;
}

// Construct NewIPNode
NewIPNode* constructIPNodeFromIP(NewIPNode* parentIP, ADDRINT address, uint64_t* nodeCount) {
    NewIPNode* curIP = new NewIPNode();
    curIP->childIPNodes.clear();
    curIP->parentIPNode = parentIP;
    curIP->IPAddress = address;
    curIP->parentID = parentIP->ID;
    curIP->tmpSplay = NULL;
    curIP->ID = GetID();
    curIP->metric = NULL;
    curIP->metricVal = new uint64_t[GLOBAL_STATE.nmetric];
    for (int i = 1; i < GLOBAL_STATE.nmetric; i++)
        curIP->metricVal[i] = 0;
    parentIP->childIPNodes.push_back(curIP);

    (*nodeCount)++;
    return curIP;
}

void hpcrun_insert_path(NewIPNode* root, HPCRunCCT_t* HPCRunNode, uint64_t* nodeCount) {
    vector<Context> contextVec1, contextVec2;

    if (HPCRunNode->ctxtHandle1 == 0)
        return;

    GetFullCallingContextInSitu(HPCRunNode->ctxtHandle1, contextVec1);
    GetFullCallingContextInSitu(HPCRunNode->ctxtHandle2, contextVec2);

    NewIPNode* tmp;
    NewIPNode* cur = root;
    for (int32_t i = contextVec1.size() - 1; i >= 0; i--) {
        tmp = findSameIPbyIP(cur->childIPNodes, contextVec1[i].ip);
        if (!tmp) {
            NewIPNode* nIP = constructIPNodeFromIP(cur, contextVec1[i].ip, nodeCount);
            cur = nIP;
        } else {
            cur = tmp;
        }
    }

#if 0
  //add a join node
  tmp = findSameIPbyIP(cur->childIPNodes, (ADDRINT)KILLED_BY);
  if (!tmp) cur = constructIPNodeFromIP(cur, (ADDRINT)KILLED_BY, nodeCount);
  else cur = tmp;
#endif

    if (HPCRunNode->ctxtHandle2 != 0) {
        // concatenate the two contexts
        for (int32_t i = contextVec2.size() - 1; i >= 0; i--) {
            tmp = findSameIPbyIP(cur->childIPNodes, contextVec2[i].ip);
            if (!tmp) {
                NewIPNode* nIP = constructIPNodeFromIP(cur, contextVec2[i].ip, nodeCount);
                cur = nIP;
            } else {
                cur = tmp;
            }
        }
    }
    // metrics only associated with leaves
    // if the path already exists, just merge the metrics
    if (cur->ID < 0) {
        cur->metricVal[HPCRunNode->metric_id] += HPCRunNode->metric;
    } else {
        cur->metricVal[HPCRunNode->metric_id] = HPCRunNode->metric;
        cur->ID = -cur->ID;
    }
}

/*======APIs to support hpcviewer format======*/
/*
 * Initialize the formatting preparation
 * (called by the clients)
 * TODO: initialize metric table, provide custom metric merge functions
 */
int init_hpcrun_format(int argc, char* argv[], void (*mergeFunc)(void* des, void* src), uint64_t (*computeMetricVal)(void* metric), bool skip) {
    // Extract executable name
    int i;
    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            filename = new string(basename(argv[i + 1]));
            break;
        }
    }
    // Create the measurement directory
    dirName = "hpctoolkit-" + *filename + "-measurements";
    int status = mkdir(dirName.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    (void)status; // TODO: check errno != EEXIST and report real errors instead of ignoring.

    if (skip)
        GLOBAL_STATE.skip = true;

    GLOBAL_STATE.mergeFunc = mergeFunc;
    GLOBAL_STATE.computeMetricVal = computeMetricVal;
    // the current metric cursor is set to 1
    GLOBAL_STATE.nmetric = 1;
    return 0;
}

/*
 * API to create metrics
 */
int hpcrun_create_metric(const char* name) {
    int t = GLOBAL_STATE.nmetric;
    snprintf(GLOBAL_STATE.metrics[GLOBAL_STATE.nmetric++], MAX_LEN, "%s", name);
    return t;
}

/*
 * Write the calling context tree of 'threadid' thread 
 * (Called from clientele program) 
 */
int newCCT_hpcrun_write(THREADID threadid) {
    FILE* fs = lazy_open_data_file(int(threadid), filename);
    if (!fs)
        return -1;

    uint32_t i;
    ThreadData* tdata = CCTLibGetTLS(threadid);
    TraceNode* cctlib = tdata->tlsRootTraceNode;
    vector<NewIPNode*> IPHandle;

    // find the main node (the entry point by the programmer)
    IPNode* mainNode = NULL;
    if (GLOBAL_STATE.skip) {
        for (i = 0; i < cctlib->nSlots; i++) {
            IPNode* childNode = GET_IPNODE_FROM_CONTEXT_HANDLE_CHECKED(cctlib->childCtxtStartIdx + i);
            if (childNode) {
                findMain(childNode, childNode->calleeTraceNodes, &mainNode);
            }
        }
    }

    // only keep the main subtree
    if (mainNode) {
        // update cctlib and make the dummy root
        cctlib = new TraceNode();
        cctlib->nSlots = 1;
        cctlib->childCtxtStartIdx = mainNode->parentTraceNode->callerCtxtHndl;
        SetIPFromInfo(cctlib->childCtxtStartIdx, 0x0); // dummy root should have 0 ip
#ifdef HAVE_METRIC_PER_IPNODE
        IPNode* rootIP = GET_IPNODE_FROM_CONTEXT_HANDLE_CHECKED(cctlib->childCtxtStartIdx);
        if (rootIP)
            rootIP->metric = NULL;
#endif
    }

    for (i = 0; i < cctlib->nSlots; i++) {
        NewIPNode* nIP = constructIPNode(NULL, GET_IPNODE_FROM_CONTEXT_HANDLE_CHECKED(cctlib->childCtxtStartIdx + i), 0, &tdata->nodeCount);
        IPHandle.push_back(nIP);

        if (nIP->tmpSplay) {
            tranverseIPs(nIP, nIP->tmpSplay, &tdata->nodeCount);
        }
    }

    hpcfmt_int8_fwrite(tdata->nodeCount, fs);
    tranverseNewCCT(IPHandle, fs);
    hpcio_fclose(fs);
    return 0;
}


// This API is used to output a hpcrun CCT with selected call paths
int newCCT_hpcrun_build_cct(vector<HPCRunCCT_t*>& OldNodes, THREADID threadid) {
    // build the hpcrun-style CCT
    ThreadData* tdata = CCTLibGetTLS(threadid);
    // initialize the root node (dummy node)
    if (!tdata->tlsHPCRunCCTRoot) {
        tdata->tlsHPCRunCCTRoot = new NewIPNode();
        tdata->tlsHPCRunCCTRoot->childIPNodes.clear();
        tdata->tlsHPCRunCCTRoot->IPAddress = 0;
        tdata->tlsHPCRunCCTRoot->ID = 0;
        tdata->tlsHPCRunCCTRoot->tmpSplay = NULL;
        tdata->tlsHPCRunCCTRoot->metric = NULL;
        tdata->tlsHPCRunCCTRoot->metricVal = new uint64_t[GLOBAL_STATE.nmetric];
        for (int i = 1; i < GLOBAL_STATE.nmetric; i++)
            tdata->tlsHPCRunCCTRoot->metricVal[i] = 0;
        tdata->nodeCount = 0;
    }

    NewIPNode* root = tdata->tlsHPCRunCCTRoot;
    vector<HPCRunCCT_t*>::iterator it;
    for (it = OldNodes.begin(); it != OldNodes.end(); ++it) {
        hpcrun_insert_path(root, *it, &tdata->nodeCount);
    }
    return 0;
}

// output the CCT
int newCCT_hpcrun_selection_write(THREADID threadid) {
    FILE* fs = lazy_open_data_file(int(threadid), filename);
    if (!fs)
        return -1;

    ThreadData* tdata = CCTLibGetTLS(threadid);
    uint32_t i;
    NewIPNode* cctlib = tdata->tlsHPCRunCCTRoot;
    vector<NewIPNode*> IPHandle;

    for (i = 0; i < cctlib->childIPNodes.size(); i++) {
        IPHandle.push_back(cctlib->childIPNodes[i]);
    }

    hpcfmt_int8_fwrite(tdata->nodeCount, fs);
    tranverseNewCCT(IPHandle, fs);
    hpcio_fclose(fs);
    return 0;
}

// ************************************************************

} // namespace PinCCTLib
