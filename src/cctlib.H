// @COPYRIGHT@
// Licensed under MIT license.
// See LICENSE.TXT file in the project root for more information.
// ==============================================================

#ifndef __CCTLIB_H__
#define __CCTLIB_H__


#include "pin.H"
#include <stdint.h>
#include <stdio.h>

#define MAX_CCT_PRINT_DEPTH (20)
#define MAX_CCT_PATH_DEPTH (100)
#define MAX_FILE_PATH   (200)

namespace PinCCTLib {

    typedef uint32_t ContextHandle_t;

    // Enum representing different data object types
    enum ObjectTypeEnum {STACK_OBJECT, DYNAMIC_OBJECT, STATIC_OBJECT, UNKNOWN_OBJECT};

    // The handle representing a data object
    typedef struct DataHandle_t {
        uint8_t objectType;
        union {
            ContextHandle_t pathHandle;
            uint32_t symName;
        };
#ifdef USE_TREE_BASED_FOR_DATA_CENTRIC
// Milind- I commented this out since it consumes too much space.
// Need to discuss with Xu on how we want to maintain this efficiently
#ifdef USE_TREE_WITH_ADDR
	uint64_t beg_addr;
	uint64_t end_addr;
#endif
#endif
    } DataHandle_t;

    // Data type returned when a client tool queries  GetFullCallingContext
    typedef struct Context {
        string functionName;
        string filePath;
        string disassembly;
        ContextHandle_t ctxtHandle;
        uint32_t lineNo;
        ADDRINT ip;
    } Context;


    // Client callback function to determine if it wants to track a given INS
    typedef BOOL (* IsInterestingInsFptr)(INS ins);

    // Client callback made from CCTLib for each instruction indicated to be tracked by the client.
    typedef VOID (*CCTLibInstrumentInsCallback)(INS ins, VOID* v, const uint32_t slot);

    // Predefined callback for tracking no INS
    inline BOOL InterestingInsNone(INS ins) {
        return false;
    }

    // Predefined callback for tracking all INS
    inline BOOL InterestingInsAll(INS ins) {
        return true;
    }

    // Predefined callback for tracking all memory INS
    inline BOOL InterestingInsMemoryAccess(INS ins) {
        return (INS_MemoryOperandCount(ins) > 0);
    }

#define INTERESTING_INS_ALL (PinCCTLib::InterestingInsAll)
#define INTERESTING_INS_NONE (PinCCTLib::InterestingInsNone)
#define INTERESTING_INS_MEMORY_ACCESS (PinCCTLib::InterestingInsMemoryAccess)

    /*
            Description:
                    CCTLib clients must call this before using CCTLib.
                    Note: For postmortem analysis call PinCCTLibInitForPostmortemAnalysis() instead.
            Arguments:
                    isInterestingIns: a client tool callback that should return boolean true/false if a given INS needs to collect context. Following predefined values are available for client tools: INTERESTING_INS_ALL, INTERESTING_INS_NONE, and INTERESTING_INS_MEMORY_ACCESS.
                    logFile: file pointer where CCTLib will put its output data.
                    userCallback: a client callback that CCTLib calls on each INS for which isInterestingIns is true passing it userCallbackArg value. See one of the examples in tests directory for example usage.
                    doDataCentric: should be set to true if the client wants CCTLib to do data-centric attribution.
    */
    int PinCCTLibInit(IsInterestingInsFptr isInterestingIns, FILE* logFile, CCTLibInstrumentInsCallback userCallback, VOID* userCallbackArg, BOOL doDataCentric = false);

    /*
    int PinCCTLibInitForPostmortemAnalysis(FILE* logFile, string serializedFilesDirectory);
            Description:
                    Reads serialized CCT metadata and rebuilds CCTs for postmortem analysis.
            Arguments:
                    logFile: file pointer where CCTLib will put its output data.
                    serializedFilesDirectory: Path to directory where previously files were serialized.

                    Caution: This should never be called with PinCCTLibInit().
    */
    int PinCCTLibInitForPostmortemAnalysis(FILE* logFile, string serializedFilesDirectory);

    /*
            Description:
                    Client tools call this API when they need the calling context handle (ContextHandle_t).
            Arguments:
                    threadId: Pin's thread id of the asking thread.
                    opaqueHandle: handle passed by CCTLib to the client tool in its userCallback.
    */
    ContextHandle_t GetContextHandle(const THREADID threadId, const uint32_t opaqueHandle);

    /*
            Description:
                    Client tools call this API when they need the handle to a data object (DataHandle_t).
            Arguments:
                    address: effectve address for which the data object is needed.
                    threadId: Pin's thread id of the asking thread.
    */
    DataHandle_t GetDataObjectHandle(VOID* address, const THREADID threadId);
     /*
            Description:
                    Client tools call this API when they need the char string for a symbol from string pool index.
            Arguments:
                    index: a string pool index 
    */
    char * GetStringFromStringPool(const uint32_t index);
    /*
            Description:
                    Prints the full calling context whose handle is ctxtHandle.
    */
    VOID PrintFullCallingContext(const ContextHandle_t ctxtHandle);

    /*
            Description:
                    Returns the full calling context whose handle is ctxtHandle.

            Arguments:
                    ctxtHandle: is the context handle for which the full call path is requested.
                    contextVec: is a vector that will be populated with the full call path.
    */
    VOID GetFullCallingContext(const ContextHandle_t ctxtHandle, vector<Context>& contextVec);

    /*
            Description:
                    Serializes all CCTLib data into files for postmortem analysis.

            Arguments:
                    directoryForSerializationFiles: directory where serialized files are written.
    */
    void SerializeMetadata(string directoryForSerializationFiles = "");

    /*
       Description:
            Dumps all CCTs into DOT files for visualization.
    */
    void DottifyAllCCTs();

#ifdef HAVE_METRIC_PER_IPNODE
    void TraverseCCTBottomUp(const THREADID threadid, void (*opFunc) (const THREADID threadid, ContextHandle_t myHandle, ContextHandle_t parentHandle, void **myMetric, void **parentMetric));
    void** GetIPNodeMetric(const THREADID threadId, const uint32_t opaqueHandle);
#endif

    /*
       Description:
           Given two CCT handles, returns true if the call path from root to leaves, except the leaves themselves are the same.
    */
    bool HaveSameCallerPrefix(ContextHandle_t ctxt1, ContextHandle_t ctxt2);

    bool IsSameSourceLine(ContextHandle_t ctxt1, ContextHandle_t ctxt2);
#ifdef USE_TREE_BASED_FOR_DATA_CENTRIC
//NOP
#elif !defined(USE_SHADOW_FOR_DATA_CENTRIC)
// by default use shadow memory technique
#define USE_SHADOW_FOR_DATA_CENTRIC
#endif

    // write the output into hpcviewer's format
    int init_hpcrun_format(int argc, char *argv[], void (*mergeFunc)(void *des, void *src), uint64_t (*computeMetricVal)(void *metric), bool skip=false);
    int newCCT_hpcrun_write(THREADID threadid);
}

#endif
