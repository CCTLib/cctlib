#ifndef __CCTLIB_H__
#define __CCTLIB_H__


#include "pin.H"
#include <stdint.h>
#include <stdio.h>

#define MAX_CCT_PRINT_DEPTH (20)
#define MAX_CCT_PATH_DEPTH (100)
#define MAX_FILE_PATH   (200)

namespace PinCCTLib {


    typedef struct DataHandle_t {
        uint8_t objectType;
        union {
            uint32_t pathHandle;
            uint32_t symName;
        };
    } DataHandle_t;

    typedef struct Context {
        string functionName;
        string filePath;
        uint32_t lineNo;
        ADDRINT ip;
    } Context;

    typedef BOOL (* IsInterestingInsFptr)(INS ins);
    typedef VOID (*CCTLibInstrumentInsCallback)(INS ins, VOID* v, uint32_t slot);

    inline BOOL InterestingInsNone(INS ins) {
        return false;
    }

    inline BOOL InterestingInsAll(INS ins) {
        return true;
    }

    inline BOOL InterestingInsMemoryAccess(INS ins) {
        return (INS_MemoryOperandCount(ins) > 0);
    }

#define INTERESTING_INS_ALL (PinCCTLib::InterestingInsAll)
#define INTERESTING_INS_NONE (PinCCTLib::InterestingInsNone)
#define INTERESTING_INS_MEMORY_ACCESS (PinCCTLib::InterestingInsMemoryAccess)

    typedef uint32_t ContextHandle_t;

    DataHandle_t GetDataObjectHandle(VOID* addr, THREADID threadId);
    int PinCCTLibInit(IsInterestingInsFptr isInterestingIns, FILE* logFile, CCTLibInstrumentInsCallback userCallback, VOID* userCallbackArg, BOOL doDataCentric = false);
    ContextHandle_t GetPINCCT32bitCurrentContextWithSlot(THREADID id, uint32_t slot);
    VOID PrintFullCallingContext(ContextHandle_t ctxtHandle);
    VOID GetFullCallingContext(ContextHandle_t ctxtHandle, vector<Context>& contextVec);
    void SerializeMetadata(string directoryForSerializationFiles = "");
    int PinCCTLibInitForReading(FILE* logFile, string serializedFilesDirectory);
    void DottifyAllCCTs();

#ifndef USE_TREE_BASED_FOR_DATA_CENTRIC
#define USE_SHADOW_FOR_DATA_CENTRIC
#endif
}

#endif
