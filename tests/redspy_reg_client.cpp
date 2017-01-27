// @COPYRIGHT@
// Licensed under MIT license.
// See LICENSE.TXT file in the project root for more information.
// ==============================================================

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
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
#include <inttypes.h>
#include <sys/time.h>
#include "pin.H"
#include "pin_isa.H"
#include "cctlib.H"
using namespace std;
using namespace PinCCTLib;


/* Other footprint_client settings */
#define MAX_REDUNDANT_CONTEXTS_TO_LOG (1000)
#define THREAD_MAX (1024)

#define MAX_WRITE_OP_LENGTH (20)
#define MAX_WRITE_OPS_IN_INS (8)

#define WINDOW_ENABLE   1000000
#define WINDOW_DISABLE  1000
#define WINDOW_CLEAN 10

#define DECODE_DEAD(data) static_cast<ContextHandle_t>(((data)  & 0xffffffffffffffff) >> 32 )
#define DECODE_KILL(data) (static_cast<ContextHandle_t>( (data)  & 0x00000000ffffffff))


#define MAKE_CONTEXT_PAIR(a, b) (((uint64_t)(a) << 32) | ((uint64_t)(b)))

__thread long long NUM_INS = 0;
__thread bool Sample_flag = true;
__thread long long NUM_winds = 0;


struct RedSpyThreadData{
    uint32_t regCtxt[REG_LAST];
    UINT8 regValue[REG_LAST][MAX_WRITE_OP_LENGTH];
    uint64_t numRegWritten;
};

struct RegInfo{
    UINT8 count;
    REG regs[MAX_WRITE_OPS_IN_INS];
};

// key for accessing TLS storage in the threads. initialized once in main()
static  TLS_KEY client_tls_key;

// function to access thread-specific data
inline RedSpyThreadData* ClientGetTLS(const THREADID threadId) {
    RedSpyThreadData* tdata =
    static_cast<RedSpyThreadData*>(PIN_GetThreadData(client_tls_key, threadId));
    return tdata;
}


INT32 Usage2() {
    PIN_ERROR("Pin tool to gather calling context on each load and store.\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

// Main for RedSpy, initialize the tool, register instrumentation functions and call the target program.
static FILE* gTraceFile;

//used to record the time
struct timeval startTime,endTime;


// Initialized the needed data structures before launching the target program
static void ClientInit(int argc, char* argv[]) {
    // Create output file
    char name[MAX_FILE_PATH] = "redspyReg.out.";
    char* envPath = getenv("CCTLIB_CLIENT_OUTPUT_FILE");
    gettimeofday(&startTime,NULL);   
 
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

static unordered_map<uint64_t, uint64_t> RedMap[THREAD_MAX];
static inline void AddToRedTable(uint64_t key,  uint16_t value, THREADID threadId) {
#ifdef MULTI_THREADED
    LOCK_RED_MAP();
#endif
    unordered_map<uint64_t, uint64_t>::iterator it = RedMap[threadId].find(key);
    if ( it  == RedMap[threadId].end()) {
        RedMap[threadId][key] = value;
    } else {
        it->second += value;
    }
#ifdef MULTI_THREADED
    UNLOCK_RED_MAP();
#endif
}

static inline VOID EmptyCtxt(THREADID threadId){

    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    int i;
    for( i = 0; i< REG_LAST; ++i){ 
       tData->regCtxt[i] = 0;
    }
    NUM_winds++;

    if(NUM_winds > WINDOW_CLEAN){
       long count = tData->numRegWritten;
       long delNum = 0;
//printf("size of the map %lu, total reg written %lu\n",count,tData->numRegWritten);
       unordered_map<uint64_t,uint64_t>::iterator it,ittmp;
       for (it = RedMap[threadId].begin(); it != RedMap[threadId].end();) {
//printf("%lu\n",(*it).second);
          if((*it).second * 100.0 < count){
             delNum += (*it).second;
             ittmp = it;
             it++;
             RedMap[threadId].erase(ittmp);
          }else
             it++;
       }
       NUM_winds=0;
       tData->numRegWritten -= delNum;
   }
}

static inline VOID CheckGenValueAfterWrite(uint32_t opaqueHandle, THREADID threadId, void * regs, uint32_t regCount, ...){
    if(Sample_flag){
        NUM_INS++;
        if(NUM_INS > WINDOW_ENABLE){
            Sample_flag = false;
            NUM_INS = 0;
            EmptyCtxt(threadId);
            return;
        }
    }else{
        NUM_INS++;
        if(NUM_INS > WINDOW_DISABLE){
            Sample_flag = true;
            NUM_INS = 0;
        }else
            return;
    }

    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
    struct RegInfo * wRegs = (struct RegInfo *)regs;
    
    va_list ap;
    UINT8 i;
    va_start(ap, regCount);
    
    for (i = 0; i < regCount; i++) {
        REG reg = wRegs->regs[i];
        ADDRINT regV = va_arg(ap, ADDRINT);
        ADDRINT regBefore = *(ADDRINT *)(&tData->regValue[reg][0]);
        
        bool isRedundantWrite = (regBefore == regV);
        
        if(isRedundantWrite && tData->regCtxt[reg] != 0) {
            AddToRedTable(MAKE_CONTEXT_PAIR(tData->regCtxt[reg],curCtxtHandle),1,threadId);
        }
        tData->regCtxt[reg] = curCtxtHandle;
        *(ADDRINT *)(&tData->regValue[reg][0]) = regV;
    }
    tData->numRegWritten += regCount;
}
    
static inline  VOID CheckLargeValueAfterWrite(PIN_REGISTER* regRef, REG reg, uint32_t opaqueHandle, THREADID threadId){

    if(Sample_flag){
        NUM_INS++;
        if(NUM_INS > WINDOW_ENABLE){
            Sample_flag = false;
            NUM_INS = 0;
            EmptyCtxt(threadId);
            return;
        }
    }else{
        NUM_INS++;
        if(NUM_INS > WINDOW_DISABLE){
            Sample_flag = true;
            NUM_INS = 0;
        }else
            return;
    }

    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
    
    //struct RegInfo * wRegs = (struct RegInfo *)regs;
    int i;
    bool isRedundantWrite = true;
    for(i = 0; i < 16; ++i){
        if(tData->regValue[reg][i] != regRef->byte[i])
            isRedundantWrite = false;
        tData->regValue[reg][i] = regRef->qword[i];
    }
    
    if(isRedundantWrite && tData->regCtxt[reg]!=0) {
        AddToRedTable(MAKE_CONTEXT_PAIR(tData->regCtxt[reg],curCtxtHandle),1,threadId);
    }
    tData->regCtxt[reg] = curCtxtHandle;
    tData->numRegWritten += 1;  
    
}


static inline void InstrumentReadValueBeforeAndAfterWriting(INS ins, struct RegInfo * wRegs, uint32_t opaqueHandle){
    
    UINT8 i;
    bool flag = true;
    for(i = 0; i < wRegs->count; ++i){
        if (REG_Size(wRegs->regs[i])>8) {
            flag = false;
        }
    }
    
    if(flag){
        switch (wRegs->count) {
            case 1:
                INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) CheckGenValueAfterWrite,IARG_UINT32,opaqueHandle,IARG_THREAD_ID,IARG_PTR,wRegs,IARG_UINT32,wRegs->count,IARG_REG_VALUE,wRegs->regs[0],IARG_END);
                break;
            case 2:
                INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) CheckGenValueAfterWrite, IARG_UINT32, opaqueHandle, IARG_THREAD_ID,  IARG_PTR, wRegs, IARG_UINT32,wRegs->count, IARG_REG_VALUE, wRegs->regs[0], IARG_REG_VALUE, wRegs->regs[1], IARG_END);
                break;
            case 3:
                INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) CheckGenValueAfterWrite, IARG_UINT32, opaqueHandle, IARG_THREAD_ID,  IARG_PTR, wRegs, IARG_UINT32,wRegs->count, IARG_REG_VALUE, wRegs->regs[0], IARG_REG_VALUE, wRegs->regs[1], IARG_REG_VALUE, wRegs->regs[2], IARG_END);
                break;
            case 4:
                INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) CheckGenValueAfterWrite, IARG_UINT32, opaqueHandle, IARG_THREAD_ID,  IARG_PTR, wRegs, IARG_UINT32,wRegs->count, IARG_REG_VALUE, wRegs->regs[0], IARG_REG_VALUE, wRegs->regs[1], IARG_REG_VALUE, wRegs->regs[2], IARG_REG_VALUE, wRegs->regs[3], IARG_END);
                break;
                
            default:
                assert(0 && "NYI");
                break;
        }
        
    }else{
        if(wRegs->count == 1){
            if(wRegs->regs[0] == REG_ST0)
               return;
            INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) CheckLargeValueAfterWrite, IARG_REG_CONST_REFERENCE,wRegs->regs[0], IARG_UINT32, wRegs->regs[0], IARG_UINT32, opaqueHandle, IARG_THREAD_ID,IARG_END);
        }else
            printf("Writing multiple registers with large size\n");
    }
}

static inline int GetNumWriteRegOperandsInIns(INS ins, UINT32 & whichOp){
    int numWriteOps = 0;
    UINT32 numOperands = INS_OperandCount(ins);
    for(UINT32 i = 0; i < numOperands; i++) {
        if (INS_OperandWritten(ins, i) && INS_OperandIsReg(ins,i)) {
            numWriteOps++;
            whichOp = i;
        }
    }
    return numWriteOps;
}

static inline bool INS_IsIgnorable(INS ins){

    if(INS_IsFarJump(ins))
       return true;
    else if(INS_IsRet(ins))
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
    return false;
}

static VOID InstrumentInsCallback(INS ins, VOID* v, const uint32_t opaqueHandle) {
    if (!INS_HasFallThrough(ins)) return;
    if (INS_IsIgnorable(ins)) return; 

    struct RegInfo * wRegs = new struct RegInfo;
    
    UINT32 numOperands = INS_OperandCount(ins);
    
    int regCount = 0;
    
    for(UINT32 Oper = 0; Oper < numOperands; Oper++) {
        
        if(!INS_OperandWritten(ins, Oper) || !INS_OperandIsReg(ins,Oper))
            continue;
        
        REG curReg = INS_OperandReg(ins,Oper);
        
        if(REG_IsIgnorable(curReg))
            continue;
        
        if (regCount >= MAX_WRITE_OPS_IN_INS) {
            assert(0 && "NYI");
            break;
        }else{
            wRegs->regs[regCount] = curReg;
            regCount++;
            wRegs->count = regCount;
        }
    }
    if(regCount > 0)
        InstrumentReadValueBeforeAndAfterWriting(ins, wRegs, opaqueHandle);
}


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
gettimeofday(&endTime,NULL);
printf("RedSpy-register unrolling:%.2f\n",endTime.tv_sec-startTime.tv_sec + (double)(endTime.tv_usec-startTime.tv_usec)/1000000);

    uint64_t grandTotalRedundantBytes = 0;
    fprintf(gTraceFile, "*************** Dump Data from Thread %d ****************\n", threadId);
    for (unordered_map<uint64_t, uint64_t>::iterator it = RedMap[threadId].begin(); it != RedMap[threadId].end(); ++it) {
        ContextHandle_t dead = DECODE_DEAD((*it).first);
        ContextHandle_t kill = DECODE_KILL((*it).first);

        for(tmpIt = tmpList.begin();tmpIt != tmpList.end(); ++tmpIt){
             bool ct1 = false;
             if(dead == 0 || ((*tmpIt).dead) == 0){
                  if(dead == 0 && ((*tmpIt).dead) == 0)
                       ct1 = true;
             }else{
                  ct1 = IsSameSourceLine(dead,(*tmpIt).dead);
             }
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
    fprintf(gTraceFile, "\n Total redundant times of register writes = %f %%\n", grandTotalRedundantBytes * 100.0 / ClientGetTLS(threadId)->numRegWritten);
    
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
    PIN_UnlockClient();
    // clear redmap now
    RedMap[threadid].clear();
}

static VOID ThreadFiniFunc(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v) {
}

static VOID FiniFunc(INT32 code, VOID *v) {
    // do whatever you want to the full CCT with footpirnt
    gettimeofday(&endTime,NULL);
    printf("RedSpy-register:%.2f\n",endTime.tv_sec-startTime.tv_sec + (double)(endTime.tv_usec-startTime.tv_usec)/1000000);
}


static void InitThreadData(RedSpyThreadData* tdata){
    tdata->numRegWritten = 0;
}

static VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    RedSpyThreadData* tdata = new RedSpyThreadData();
    InitThreadData(tdata);
    //    __sync_fetch_and_add(&gClientNumThreads, 1);
    PIN_SetThreadData(client_tls_key, tdata, threadid);
}


int main(int argc, char* argv[]) {
    // Initialize PIN
    if(PIN_Init(argc, argv))
        return Usage2();
    
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
    
    
    // Register ImageUnload to be called when an image is unloaded
    IMG_AddUnloadFunction(ImageUnload, 0);
    
    // Launch program now
    PIN_StartProgram();
    return 0;
}


