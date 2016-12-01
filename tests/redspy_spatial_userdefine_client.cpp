// * BeginRiceCopyright *****************************************************
//
// Copyright ((c)) 2002-2014, Rice University
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// * Neither the name of Rice University (RICE) nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// This software is provided by RICE and contributors "as is" and any
// express or implied warranties, including, but not limited to, the
// implied warranties of merchantability and fitness for a particular
// purpose are disclaimed. In no event shall RICE or contributors be
// liable for any direct, indirect, incidental, special, exemplary, or
// consequential damages (including, but not limited to, procurement of
// substitute goods or services; loss of use, data, or profits; or
// business interruption) however caused and on any theory of liability,
// whether in contract, strict liability, or tort (including negligence
// or otherwise) arising in any way out of the use of this software, even
// if advised of the possibility of such damage.
//
// ******************************************************* EndRiceCopyright *

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <iostream>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <list>
#include <sys/mman.h>
#include <sstream>
#include <functional>
#include <unordered_set>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include "pin.H"

//enable Data-centric
#define USE_TREE_BASED_FOR_DATA_CENTRIC
#define USE_TREE_WITH_ADDR
#include "cctlib.H"
using namespace std;
using namespace PinCCTLib;

#define THREAD_MAX (1024)

#define GEN_REG_NUM (16)
#define GEN_REG_LEN (8)
#define X87_REG_NUM (8)
#define X87_REG_LEN (10)
#define SIMD_REG_NUM (16)
#define SIMD_REG_LEN (32)

#define SAME_RATE (0.1)
#define SAME_RECORD_LIMIT (0)
#define RED_RATE (0.9)
#define APPROX_RATE (0.01)

#define ARRAY_UPDATE_THRESHOLD(a) (a/4)
#define MAKE_CONTEXT_PAIR(a, b) (((uint64_t)(a) << 32) | ((uint64_t)(b)))

#define ARRAY_ANALYSIS_FN_NAME "Analyze_this_array"


typedef struct valueGroup{
    list<uint32_t> indexes;
}ValueGroup;

typedef struct intraRedRecord{
    double redundancy;
    uint32_t curCtxt;
    list<ValueGroup> group;
    list<uint32_t> spatialRedInd;
}IntraRedRecord;

typedef struct intraRegsRed{
    double genRegRed;
    double x87RegRed;
    double simdRegRed;
}IntraRegsRed;

struct RedSpyThreadData{

    long long numIns;
};

//helper struct used to 

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


INT32 Usage2() {
    PIN_ERROR("Pin tool to gather calling context on each load and store.\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

// Main for RedSpy, initialize the tool, register instrumentation functions and call the target program.
static FILE* gTraceFile;
uint32_t lastStatic;
// Initialized the needed data structures before launching the target program
static void ClientInit(int argc, char* argv[]) {
    // Create output file
    char name[MAX_FILE_PATH] = "redspy_spatial_selected.out.";
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

static unordered_map<string, list<IntraRedRecord>> arrayDataRed[THREAD_MAX];
static unordered_map<uint32_t, list<IntraRegsRed>> regsRed[THREAD_MAX];


VOID inline RecordIntraRegsRedundancy(uint32_t ctxt, IntraRegsRed redPair,THREADID threadId){
    
    unordered_map<uint32_t,list<IntraRegsRed>>::iterator it;
    it = regsRed[threadId].find(ctxt);
    if(it == regsRed[threadId].end()){
        list<IntraRegsRed> newlist;
        newlist.push_back(redPair);
        regsRed[threadId].insert(std::pair<uint32_t,list<IntraRegsRed>>(ctxt,newlist));
    }else{
        it->second.push_back(redPair);
    }
}

VOID inline RecordIntraArrayRedundancy(string name, IntraRedRecord redPair,THREADID threadId){
    
    unordered_map<string,list<IntraRedRecord>>::iterator it;
    it = arrayDataRed[threadId].find(name);
    if(it == arrayDataRed[threadId].end()){
        list<IntraRedRecord> newlist;
        newlist.push_back(redPair);
        arrayDataRed[threadId].insert(std::pair<string,list<IntraRedRecord>>(name,newlist));
    }else{
        it->second.push_back(redPair);
    }
}

static void CheckRegValues(CONTEXT * ctxt,THREADID threadId){
    
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    //ContextHandle_t curCtxtHandle = GetContextHandle(threadId, 0);
    
    //get values for general registers
    UINT8 ** genRegs;
    genRegs = (UINT8 **)malloc(GEN_REG_NUM * sizeof(UINT8 *));
    for (int i = 0; i < GEN_REG_NUM; ++i) {
        genRegs[i] = (UINT8 *)malloc(GEN_REG_LEN * sizeof(UINT8));
    }
    
    PIN_GetContextRegval(ctxt,REG_RAX,genRegs[0]);
    PIN_GetContextRegval(ctxt,REG_RBX,genRegs[1]);
    PIN_GetContextRegval(ctxt,REG_RCX,genRegs[2]);
    PIN_GetContextRegval(ctxt,REG_RDX,genRegs[3]);
    
    PIN_GetContextRegval(ctxt,REG_RBP,genRegs[4]);
    PIN_GetContextRegval(ctxt,REG_RDI,genRegs[5]);
    PIN_GetContextRegval(ctxt,REG_RSI,genRegs[6]);
    PIN_GetContextRegval(ctxt,REG_RSP,genRegs[7]);
    
    PIN_GetContextRegval(ctxt,REG_R8,genRegs[8]);
    PIN_GetContextRegval(ctxt,REG_R9,genRegs[9]);
    PIN_GetContextRegval(ctxt,REG_R10,genRegs[10]);
    PIN_GetContextRegval(ctxt,REG_R11,genRegs[11]);
    PIN_GetContextRegval(ctxt,REG_R12,genRegs[12]);
    PIN_GetContextRegval(ctxt,REG_R13,genRegs[13]);
    PIN_GetContextRegval(ctxt,REG_R14,genRegs[14]);
    PIN_GetContextRegval(ctxt,REG_R15,genRegs[15]);
    
    //get values for X87 registers
    UINT8 ** x87Regs;
    x87Regs = (UINT8 **)malloc(X87_REG_NUM * sizeof(UINT8 *));
    for (int i = 0; i < X87_REG_NUM; ++i) {
        x87Regs[i] = (UINT8 *)malloc(X87_REG_LEN * sizeof(UINT8));
    }
    
    PIN_GetContextRegval(ctxt,REG_ST0,x87Regs[0]);
    PIN_GetContextRegval(ctxt,REG_ST1,x87Regs[1]);
    PIN_GetContextRegval(ctxt,REG_ST2,x87Regs[2]);
    PIN_GetContextRegval(ctxt,REG_ST3,x87Regs[3]);
    PIN_GetContextRegval(ctxt,REG_ST4,x87Regs[4]);
    PIN_GetContextRegval(ctxt,REG_ST5,x87Regs[5]);
    PIN_GetContextRegval(ctxt,REG_ST6,x87Regs[6]);
    PIN_GetContextRegval(ctxt,REG_ST7,x87Regs[7]);
    
    //get values for SIMD registers
    UINT8 ** simdRegs;
    simdRegs = (UINT8 **)malloc(SIMD_REG_NUM * sizeof(UINT8 *));
    for (int i = 0; i < SIMD_REG_NUM; ++i) {
        simdRegs[i] = (UINT8 *)malloc(SIMD_REG_LEN * sizeof(UINT8));
    }
    
    PIN_GetContextRegval(ctxt,REG_YMM0,simdRegs[0]);
    PIN_GetContextRegval(ctxt,REG_YMM1,simdRegs[1]);
    PIN_GetContextRegval(ctxt,REG_YMM2,simdRegs[2]);
    PIN_GetContextRegval(ctxt,REG_YMM3,simdRegs[3]);
    PIN_GetContextRegval(ctxt,REG_YMM4,simdRegs[4]);
    PIN_GetContextRegval(ctxt,REG_YMM5,simdRegs[5]);
    PIN_GetContextRegval(ctxt,REG_YMM6,simdRegs[6]);
    PIN_GetContextRegval(ctxt,REG_YMM7,simdRegs[7]);
    PIN_GetContextRegval(ctxt,REG_YMM8,simdRegs[8]);
    PIN_GetContextRegval(ctxt,REG_YMM9,simdRegs[9]);
    PIN_GetContextRegval(ctxt,REG_YMM10,simdRegs[10]);
    PIN_GetContextRegval(ctxt,REG_YMM11,simdRegs[11]);
    PIN_GetContextRegval(ctxt,REG_YMM12,simdRegs[12]);
    PIN_GetContextRegval(ctxt,REG_YMM13,simdRegs[13]);
    PIN_GetContextRegval(ctxt,REG_YMM14,simdRegs[14]);
    PIN_GetContextRegval(ctxt,REG_YMM15,simdRegs[15]);
    
    int index = 0;
    int i,j;
    
    //check redundancy in general registers
    uint64_t valuesMap[GEN_REG_NUM];
    valuesMap[index++] = *(uint64_t *)(genRegs[0]);
    
    for (int i = 1; i < GEN_REG_NUM; ++i) {
        
        for (j = 0; j < index; ++j) {
            if (*(uint64_t *)(genRegs[i]) == valuesMap[j]) {
                break;
            }
        }
        if (j >= index) {
            valuesMap[index++] = *(uint64_t *)(genRegs[i]);
        }
    }
    
    float genRegRate = (float)index/GEN_REG_NUM;
    
    //check redundancy in x87 registers
    UINT8 ** x87values;
    x87values = (UINT8 **)malloc(X87_REG_NUM * sizeof(UINT8 *));
    for (int i = 0; i < X87_REG_NUM; ++i) {
        x87values[i] = (UINT8 *)malloc(X87_REG_LEN * sizeof(UINT8));
    }
    index = 0;
    memcpy(x87values[index++], x87Regs[0], X87_REG_LEN * sizeof(UINT8));
    for (int i = 1; i < X87_REG_NUM; ++i) {
        
        for (j = 0; j < index; ++j) {
            if (memcmp(x87values[j],x87Regs[i],X87_REG_LEN * sizeof(UINT8))==0) {
                break;
            }
        }
        if (j >= index) {
            memcpy(x87values[index++], x87Regs[i], X87_REG_LEN * sizeof(UINT8));
        }
    }
    float x87RegRate = (float)index/X87_REG_NUM;
    
    //check redundancy in SIMD registers
    UINT8 ** simdValues;
    simdValues = (UINT8 **)malloc(SIMD_REG_NUM * sizeof(UINT8 *));
    for (int i = 0; i < SIMD_REG_NUM; ++i) {
        simdValues[i] = (UINT8 *)malloc(SIMD_REG_LEN * sizeof(UINT8));
    }
    index = 0;
    memcpy(simdValues[index++], simdRegs[0], SIMD_REG_LEN * sizeof(UINT8));
    for (int i = 1; i < 8; ++i) {
        
        for (j = 0; j < index; ++j) {
            if (memcmp(simdValues[j],simdRegs[i],SIMD_REG_LEN * sizeof(UINT8))==0) {
                break;
            }
        }
        if (j >= index) {
            memcpy(simdValues[index++], simdRegs[i], SIMD_REG_LEN * sizeof(UINT8));
        }
    }
    float simdRegRate = (float)index/SIMD_REG_NUM;
    
    if (genRegRate > RED_RATE || x87RegRate > RED_RATE || simdRegRate > RED_RATE) {
        ContextHandle_t curCtxtHandle = GetContextHandle(threadId, 0);
        IntraRegsRed newpair;
        newpair.genRegRed = genRegRate;
        newpair.x87RegRed = x87RegRate;
        newpair.simdRegRed = simdRegRate;
        RecordIntraRegsRedundancy(curCtxtHandle,newpair,threadId);
    }
}


template<typename T, bool isApprox>
struct ArrayAnalysis{
    
    typedef typename unordered_map<T,list<uint32_t>>::iterator MyIterator;
    
    static __attribute__((always_inline)) bool CheckIntraArrayRedundancy(uint64_t begAddr, uint64_t endAddr, uint32_t stride, IntraRedRecord * newPair ){
        
        unordered_map<T,list<uint32_t>> valuesMap;
        MyIterator mapIt;
        list<uint32_t> spatialRedIndex;
        uint64_t address = begAddr;
        uint32_t index = 0;
        T valueLast = 0;
        while(address < endAddr){
            
            T value = *static_cast<T *>((void *)address);
            
            if(isApprox){
                T r = (value - valueLast)/value;
                if (r < APPROX_RATE && r > -APPROX_RATE)
                    spatialRedIndex.push_back(index);
                for(mapIt=valuesMap.begin(); mapIt != valuesMap.end(); ++mapIt){
                    r = (value - mapIt->first)/value;
                    if (r < APPROX_RATE && r > -APPROX_RATE){
                        mapIt->second.push_back(index);
                        break;
                    }
                }
                if(mapIt == valuesMap.end()){
                    list<uint32_t> newlist;
                    newlist.push_back(index);
                    valuesMap.insert(std::pair<T,list<uint32_t>>(value,newlist));
                }
            }else{
                if(value == valueLast)
                    spatialRedIndex.push_back(index);
                mapIt = valuesMap.find(value);
                if(mapIt == valuesMap.end()){
                    list<uint32_t> newlist;
                    newlist.push_back(index);
                    valuesMap.insert(std::pair<T,list<uint32_t>>(value,newlist));
                }else{
                    mapIt->second.push_back(index);
                }
            }
            address += stride;
            index++;
            valueLast = value;
        }
        uint32_t numUniqueValue = valuesMap.size();
        double redRate = (double)(index - numUniqueValue)/index;
        list<ValueGroup> maxList;
        for (mapIt = valuesMap.begin(); mapIt != valuesMap.end(); ++mapIt){
            if(mapIt->second.size() > index*SAME_RATE){
                ValueGroup newGroup;
                newGroup.indexes = mapIt->second;
                maxList.push_back(newGroup);
            }
        }
        if(redRate > RED_RATE || maxList.size() > SAME_RECORD_LIMIT){
            newPair->redundancy = redRate;
            newPair->group = maxList;
            newPair->spatialRedInd = spatialRedIndex;
            return true;
        }
        return false;
    }
};

static VOID InstrumentInsCallback(INS ins, VOID* v, const uint32_t opaqueHandle) {
    ;
}

void new_ARRAY_ANALYSIS_FN_NAME(char * name, void * addr, uint32_t typeSize, uint32_t stride, bool isApprox, THREADID threadId){
    printf("name:%s, addr:%p, type:%d, stride:%d\n",name,addr,typeSize,stride);
    string str(name);
    
    DataHandle_t dataHandle = GetDataObjectHandle(addr,threadId);
    IntraRedRecord newRecord;
    bool hasRedundant = false;
    
    if (isApprox) {
        switch (typeSize) {
            case 4:
                hasRedundant = ArrayAnalysis<float,true>::CheckIntraArrayRedundancy(dataHandle.beg_addr,dataHandle.end_addr,stride,&newRecord);
                break;
            case 8:
                hasRedundant = ArrayAnalysis<double,true>::CheckIntraArrayRedundancy(dataHandle.beg_addr,dataHandle.end_addr,stride,&newRecord);
                break;
            default:
                assert(0 && "approx inappropriate type size, should not reach here!");
                break;
        }
    }else{
    
        switch (typeSize) {
            case 1:
                hasRedundant = ArrayAnalysis<uint8_t,false>::CheckIntraArrayRedundancy(dataHandle.beg_addr,dataHandle.end_addr,stride,&newRecord);
                break;
            case 2:
                hasRedundant = ArrayAnalysis<uint16_t,false>::CheckIntraArrayRedundancy(dataHandle.beg_addr,dataHandle.end_addr,stride,&newRecord);
                break;
            case 4:
                hasRedundant = ArrayAnalysis<uint32_t,false>::CheckIntraArrayRedundancy(dataHandle.beg_addr,dataHandle.end_addr,stride,&newRecord);
                break;
            case 8:
                hasRedundant = ArrayAnalysis<uint64_t,false>::CheckIntraArrayRedundancy(dataHandle.beg_addr,dataHandle.end_addr,stride,&newRecord);
                break;
            default:
                assert(0 && "unknow element size, should not reach here!");
                break;
        }
    }
    if(hasRedundant){
        ContextHandle_t curCtxtHandle = GetContextHandle(threadId, 0);
        newRecord.curCtxt = curCtxtHandle;
        RecordIntraArrayRedundancy( name, newRecord, threadId);
    }
}

VOID Overrides (IMG img, VOID * v) {
    // Master setup
    RTN rtn = RTN_FindByName (img, ARRAY_ANALYSIS_FN_NAME);
    if (RTN_Valid (rtn)) {
        
        RTN_InsertCall (rtn, IPOINT_BEFORE, (AFUNPTR) CheckRegValues, IARG_CONTEXT, IARG_THREAD_ID,IARG_END);
        // Define a function prototype that describes the application routine
        // that will be replaced.
        //
        PROTO proto_master = PROTO_Allocate (PIN_PARG (void), CALLINGSTD_DEFAULT,
                                             ARRAY_ANALYSIS_FN_NAME,PIN_PARG (char *),PIN_PARG (void *),PIN_PARG (uint32_t),PIN_PARG (uint32_t), PIN_PARG (bool),
                                             PIN_PARG_END ());
        
        // Replace the application routine with the replacement function.
        // Additional arguments have been added to the replacement routine.
        //
        RTN_ReplaceSignature (rtn, AFUNPTR (new_ARRAY_ANALYSIS_FN_NAME),
                              IARG_PROTOTYPE, proto_master,
                              IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                              IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                              IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                              IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                              IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                              IARG_THREAD_ID, IARG_END);
        // Free the function prototype.
        PROTO_Free (proto_master);
    }
}


struct RedundacyData {
    ContextHandle_t dead;
    ContextHandle_t kill;
    uint64_t frequency;
};

static inline string ConvertListToString(list<uint32_t> inlist){

    list<uint32_t>::iterator it = inlist.begin();
    uint32_t tmp = (*it);
    string indexList = "[" + to_string(tmp) + ",";
    it++;
    while(it != inlist.end()){
        if(*it == tmp + 1){
            tmp = *it;
        }
        else{
            indexList += to_string(tmp) + "],[" + to_string(*it)+ ",";
            tmp = *it;
        }
        it++;
    }
    indexList += to_string(tmp) + "]";
    return indexList;
}


static inline bool RedundacyCompare(const struct RedundacyData &first, const struct RedundacyData &second) {
    return first.frequency > second.frequency ? true : false;
}

static void PrintRedundancyPairs(THREADID threadId) {

    fprintf(gTraceFile,"\n*************** Intra Array Redundancy of Thread %d ***************\n",threadId);
    unordered_map<string,list<IntraRedRecord>>::iterator itIntra;

    fprintf(gTraceFile,"========== Selected Dataobjecy Redundancy ==========\n");
    for(itIntra = arrayDataRed[threadId].begin(); itIntra != arrayDataRed[threadId].end(); ++itIntra){

        fprintf(gTraceFile,"\nVariable %s: \n",(itIntra->first).c_str());

        list<IntraRedRecord>::iterator listIt;
        for(listIt = itIntra->second.begin(); listIt != itIntra->second.end(); ++listIt){
            
            PrintFullCallingContext((*listIt).curCtxt);
            fprintf(gTraceFile,"\nRed:%.2f, unique value large index group:\n",(*listIt).redundancy);
            list<ValueGroup>::iterator groupIt;
            int num = 0;
            for (groupIt = (*listIt).group.begin(); groupIt != (*listIt).group.end(); ++groupIt) {
                string indexlist = ConvertListToString((*groupIt).indexes);
                fprintf(gTraceFile,"Group %d: %s\n",num, indexlist.c_str());
            }
            string indexlist = ConvertListToString((*listIt).spatialRedInd);
            fprintf(gTraceFile,"redundant spatial indexes:%s\n",indexlist.c_str());

        }
        fprintf(gTraceFile,"\n----------------------------");
    }
    
    fprintf(gTraceFile,"\n*************** Intra Registers Redundancy of Thread %d ***************\n",threadId);
    unordered_map<uint32_t,list<IntraRegsRed>>::iterator itIntraReg;
    
    fprintf(gTraceFile,"========== ==========\n");
    for(itIntraReg = regsRed[threadId].begin(); itIntraReg != regsRed[threadId].end(); ++itIntraReg){
        
        PrintFullCallingContext(itIntraReg->first);
        
        list<IntraRegsRed>::iterator listItReg;
        for(listItReg = itIntraReg->second.begin(); listItReg != itIntraReg->second.end(); ++listItReg){
            
            fprintf(gTraceFile,"\n general registers redundancy: %.2f\n",(*listItReg).genRegRed);
            fprintf(gTraceFile,"\n X87 registers redundancy: %.2f\n",(*listItReg).x87RegRed);
            fprintf(gTraceFile,"\n SIMD registers redundancy: %.2f\n",(*listItReg).simdRegRed);
        }
        fprintf(gTraceFile,"\n----------------------------");
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
    arrayDataRed[threadid].clear();
}

static VOID ThreadFiniFunc(THREADID threadId, const CONTEXT *ctxt, INT32 code, VOID *v) {

}

static VOID FiniFunc(INT32 code, VOID *v) {
    // do whatever you want to the full CCT with footpirnt
}


static void InitThreadData(RedSpyThreadData* tdata){
    
    tdata->numIns = 0;
}

static VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    RedSpyThreadData* tdata = new RedSpyThreadData();
    InitThreadData(tdata);
    //    __sync_fetch_and_add(&gClientNumThreads, 1);
    PIN_SetThreadData(client_tls_key, tdata, threadid);
#ifdef MULTI_THREADED
    PIN_SetThreadData(client_tls_key, tdata, threadid);
#else
    gSingleThreadedTData = tdata;
#endif
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
    PinCCTLibInit(INTERESTING_INS_MEMORY_ACCESS, gTraceFile, InstrumentInsCallback, 0, true);
    
    
    // Obtain  a key for TLS storage.
    client_tls_key = PIN_CreateThreadDataKey(0 /*TODO have a destructir*/);
    // Register ThreadStart to be called when a thread starts.
    PIN_AddThreadStartFunction(ThreadStart, 0);
    
    
    // fini function for post-mortem analysis
    PIN_AddThreadFiniFunction(ThreadFiniFunc, 0);
    PIN_AddFiniFunction(FiniFunc, 0);

    IMG_AddInstrumentFunction(Overrides, 0);
    
    // Register ImageUnload to be called when an image is unloaded
    IMG_AddUnloadFunction(ImageUnload, 0);
    
    // Launch program now
    PIN_StartProgram();
    return 0;
}


