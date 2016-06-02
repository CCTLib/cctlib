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

/* Other footprint_client settings */
#define MAX_REDUNDANT_CONTEXTS_TO_LOG (100)
#define THREAD_MAX (1024)


#define MAX_WRITE_OP_LENGTH (512)
#define MAX_WRITE_OPS_IN_INS (8)

#define WINDOW_ENABLE 1000000
#define WINDOW_DISABLE 1000000000

#define SAME_RATE (0.1)
#define SAME_RECORD_LIMIT (0)
#define RED_RATE (0.9)


#define MAKE_CONTEXT_PAIR(a, b) (((uint64_t)(a) << 32) | ((uint64_t)(b)))

__thread long long NUM_INS = 0;
__thread bool Sample_flag = true;

typedef struct dataObjectStatus{
    uint32_t numOfReads; //num of reads
    uint8_t secondWrite;
    uint64_t startAddr;
    uint32_t lastWCtxt;
    uint8_t accessLen;
}DataObjectStatus;

typedef struct intraRedIndexPair{
    double redundancy;
    uint32_t curCtxt;
    list<uint32_t> indexes;
    list<uint32_t> spatialRedInd;
}IntraRedIndexPair;

struct RedSpyThreadData{
    unordered_map<uint32_t,DataObjectStatus> dynamicDataObjects;
    unordered_map<uint32_t,DataObjectStatus> staticDataObjects;
};

//helper struct used to 

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
uint32_t lastStatic;
// Initialized the needed data structures before launching the target program
static void ClientInit(int argc, char* argv[]) {
    // Create output file
    char name[MAX_FILE_PATH] = "redspyIntraArray.out.";
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

static unordered_map<uint64_t, list<IntraRedIndexPair>> dyIntraDataRed[THREAD_MAX];
static unordered_map<uint64_t, list<IntraRedIndexPair>> stIntraDataRed[THREAD_MAX];

int inline FindRedPair(list<IntraRedIndexPair> redlist,IntraRedIndexPair redpair){
    list<IntraRedIndexPair>::iterator it;
    for(it = redlist.begin();it != redlist.end(); ++it){
        if((*it).redundancy == redpair.redundancy && (*it).curCtxt == redpair.curCtxt)
            return 1;
    }
    return 0;
}

static inline VOID EmptyCtxt(THREADID threadId){
    
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    unordered_map<uint32_t,DataObjectStatus>::iterator it;
    
    for( it = tData->dynamicDataObjects.begin(); it != tData->dynamicDataObjects.end(); ++it){
        it->second.numOfReads = 0;
    }
    for( it = tData->staticDataObjects.begin(); it != tData->staticDataObjects.end(); ++it){
        it->second.numOfReads = 0;
    }
}

//type:0 means dynamic data object while 1 means static
VOID inline RecordIntraArrayRedundancy(uint32_t dataObj,uint32_t lastW, IntraRedIndexPair redPair,THREADID threadId,uint8_t type){
    uint64_t data = (uint64_t)dataObj;
    uint64_t context = (uint64_t)lastW;
    uint64_t key = (data << 32) | context;
  
    if(type == 0){
        unordered_map<uint64_t,list<IntraRedIndexPair>>::iterator it;
        it = dyIntraDataRed[threadId].find(key);
        if(it == dyIntraDataRed[threadId].end()){
            list<IntraRedIndexPair> newlist;
            newlist.push_back(redPair);
            dyIntraDataRed[threadId].insert(std::pair<uint64_t,list<IntraRedIndexPair>>(key,newlist));
        }else{
            if(!FindRedPair(it->second,redPair))
                it->second.push_back(redPair);
        }
    }else{
        unordered_map<uint64_t,list<IntraRedIndexPair>>::iterator it;
        it = stIntraDataRed[threadId].find(key);
        if(it == stIntraDataRed[threadId].end()){
            list<IntraRedIndexPair> newlist;
            newlist.push_back(redPair);
            stIntraDataRed[threadId].insert(std::pair<uint64_t,list<IntraRedIndexPair>>(key,newlist));
        }else{
            if(!FindRedPair(it->second,redPair))
                it->second.push_back(redPair);
        }
    }
}

/* update the reading access pattern */
VOID UpdateReadAccess(void *addr, THREADID threadId, const uint32_t opHandle){
        /////////////////////////////////////////
    
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
    
        if((uint64_t)addr & 0x7f0000000000)
            return;
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
 
        DataHandle_t dataHandle = GetDataObjectHandle(addr,threadId);
        if(dataHandle.objectType == DYNAMIC_OBJECT){
            unordered_map<uint32_t,DataObjectStatus>::iterator it;
            it = tData->dynamicDataObjects.find(dataHandle.pathHandle);
            if(it != tData->dynamicDataObjects.end()){
                it->second.numOfReads += 1;
            }
        }else if(dataHandle.objectType == STATIC_OBJECT){
            unordered_map<uint32_t,DataObjectStatus>::iterator it;
            it = tData->staticDataObjects.find(dataHandle.symName);
            if(it != tData->staticDataObjects.end()){
                it->second.numOfReads += 1;
            }
        }
}

inline VOID CheckAndRecordIntraArrayRedundancy(uint32_t nameORpath, uint32_t lastWctxt, uint32_t curCtxt, uint16_t accessLen, uint64_t begaddr, uint64_t endaddr,THREADID threadId, uint8_t type ){
        uint64_t address;
        uint32_t index;
        if(accessLen == 1){
            unordered_map<uint8_t,list<uint32_t>> valuesMap1;
            unordered_map<uint8_t,list<uint32_t>>::iterator it1;
            list<uint32_t> spatialRedIndex;
            address = begaddr;
            index = 0;
            uint8_t valueLast = 0;
            while(address < endaddr){
            
                uint8_t value1 = *static_cast<uint8_t *>((void *)address);
                if(value1 == valueLast)
                    spatialRedIndex.push_back(index);
                it1 = valuesMap1.find(value1);
                if(it1 == valuesMap1.end()){
                    list<uint32_t> newlist;
                    newlist.push_back(index);
                    valuesMap1.insert(std::pair<uint8_t,list<uint32_t>>(value1,newlist));
                }else{
                    it1->second.push_back(index);
                }
                address += 1;
                index++;
                valueLast = value1;
            }
            uint32_t numUniqueValue = valuesMap1.size();
            double redRate = (double)(index - numUniqueValue)/index;
            list<uint32_t> maxList;
            for (it1 = valuesMap1.begin(); it1 != valuesMap1.end(); ++it1){
                if(it1->second.size() > index*SAME_RATE){
                    maxList.push_back(*(it1->second.begin()));
                }
            }
            if(redRate > RED_RATE || maxList.size() > SAME_RECORD_LIMIT){
                IntraRedIndexPair newpair;
                newpair.redundancy = redRate;
                newpair.curCtxt = curCtxt;
                newpair.indexes = maxList; 
                newpair.spatialRedInd = spatialRedIndex;                         
                RecordIntraArrayRedundancy(nameORpath, lastWctxt, newpair,threadId,type);
            }
        }else if(accessLen == 2){
            unordered_map<uint16_t,list<uint32_t>> valuesMap1;
            unordered_map<uint16_t,list<uint32_t>>::iterator it1;
            list<uint32_t> spatialRedIndex;
            address = begaddr;
            index = 0;
            uint16_t valueLast = 0;
            while(address < endaddr){
            
                uint16_t value1 = *static_cast<uint16_t *>((void *)address);
                if(value1 == valueLast)
                   spatialRedIndex.push_back(index);
                it1 = valuesMap1.find(value1);
                if(it1 == valuesMap1.end()){
                    list<uint32_t> newlist;
                    newlist.push_back(index);
                    valuesMap1.insert(std::pair<uint16_t,list<uint32_t>>(value1,newlist));
                }else{
                    it1->second.push_back(index);
                }
                address += 2;
                index++;
                valueLast = value1;
            }
            uint32_t numUniqueValue = valuesMap1.size();
            double redRate = (double)(index - numUniqueValue)/index;
            list<uint32_t> maxList;
            for (it1 = valuesMap1.begin(); it1 != valuesMap1.end(); ++it1){
                if(it1->second.size() > index*SAME_RATE){
                    maxList.push_back(*(it1->second.begin()));
                }
            }
            if(redRate > RED_RATE || maxList.size() > SAME_RECORD_LIMIT){
                IntraRedIndexPair newpair;
                newpair.redundancy = redRate;
                newpair.curCtxt = curCtxt;
                newpair.indexes = maxList;                            
                newpair.spatialRedInd = spatialRedIndex;
                RecordIntraArrayRedundancy(nameORpath, lastWctxt, newpair,threadId,type);
            }
        }else if(accessLen == 4){
            unordered_map<uint32_t,list<uint32_t>> valuesMap1;
            unordered_map<uint32_t,list<uint32_t>>::iterator it1;
            list<uint32_t> spatialRedIndex;
            address = begaddr;
            index = 0;
            uint32_t valueLast = 0;
            while(address < endaddr){
            
                 uint32_t value1 = *static_cast<uint32_t *>((void *)address);
                 if(value1 == valueLast)
                    spatialRedIndex.push_back(index);
                 it1 = valuesMap1.find(value1);
                 if(it1 == valuesMap1.end()){
                    list<uint32_t> newlist;
                    newlist.push_back(index);
                    valuesMap1.insert(std::pair<uint32_t,list<uint32_t>>(value1,newlist));
                 }else{
                    it1->second.push_back(index);
                 }
                 address += 4;
                 index++;
                 valueLast = value1;
            }
            uint32_t numUniqueValue = valuesMap1.size();
            double redRate = (double)(index - numUniqueValue)/index;
            list<uint32_t> maxList;
            for (it1 = valuesMap1.begin(); it1 != valuesMap1.end(); ++it1){
                if(it1->second.size() > index*SAME_RATE){
                    maxList.push_back(*(it1->second.begin()));
                }
            }
            if(redRate > RED_RATE || maxList.size() > SAME_RECORD_LIMIT){
                IntraRedIndexPair newpair;
                newpair.redundancy = redRate;
                newpair.curCtxt = curCtxt;
                newpair.indexes = maxList; 
                newpair.spatialRedInd = spatialRedIndex;                           
                RecordIntraArrayRedundancy(nameORpath, lastWctxt, newpair,threadId,type);
            }   
        }else if(accessLen == 8){
            unordered_map<uint64_t,list<uint32_t>> valuesMap1;
            unordered_map<uint64_t,list<uint32_t>>::iterator it1;
            list<uint32_t> spatialRedIndex;
            address = begaddr;
            index = 0;
            uint64_t valueLast = 0;
            while(address < endaddr){
            
                uint64_t value1 = *static_cast<uint64_t *>((void *)address);
                if(valueLast == value1)
                   spatialRedIndex.push_back(index);
                it1 = valuesMap1.find(value1);
                if(it1 == valuesMap1.end()){
                    list<uint32_t> newlist;
                    newlist.push_back(index);
                    valuesMap1.insert(std::pair<uint64_t,list<uint32_t>>(value1,newlist));
                }else{
                    it1->second.push_back(index);
                }
                address += 8;
                index++;
                valueLast = value1;
            }
            uint32_t numUniqueValue = valuesMap1.size();
            double redRate = (double)(index - numUniqueValue)/index;
            list<uint32_t> maxList;
            for (it1 = valuesMap1.begin(); it1 != valuesMap1.end(); ++it1){
                if(it1->second.size() > index*SAME_RATE){
                    maxList.push_back(*(it1->second.begin()));
                }
            }
            if(redRate > RED_RATE || maxList.size() > SAME_RECORD_LIMIT){
                IntraRedIndexPair newpair;
                newpair.redundancy = redRate;
                newpair.curCtxt = curCtxt;
                newpair.indexes = maxList;                            
                newpair.spatialRedInd = spatialRedIndex;
                RecordIntraArrayRedundancy(nameORpath, lastWctxt, newpair,threadId,type);
            }
        }else{
            ;//printf("\nHaven't thought about how to handle this case\n"); 
        }
}

//check whether there are same elements inside the data objects
VOID CheckIntraArrayElements(void *addr, uint16_t AccessLen, THREADID threadId, const uint32_t opHandle){

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
    
    if((uint64_t)addr & 0x7f0000000000)
        return;

    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    DataHandle_t dataHandle = GetDataObjectHandle(addr,threadId);
    uint32_t curCtxt = GetContextHandle(threadId, opHandle);

    if(dataHandle.objectType == DYNAMIC_OBJECT){
        if((dataHandle.end_addr-dataHandle.beg_addr)/AccessLen <= 1)
            return;
        unordered_map<uint32_t,DataObjectStatus>::iterator it;
        it = tData->dynamicDataObjects.find(dataHandle.pathHandle);
        if(it != tData->dynamicDataObjects.end()){
            uint32_t arraySize = (dataHandle.end_addr - dataHandle.beg_addr)/AccessLen;
            if(it->second.numOfReads > arraySize/4){
                CheckAndRecordIntraArrayRedundancy(dataHandle.pathHandle, it->second.lastWCtxt, curCtxt, AccessLen, dataHandle.beg_addr, dataHandle.end_addr, threadId, 0);
            }
            if(it->second.numOfReads != 0)
                it->second.secondWrite+=1;
            it->second.numOfReads = 0;
            it->second.lastWCtxt = curCtxt;
        }else{
            DataObjectStatus newStatus;
            newStatus.numOfReads = 0;
            newStatus.secondWrite = 0;
            newStatus.startAddr = dataHandle.beg_addr;
            newStatus.accessLen = AccessLen;
            newStatus.lastWCtxt = curCtxt;
            tData->dynamicDataObjects.insert(std::pair<uint32_t,DataObjectStatus>(dataHandle.pathHandle,newStatus)); 
        }
    }else if(dataHandle.objectType == STATIC_OBJECT){
        if((dataHandle.end_addr-dataHandle.beg_addr)/AccessLen <= 1)
            return;      
        unordered_map<uint32_t,DataObjectStatus>::iterator it;
        it = tData->staticDataObjects.find(dataHandle.symName);
        if(it != tData->staticDataObjects.end()){
            uint32_t arraySize = (dataHandle.end_addr - dataHandle.beg_addr)/AccessLen; 
            if(it->second.numOfReads > arraySize/4){
                CheckAndRecordIntraArrayRedundancy(dataHandle.symName, it->second.lastWCtxt, curCtxt, AccessLen, dataHandle.beg_addr, dataHandle.end_addr, threadId, 1);
            }
            if(it->second.numOfReads != 0)
                it->second.secondWrite+=1;
            it->second.numOfReads = 0;
            it->second.lastWCtxt = curCtxt;
        }else{
            DataObjectStatus newStatus;
            newStatus.numOfReads = 0;
            newStatus.secondWrite = 0;
            newStatus.startAddr = dataHandle.beg_addr;
            newStatus.accessLen = AccessLen;
            newStatus.lastWCtxt = curCtxt;
            tData->staticDataObjects.insert(std::pair<uint32_t,DataObjectStatus>(dataHandle.symName,newStatus)); 
        }
    }
}

static inline int GetNumWriteOperandsInIns(INS ins, UINT32 & whichOp){
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

static VOID InstrumentInsCallback(INS ins, VOID* v, const uint32_t opaqueHandle) {
    if (!INS_IsMemoryRead(ins) && !INS_IsMemoryWrite(ins)) return;
   // if (INS_IsStackRead(ins) || INS_IsStackWrite(ins)) return;
    if (INS_IsBranchOrCall(ins) || INS_IsRet(ins)) return;
    
    UINT32 memOperands = INS_MemoryOperandCount(ins);
   
    // Special case, if we have only one write operand
    UINT32 whichOp = 0;
    if(GetNumWriteOperandsInIns(ins, whichOp) == 1){
        // Read the value at location before and after the instruction
        for(UINT32 memop = 0; memop < memOperands; memop++){
           if(INS_MemoryOperandIsRead(ins,memop) && !INS_MemoryOperandIsWritten(ins,memop)){
               INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) UpdateReadAccess, IARG_MEMORYOP_EA, memop, IARG_THREAD_ID, IARG_UINT32,opaqueHandle, IARG_END);    
           }else if(INS_MemoryOperandIsWritten(ins,memop)){
               UINT32 refSize = INS_MemoryOperandSize(ins, memop);
               INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) CheckIntraArrayElements, IARG_MEMORYOP_EA, memop, IARG_UINT32, refSize, IARG_THREAD_ID, IARG_UINT32, opaqueHandle, IARG_END);
           }
        }
        return;
    }
    
    for(UINT32 memOp = 0; memOp < memOperands; memOp++) {
        if(INS_MemoryOperandIsRead(ins,memOp) && !INS_MemoryOperandIsWritten(ins,memOp)){
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) UpdateReadAccess, IARG_MEMORYOP_EA, memOp, IARG_THREAD_ID, IARG_UINT32,opaqueHandle, IARG_END);    
        }       
 
        if(!INS_MemoryOperandIsWritten(ins, memOp))
            continue;
        
        UINT32 refSize = INS_MemoryOperandSize(ins, memOp);
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) CheckIntraArrayElements, IARG_MEMORYOP_EA, memOp, IARG_UINT32, refSize, IARG_THREAD_ID, IARG_UINT32, opaqueHandle, IARG_END);
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
    string indexlist = "[" + to_string(tmp) + ",";
    it++;
    while(it != inlist.end()){
        if(*it == tmp + 1){
            tmp = *it;
        }
        else{
            indexlist += to_string(tmp) + "],[" + to_string(*it)+ ",";
            tmp = *it;
        }
        it++;
    }
    indexlist += to_string(tmp) + "]";
    return indexlist;
}


static inline bool RedundacyCompare(const struct RedundacyData &first, const struct RedundacyData &second) {
    return first.frequency > second.frequency ? true : false;
}

static void PrintRedundancyPairs(THREADID threadId) {
    vector<RedundacyData> tmpList;
    vector<RedundacyData>::iterator tmpIt;

    uint64_t grandTotalRedundantBytes = 0;
    fprintf(gTraceFile,"\n*************** Intra Array Redundancy of Thread %d ***************\n",threadId);
    unordered_map<uint64_t,list<IntraRedIndexPair>>::iterator itIntra;
    uint8_t account = 0;
    fprintf(gTraceFile,"========== Static Dataobjecy Redundancy ==========\n");
    for(itIntra = stIntraDataRed[threadId].begin(); itIntra != stIntraDataRed[threadId].end(); ++itIntra){
        uint64_t keyhash = itIntra->first;
        uint32_t dataObj = keyhash >> 32;
        uint32_t contxt = keyhash & 0xffffffff;
        char *symName = GetStringFromStringPool(dataObj);
        fprintf(gTraceFile,"\nVariable %s at \n",symName);
        PrintFullCallingContext(contxt);
        list<IntraRedIndexPair>::iterator listit,listit2;
        for(listit = itIntra->second.begin(); listit != itIntra->second.end(); ++listit){
            for(listit2 = itIntra->second.begin();listit2 != listit;++listit2){
               if(IsSameSourceLine((*listit).curCtxt,(*listit2).curCtxt))
                  break;
            }
            if(listit2 == listit){
               fprintf(gTraceFile,"\nRed:%.2f, unique Indexes:",(*listit).redundancy);
               string indexlist = ConvertListToString((*listit).indexes);
               fprintf(gTraceFile,"%s\n",indexlist.c_str());
               indexlist = ConvertListToString((*listit).spatialRedInd);
               fprintf(gTraceFile,"redundant spatial indexes:%s\n",indexlist.c_str());
               PrintFullCallingContext((*listit).curCtxt);
            }
        }
        fprintf(gTraceFile,"\n----------------------------");
        account++;
        if(account > MAX_REDUNDANT_CONTEXTS_TO_LOG)
            break;
    }
    account = 0;
    fprintf(gTraceFile,"########## Dynamic Dataobjecy Redundancy ##########\n");
    for(itIntra = dyIntraDataRed[threadId].begin(); itIntra != dyIntraDataRed[threadId].end(); ++itIntra){
        uint64_t keyhash = itIntra->first;
        uint32_t dataObj = keyhash >> 32;
        uint32_t contxt = keyhash & 0xffffffff;        
        fprintf(gTraceFile,"\ndynamic malloc:\n");
        PrintFullCallingContext(dataObj);
        fprintf(gTraceFile,"\n ~~ at ~~:\n");
        PrintFullCallingContext(contxt);
        list<IntraRedIndexPair>::iterator listit,listit2;
        
        for(listit = itIntra->second.begin(); listit != itIntra->second.end(); ++listit){
            for(listit2 = itIntra->second.begin();listit2 != listit;++listit2){
               if(IsSameSourceLine((*listit).curCtxt,(*listit2).curCtxt))
                  break;
            }
            if(listit2 == listit){
               fprintf(gTraceFile,"\nRed:%.2f, unique Indexes:",(*listit).redundancy);
               string indexlist = ConvertListToString((*listit).indexes);
               fprintf(gTraceFile,"%s\n",indexlist.c_str());
               indexlist = ConvertListToString((*listit).spatialRedInd);
               fprintf(gTraceFile,"redundant spatial indexes:%s\n",indexlist.c_str());               
               PrintFullCallingContext((*listit).curCtxt);
            }
        }
        fprintf(gTraceFile,"\n----------------------------");
        account++;
        if(account > MAX_REDUNDANT_CONTEXTS_TO_LOG)
            break;
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
    dyIntraDataRed[threadid].clear();
    stIntraDataRed[threadid].clear();
}

static VOID ThreadFiniFunc(THREADID threadId, const CONTEXT *ctxt, INT32 code, VOID *v) {

    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    unordered_map<uint32_t,DataObjectStatus>::iterator it;
    for( it = tData->staticDataObjects.begin(); it != tData->staticDataObjects.end();++it){
        if(it->second.secondWrite == 0){
            DataHandle_t dataHandle = GetDataObjectHandle((void*)(it->second.startAddr),threadId); 
            CheckAndRecordIntraArrayRedundancy(it->first, it->second.lastWCtxt, it->second.lastWCtxt, it->second.accessLen, dataHandle.beg_addr, dataHandle.end_addr, threadId, 1);           
        }
    }
    for( it = tData->dynamicDataObjects.begin(); it != tData->dynamicDataObjects.end();++it){
        if(it->second.secondWrite == 0){
            DataHandle_t dataHandle = GetDataObjectHandle((void*)(it->second.startAddr),threadId); 
            if((dataHandle.end_addr - dataHandle.beg_addr)/it->second.accessLen <= 1)
               continue;
            CheckAndRecordIntraArrayRedundancy(it->first, it->second.lastWCtxt, it->second.lastWCtxt, it->second.accessLen, dataHandle.beg_addr, dataHandle.end_addr, threadId, 0);           
        }
    }

}

static VOID FiniFunc(INT32 code, VOID *v) {
    // do whatever you want to the full CCT with footpirnt
}


static void InitThreadData(RedSpyThreadData* tdata){
    ;
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
    PinCCTLibInit(INTERESTING_INS_MEMORY_ACCESS, gTraceFile, InstrumentInsCallback, 0, true);
    
    
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


