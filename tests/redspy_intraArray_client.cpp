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

#include "cctlib.H"
using namespace std;
using namespace PinCCTLib;

/* infrastructure for shadow memory */
/* MACROs */
// 64KB shadow pages
#define PAGE_OFFSET_BITS (16LL)
#define PAGE_OFFSET(addr) ( addr & 0xFFFF)
#define PAGE_OFFSET_MASK ( 0xFFFF)

#define PAGE_SIZE (1 << PAGE_OFFSET_BITS)

// 2 level page table
#define PTR_SIZE (sizeof(struct Status *))
#define LEVEL_1_PAGE_TABLE_BITS  (20)
#define LEVEL_1_PAGE_TABLE_ENTRIES  (1 << LEVEL_1_PAGE_TABLE_BITS )
#define LEVEL_1_PAGE_TABLE_SIZE  (LEVEL_1_PAGE_TABLE_ENTRIES * PTR_SIZE )

#define LEVEL_2_PAGE_TABLE_BITS  (12)
#define LEVEL_2_PAGE_TABLE_ENTRIES  (1 << LEVEL_2_PAGE_TABLE_BITS )
#define LEVEL_2_PAGE_TABLE_SIZE  (LEVEL_2_PAGE_TABLE_ENTRIES * PTR_SIZE )

#define LEVEL_1_PAGE_TABLE_SLOT(addr) (((addr) >> (LEVEL_2_PAGE_TABLE_BITS + PAGE_OFFSET_BITS)) & 0xfffff)
#define LEVEL_2_PAGE_TABLE_SLOT(addr) (((addr) >> (PAGE_OFFSET_BITS)) & 0xFFF)


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




#define DECODE_DEAD(data) static_cast<ContextHandle_t>(((data)  & 0xffffffffffffffff) >> 32 )
#define DECODE_KILL(data) (static_cast<ContextHandle_t>( (data)  & 0x00000000ffffffff))


#define MAKE_CONTEXT_PAIR(a, b) (((uint64_t)(a) << 32) | ((uint64_t)(b)))

struct AddrValPair{
    void * address;
    uint8_t value[MAX_WRITE_OP_LENGTH];
};

typedef struct dataObjectStatus{
    uint16_t accessLen;
    uint8_t lastOperation; //1 means write,0 means read
}DataObjectStatus;

typedef struct intraRedIndexPair{
    double redundancy;
    list<uint32_t> indexes;
}IntraRedIndexPair;

struct RedSpyThreadData{
    AddrValPair buffer[MAX_WRITE_OPS_IN_INS];
    unordered_map<uint32_t,DataObjectStatus> dynamicDataObjects;
    unordered_map<uint32_t,DataObjectStatus> staticDataObjects;
    uint64_t bytesWritten;
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


template<int start, int end, int incr>
struct UnrolledLoop{
    static inline void Body(function<void (const int)> func){
        func(start); // Real loop body
        UnrolledLoop<start+incr, end, incr>:: Body(func);   // unroll next iteration
    }
};

template<int end,  int incr>
struct UnrolledLoop<end , end , incr>{
    static inline void Body(function<void (const int)> func){
        // empty body
    }
};

template<int start, int end, int incr>
struct UnrolledConjunction{
    static inline bool Body(function<bool (const int)> func){
        return func(start) && UnrolledConjunction<start+incr, end, incr>:: Body(func);   // unroll next iteration
    }
};

template<int end,  int incr>
struct UnrolledConjunction<end , end , incr>{
    static inline bool Body(function<void (const int)> func){
        return true;
    }
};

INT32 Usage2() {
    PIN_ERROR("Pin tool to gather calling context on each load and store.\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

// Main for RedSpy, initialize the tool, register instrumentation functions and call the target program.
static FILE* gTraceFile;
static uint8_t ** gL1PageTable[LEVEL_1_PAGE_TABLE_SIZE];

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


/* helper functions for shadow memory */
static uint8_t* GetOrCreateShadowBaseAddress(uint64_t address) {
    uint8_t *shadowPage;
    uint8_t ***l1Ptr = &gL1PageTable[LEVEL_1_PAGE_TABLE_SLOT(address)];
    if(*l1Ptr == 0) {
        *l1Ptr = (uint8_t **) mmap(0, LEVEL_2_PAGE_TABLE_SIZE, PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] =  (uint8_t *) mmap(0, PAGE_SIZE * (sizeof(uint64_t)), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    } else if((shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)]) == 0 ){
        shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] =  (uint8_t *) mmap(0, PAGE_SIZE * (sizeof(uint64_t)), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    }
    return shadowPage;
}



static const uint64_t READ_ACCESS_STATES [] = {/*0 byte */0, /*1 byte */ ONE_BYTE_READ_ACTION, /*2 byte */ TWO_BYTE_READ_ACTION, /*3 byte */ 0, /*4 byte */ FOUR_BYTE_READ_ACTION, /*5 byte */0, /*6 byte */0, /*7 byte */0, /*8 byte */ EIGHT_BYTE_READ_ACTION};
static const uint64_t WRITE_ACCESS_STATES [] = {/*0 byte */0, /*1 byte */ ONE_BYTE_WRITE_ACTION, /*2 byte */ TWO_BYTE_WRITE_ACTION, /*3 byte */ 0, /*4 byte */ FOUR_BYTE_WRITE_ACTION, /*5 byte */0, /*6 byte */0, /*7 byte */0, /*8 byte */ EIGHT_BYTE_WRITE_ACTION};
static const uint8_t OVERFLOW_CHECK [] = {/*0 byte */0, /*1 byte */ 0, /*2 byte */ 0, /*3 byte */ 1, /*4 byte */ 2, /*5 byte */3, /*6 byte */4, /*7 byte */5, /*8 byte */ 6};

static unordered_map<uint64_t, uint64_t> RedMap[THREAD_MAX];
static inline void AddToRedTable(uint64_t key, int index,  uint16_t value, THREADID threadId) {
#ifdef MULTI_THREADED
    LOCK_RED_MAP();
#endif
    uint64_t ind;
    uint64_t val = (uint64_t)value;
    if(index == -1)
        ind = 0x00000000ffffffff;
    else
        ind = (uint64_t)index;
    uint64_t result = (ind << 32) | val;
    unordered_map<uint64_t, uint64_t>::iterator it = RedMap[threadId].find(key);
    if ( it  == RedMap[threadId].end()) {
        RedMap[threadId][key] = result;
    } else {
        it->second += value;
    }
#ifdef MULTI_THREADED
    UNLOCK_RED_MAP();
#endif
}

static unordered_map<uint64_t, list<IntraRedIndexPair>> dyIntraDataRed[THREAD_MAX];
static unordered_map<uint64_t, list<IntraRedIndexPair>> stIntraDataRed[THREAD_MAX];

int inline FindRedPair(list<IntraRedIndexPair> redlist,IntraRedIndexPair redpair){
    list<IntraRedIndexPair>::iterator it;
    for(it = redlist.begin();it != redlist.end(); ++it){
        if((*it).redundancy != redpair.redundancy)
            continue;
        list<uint32_t>::iterator indit, indit2;
        indit2 = redpair.indexes.begin();
        for(indit = (*it).indexes.begin(); indit != (*it).indexes.end() && indit2 != redpair.indexes.end(); ++indit,++indit2){
            if((*indit) != (*indit2))
                break;
        }
        if(indit == (*it).indexes.end() && indit2 == redpair.indexes.end())
            return 1;
    }
    return 0;
}

//type:0 means dynamic data object while 1 means static
VOID inline RecordIntraArrayRedundancy(uint32_t dataObj,uint32_t cnxt,IntraRedIndexPair redPair,THREADID threadId,uint8_t type){
    uint64_t data = (uint64_t)dataObj;
    uint64_t context = (uint64_t)cnxt;
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

//check whether there are same elements inside the data objects
VOID CheckIntraArrayElements(void *addr,THREADID threadId, const uint32_t opHandle){
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    DataHandle_t dataHandle = GetDataObjectHandle(addr,threadId);
    uint32_t curCtxt = GetContextHandle(threadId, opHandle);

    if((uint64_t)addr & 0x7f0000000000)
        return;
                           
    if(dataHandle.objectType == DYNAMIC_OBJECT){
        unordered_map<uint32_t,DataObjectStatus>::iterator it;
        uint64_t address;
        uint32_t index,max;
        double redundancy;
        it = tData->dynamicDataObjects.find(dataHandle.pathHandle);
        if(it != tData->dynamicDataObjects.end()){
            if(it->second.lastOperation != 0){
//check the same elements in this dataObject
                if(it->second.accessLen == 1){
                            unordered_map<uint8_t,list<uint32_t>> valuesMap1;
                            unordered_map<uint8_t,list<uint32_t>>::iterator it1;
                            address = dataHandle.beg_addr;
                            index = 0;
                            while(address < dataHandle.end_addr){
            
                                uint8_t value1 = *static_cast<uint8_t *>((void *)address);
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
                            }
                            max = 1;
                            list<uint32_t> maxList;
                            for (it1 = valuesMap1.begin(); it1 != valuesMap1.end(); ++it1){
                                if(max < it1->second.size()){
                                    max = it1->second.size();
                                    maxList = it1->second;
                                }
                            }
                            redundancy = (double)max/(index+1);
                            if(redundancy > 0.5){
                                IntraRedIndexPair newpair;
                                newpair.redundancy = redundancy;
                                newpair.indexes = maxList;                            
                                RecordIntraArrayRedundancy(dataHandle.pathHandle,curCtxt, newpair,threadId,0);
                            }
                }else if(it->second.accessLen == 2){
                            unordered_map<uint16_t,list<uint32_t>> valuesMap1;
                            unordered_map<uint16_t,list<uint32_t>>::iterator it1;
                            address = dataHandle.beg_addr;
                            index = 0;
                            while(address < dataHandle.end_addr){
            
                                uint16_t value1 = *static_cast<uint16_t *>((void *)address);
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
                            }
                            max = 1;
                            list<uint32_t> maxList;
                            for (it1 = valuesMap1.begin(); it1 != valuesMap1.end(); ++it1){
                                if(max < it1->second.size()){
                                    max = it1->second.size();
                                    maxList = it1->second;
                                }
                            }
                            redundancy = (double)max/(index+1);
                            if(redundancy > 0.5){
                                IntraRedIndexPair newpair;
                                newpair.redundancy = redundancy;
                                newpair.indexes = maxList;                            
                                RecordIntraArrayRedundancy(dataHandle.pathHandle,curCtxt, newpair,threadId,0);
                            }
                }else if(it->second.accessLen == 4){
                            unordered_map<uint32_t,list<uint32_t>> valuesMap1;
                            unordered_map<uint32_t,list<uint32_t>>::iterator it1;
                            address = dataHandle.beg_addr;
                            index = 0;
                            while(address < dataHandle.end_addr){
            
                                uint32_t value1 = *static_cast<uint32_t *>((void *)address);
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
                            }
                            max = 1;
                            list<uint32_t> maxList;
                            for (it1 = valuesMap1.begin(); it1 != valuesMap1.end(); ++it1){
                                if(max < it1->second.size()){
                                    max = it1->second.size();
                                    maxList = it1->second;
                                }
                            }
                            redundancy = (double)max/(index+1);
                            if(redundancy > 0.5){
                                IntraRedIndexPair newpair;
                                newpair.redundancy = redundancy;
                                newpair.indexes = maxList;                            
                                RecordIntraArrayRedundancy(dataHandle.pathHandle,curCtxt, newpair,threadId,0);
                            }
                 
                }else if(it->second.accessLen == 8){
                            unordered_map<uint64_t,list<uint32_t>> valuesMap1;
                            unordered_map<uint64_t,list<uint32_t>>::iterator it1;
                            address = dataHandle.beg_addr;
                            index = 0;
                            while(address < dataHandle.end_addr){
            
                                uint64_t value1 = *static_cast<uint64_t *>((void *)address);
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
                            }
                            max = 1;
                            list<uint32_t> maxList;
                            for (it1 = valuesMap1.begin(); it1 != valuesMap1.end(); ++it1){
                                if(max < it1->second.size()){
                                    max = it1->second.size();
                                    maxList = it1->second;
                                }
                            }
                            redundancy = (double)max/(index+1);
                            if(redundancy > 0.5){
                                IntraRedIndexPair newpair;
                                newpair.redundancy = redundancy;
                                newpair.indexes = maxList;                            
                                RecordIntraArrayRedundancy(dataHandle.pathHandle,curCtxt, newpair,threadId,0);
                            }

                }else{
                            printf("\nHaven't thought about how to handle this case\n"); 
                           //  break;
                }
                it->second.lastOperation = 0;
            }
        }
    }else if(dataHandle.objectType == STATIC_OBJECT){
        unordered_map<uint32_t,DataObjectStatus>::iterator it;
        uint64_t address;
        uint32_t index,max;
        double redundancy;
        it = tData->staticDataObjects.find(dataHandle.symName);
        if(it != tData->staticDataObjects.end()){
            if(it->second.lastOperation != 0){
//check the same elements in this dataObject

              printf("%s\n",GetStringFromStringPool(dataHandle.symName));

                if(it->second.accessLen == 1){
                            unordered_map<uint8_t,list<uint32_t>> valuesMap1;
                            unordered_map<uint8_t,list<uint32_t>>::iterator it1;
                            address = dataHandle.beg_addr;
                            index = 0;
                            while(address < dataHandle.end_addr){
            
                                uint8_t value1 = *static_cast<uint8_t *>((void *)address);
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
                            }
                            max = 1;
                            uint8_t vvv = 0;
                            list<uint32_t> maxList;
                            for (it1 = valuesMap1.begin(); it1 != valuesMap1.end(); ++it1){
                                if(max < it1->second.size()){
                                    max = it1->second.size();
                                    maxList = it1->second;
                                    vvv = it1->first;
                                }
                            }
                            redundancy = (double)max/(index+1);
                            if(redundancy > 0.5){
printf("%d,%" PRIu8 "\n",1,vvv);
list<uint32_t>::iterator iii;
iii = maxList.begin();
for(iii = maxList.begin();iii != maxList.end(); ++iii)
    printf("%d,",*iii);

                                IntraRedIndexPair newpair;
                                newpair.redundancy = redundancy;
                                newpair.indexes = maxList;                            
                                RecordIntraArrayRedundancy(dataHandle.symName,curCtxt, newpair,threadId,1);
                            }

                }else if(it->second.accessLen == 2){
                            unordered_map<uint16_t,list<uint32_t>> valuesMap1;
                            unordered_map<uint16_t,list<uint32_t>>::iterator it1;
                            address = dataHandle.beg_addr;
                            index = 0;
                            while(address < dataHandle.end_addr){
            
                                uint16_t value1 = *static_cast<uint16_t *>((void *)address);
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
                            }
                            max = 1;
                            uint16_t vvv = 0;
                            list<uint32_t> maxList;
                            for (it1 = valuesMap1.begin(); it1 != valuesMap1.end(); ++it1){
                                if(max < it1->second.size()){
                                    max = it1->second.size();
                                    maxList = it1->second;
                                    vvv = it1->first;
                                }
                            }
                            redundancy = (double)max/(index+1);
                            if(redundancy > 0.5){
printf("%d,%" PRIu16 "\n",2,vvv);
list<uint32_t>::iterator iii;
iii = maxList.begin();
for(iii = maxList.begin();iii != maxList.end(); ++iii)
    printf("%d,",*iii);

                                IntraRedIndexPair newpair;
                                newpair.redundancy = redundancy;
                                newpair.indexes = maxList;                            
                                RecordIntraArrayRedundancy(dataHandle.symName,curCtxt, newpair,threadId,1);
                            }

                }else if(it->second.accessLen == 4){
                            unordered_map<uint32_t,list<uint32_t>> valuesMap1;
                            unordered_map<uint32_t,list<uint32_t>>::iterator it1;
                            address = dataHandle.beg_addr;
                            index = 0;
                            while(address < dataHandle.end_addr){
            
                                uint32_t value1 = *static_cast<uint32_t *>((void *)address);
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
                            }
                            max = 1;
                            uint32_t vvv = 0;
                            list<uint32_t> maxList;
                            for (it1 = valuesMap1.begin(); it1 != valuesMap1.end(); ++it1){
                                if(max < it1->second.size()){
                                    max = it1->second.size();
                                    maxList = it1->second;
                                    vvv = it1->first;
                                }
                            }
                            redundancy = (double)max/(index+1);
                            if(redundancy > 0.5){
printf("%d,%" PRIu32 "\n",4,vvv);
list<uint32_t>::iterator iii;
iii = maxList.begin();
for(iii = maxList.begin();iii != maxList.end(); ++iii)
    printf("%d,",*iii);

                                IntraRedIndexPair newpair;
                                newpair.redundancy = redundancy;
                                newpair.indexes = maxList;                            
                                RecordIntraArrayRedundancy(dataHandle.symName,curCtxt, newpair,threadId,1);
                            }

                }else if(it->second.accessLen == 8){
                            unordered_map<uint64_t,list<uint32_t>> valuesMap1;
                            unordered_map<uint64_t,list<uint32_t>>::iterator it1;
                            address = dataHandle.beg_addr;
                            index = 0;
                            while(address < dataHandle.end_addr){
            
                                uint64_t value1 = *static_cast<uint64_t *>((void *)address);
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
                            }
                            max = 1;
                            uint64_t vvv = 0;
                            list<uint32_t> maxList;
                            for (it1 = valuesMap1.begin(); it1 != valuesMap1.end(); ++it1){
                                if(max < it1->second.size()){
                                    max = it1->second.size();
                                    maxList = it1->second;
                                    vvv = it1->first;
                                }
                            }
                            redundancy = (double)max/(index+1);
                            if(redundancy > 0.5){
printf("%d,%" PRIu64 "\n",8,vvv);
list<uint32_t>::iterator iii;
iii = maxList.begin();
for(iii = maxList.begin();iii != maxList.end(); ++iii)
    printf("%d,",*iii);

                                IntraRedIndexPair newpair;
                                newpair.redundancy = redundancy;
                                newpair.indexes = maxList;                            
                                RecordIntraArrayRedundancy(dataHandle.symName,curCtxt, newpair,threadId,1);
                            }

                }else{     
                            printf("\nHaven't thought about how to handle this case\n");
                            //break; 
                }
                it->second.lastOperation = 0;
            }
        }

    }
}


template<uint16_t AccessLen, uint32_t bufferOffset>
struct RedSpyAnalysis{
    static inline bool IsWriteRedundant(void * &addr, THREADID threadId){
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        AddrValPair * avPair = & tData->buffer[bufferOffset];
        addr = avPair->address;
        switch(AccessLen){
            case 1: return *((uint8_t*)(&avPair->value)) == *(static_cast<uint8_t*>(avPair->address));
            case 2: return *((uint16_t*)(&avPair->value)) == *(static_cast<uint16_t*>(avPair->address));
            case 4: return *((uint32_t*)(&avPair->value)) == *(static_cast<uint32_t*>(avPair->address));
            case 8: return *((uint64_t*)(&avPair->value)) == *(static_cast<uint64_t*>(avPair->address));
            default: return memcmp(&avPair->value, avPair->address, AccessLen) == 0;
        }
    }
    
    static inline VOID RecordNByteValueBeforeWrite(void* addr, THREADID threadId){
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        AddrValPair * avPair = & tData->buffer[bufferOffset];
//printf("\n B: %lx %lu %d %d %lx", (uint64_t)addr, tData->bytesWritten, AccessLen, bufferOffset, (uint64_t)ip);
//fflush(stdout);
        avPair->address = addr;
        switch(AccessLen){
            case 1: *((uint8_t*)(&avPair->value)) = *(static_cast<uint8_t*>(addr)); break;
            case 2: *((uint16_t*)(&avPair->value)) = *(static_cast<uint16_t*>(addr)); break;
            case 4: *((uint32_t*)(&avPair->value)) = *(static_cast<uint32_t*>(addr)); break;
            case 8: *((uint64_t*)(&avPair->value)) = *(static_cast<uint64_t*>(addr)); break;
            default:memcpy(&avPair->value, addr, AccessLen);
        }
        /////////////////////////////////////////
        if((uint64_t)addr & 0x7f0000000000)
            return;
        DataHandle_t dataHandle = GetDataObjectHandle(addr,threadId);
        if(dataHandle.objectType == DYNAMIC_OBJECT){
            if((dataHandle.end_addr - dataHandle.beg_addr)/AccessLen <= 1)
                return;
            unordered_map<uint32_t,DataObjectStatus>::iterator it;
            it = tData->dynamicDataObjects.find(dataHandle.pathHandle);
            if(it == tData->dynamicDataObjects.end()){
                DataObjectStatus newStatus;
                newStatus.accessLen = AccessLen;
                newStatus.lastOperation += 1;
                tData->dynamicDataObjects.insert(std::pair<uint32_t,DataObjectStatus>(dataHandle.pathHandle,newStatus));
            }else{
                it->second.lastOperation += 1;
            }
        }else if(dataHandle.objectType == STATIC_OBJECT){
            if((dataHandle.end_addr - dataHandle.beg_addr)/AccessLen <= 1)
                return; 
            unordered_map<uint32_t,DataObjectStatus>::iterator it;
            it = tData->staticDataObjects.find(dataHandle.symName);
            if(it == tData->staticDataObjects.end()){
                DataObjectStatus newStatus;
                newStatus.accessLen = AccessLen;
                newStatus.lastOperation += 1;
                tData->staticDataObjects.insert(std::pair<uint32_t,DataObjectStatus>(dataHandle.symName,newStatus));
            }else{
                it->second.lastOperation += 1;
            }
        } 
    }
    
    static inline VOID CheckNByteValueAfterWrite(void * address, uint32_t opaqueHandle, THREADID threadId){
        void * addr;
        bool isRedundantWrite = IsWriteRedundant(addr, threadId);
//printf("\t A: %lx %lu %d %d %lx", (uint64_t)addr, ClientGetTLS(threadId)->bytesWritten, AccessLen, bufferOffset, (uint64_t)ip);
//fflush(stdout);
        ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
        
        uint8_t* status = GetOrCreateShadowBaseAddress((uint64_t)addr);
        ContextHandle_t * __restrict__ prevIP = (ContextHandle_t*)(status + PAGE_OFFSET((uint64_t)addr) * sizeof(ContextHandle_t));
        const bool isAccessWithinPageBoundary = IS_ACCESS_WITHIN_PAGE_BOUNDARY( (uint64_t)addr, AccessLen);
        if(isRedundantWrite) {
            int indexInfo = -1; 
            if((uint64_t)address & 0x7f0000000000){
                ;
            }else{
                DataHandle_t dataHandle = GetDataObjectHandle(address,threadId);
                if(dataHandle.objectType == DYNAMIC_OBJECT || dataHandle.objectType == STATIC_OBJECT){                
                    indexInfo = (dataHandle.end_addr - (uint64_t)address)/AccessLen;
                    if(indexInfo<=1)
                        indexInfo = -1;
                }
            }
            // detected redundancy
            if(isAccessWithinPageBoundary) {
                // All from same ctxt?
                if (UnrolledConjunction<0, AccessLen, 1>::Body( [&] (int index) -> bool { return (prevIP[index] == prevIP[0]); })) {
                    // report in RedTable
                    AddToRedTable(MAKE_CONTEXT_PAIR(prevIP[0], curCtxtHandle),indexInfo, AccessLen, threadId);
                    // Update context
                    UnrolledLoop<0, AccessLen, 1>::Body( [&] (int index) -> VOID {
                        // Update context
                        prevIP[index] = curCtxtHandle;
                    });
                } else {
                    // different contexts
                    UnrolledLoop<0, AccessLen, 1>::Body( [&] (int index) -> VOID {
                        // report in RedTable
                        AddToRedTable(MAKE_CONTEXT_PAIR(prevIP[index], curCtxtHandle),indexInfo, 1,threadId);
                        // Update context
                        prevIP[index] = curCtxtHandle;
                    });
                }
            } else {
                // Write across a 64-K page boundary
                // First byte is on this page though
                AddToRedTable(MAKE_CONTEXT_PAIR(prevIP[0], curCtxtHandle),indexInfo, 1, threadId);
                // Update context
                prevIP[0] = curCtxtHandle;
                
                // Remaining bytes [1..AccessLen] somewhere will across a 64-K page boundary
                UnrolledLoop<1, AccessLen, 1>::Body( [&] (int index) -> VOID {
                    status = GetOrCreateShadowBaseAddress((uint64_t)addr + index);
                    prevIP = (ContextHandle_t*)(status + PAGE_OFFSET(((uint64_t)addr + index)) * sizeof(ContextHandle_t));
                    // report in RedTable
                    AddToRedTable(MAKE_CONTEXT_PAIR(prevIP[0 /* 0 is correct*/ ], curCtxtHandle),indexInfo, 1, threadId);
                    // Update context
                    prevIP[0] = curCtxtHandle;
                } );
            }
        } else {
            // No redundancy.
            // Just update contexts
            if(isAccessWithinPageBoundary) {
                UnrolledLoop<0, AccessLen, 1>::Body( [&] (int index) -> VOID {
                    // Update context
                    prevIP[index] = curCtxtHandle;
                });
            } else {
                // Write across a 64-K page boundary
                UnrolledLoop<0, AccessLen, 1>::Body( [&] (int index) -> VOID {
                    status = GetOrCreateShadowBaseAddress((uint64_t)addr + index);
                    prevIP = (ContextHandle_t*)(status + PAGE_OFFSET(((uint64_t)addr + index)) * sizeof(ContextHandle_t));
                    // Update context
                    prevIP[0] = curCtxtHandle;
                } );
            }
        }
    }
};


static inline VOID RecordValueBeforeLargeWrite(void* addr, UINT32 accessLen,  uint32_t bufferOffset, THREADID threadId){
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    memcpy(& (tData->buffer[bufferOffset].value), addr, accessLen);
    tData->buffer[bufferOffset].address = addr;
    /////////////////////////////////////////
    if((uint64_t)addr & 0x7f0000000000)
        return;
    DataHandle_t dataHandle = GetDataObjectHandle(addr,threadId);
    if(dataHandle.objectType == DYNAMIC_OBJECT){
        unordered_map<uint32_t,DataObjectStatus>::iterator it;
        it = tData->dynamicDataObjects.find(dataHandle.pathHandle);
        if(it == tData->dynamicDataObjects.end()){
            DataObjectStatus newStatus;
            newStatus.accessLen = accessLen;
            newStatus.lastOperation += 1;
            tData->dynamicDataObjects.insert(std::pair<uint32_t,DataObjectStatus>(dataHandle.pathHandle,newStatus));
        }else{
            it->second.lastOperation += 1;
        }
    }else if(dataHandle.objectType == STATIC_OBJECT){
        unordered_map<uint32_t,DataObjectStatus>::iterator it;
        it = tData->staticDataObjects.find(dataHandle.symName);
        if(it == tData->staticDataObjects.end()){
            DataObjectStatus newStatus;
            newStatus.accessLen = accessLen;
            newStatus.lastOperation += 1;
            tData->staticDataObjects.insert(std::pair<uint32_t,DataObjectStatus>(dataHandle.symName,newStatus));
        }else{
            it->second.lastOperation += 1;
        }
    } 
}

static inline VOID CheckAfterLargeWrite(void* address, UINT32 accessLen,  uint32_t bufferOffset, uint32_t opaqueHandle, THREADID threadId){
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    void * addr = tData->buffer[bufferOffset].address;
    ContextHandle_t curCtxtHandle = GetContextHandle(threadId, opaqueHandle);
    
    uint8_t* status = GetOrCreateShadowBaseAddress((uint64_t)addr);
    ContextHandle_t * __restrict__ prevIP = (ContextHandle_t*)(status + PAGE_OFFSET((uint64_t)addr) * sizeof(ContextHandle_t));
    if(memcmp( & (tData->buffer[bufferOffset].value), addr, accessLen) == 0){
        // redundant
        int indexInfo = -1; 
        if((uint64_t)address & 0x7f0000000000){
                ;
        }else{
            DataHandle_t dataHandle = GetDataObjectHandle(address,threadId);
            if(dataHandle.objectType == DYNAMIC_OBJECT || dataHandle.objectType == STATIC_OBJECT){                
                indexInfo = (dataHandle.end_addr - (uint64_t)address)/accessLen;
                if(indexInfo<=1)
                    indexInfo = -1;
            }
        }
        for(UINT32 index = 0 ; index < accessLen; index++){
            status = GetOrCreateShadowBaseAddress((uint64_t)addr + index);
            prevIP = (ContextHandle_t*)(status + PAGE_OFFSET(((uint64_t)addr + index)) * sizeof(ContextHandle_t));
            // report in RedTable
            AddToRedTable(MAKE_CONTEXT_PAIR(prevIP[0 /* 0 is correct*/ ], curCtxtHandle),indexInfo, 1, threadId);
            // Update context
            prevIP[0] = curCtxtHandle;
        }
    }else{
        // Not redundant
        for(UINT32 index = 0 ; index < accessLen; index++){
            status = GetOrCreateShadowBaseAddress((uint64_t)addr + index);
            prevIP = (ContextHandle_t*)(status + PAGE_OFFSET(((uint64_t)addr + index)) * sizeof(ContextHandle_t));
            // Update context
            prevIP[0] = curCtxtHandle;
        }
    }
}




inline VOID BytesWrittenInBBL(uint32_t count, THREADID threadId) {
    ClientGetTLS(threadId)->bytesWritten += count;
}



// Instrument a trace, take the first instruction in the first BBL and insert the analysis function before that
static void InstrumentTrace(TRACE trace, void* f) {
    // Insert counting code
    for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        uint32_t totalBytesWrittenInBBL = 0;
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if(INS_IsMemoryWrite(ins)) {
                totalBytesWrittenInBBL += INS_MemoryWriteSize(ins);
            }
        }
        
        // Insert a call to corresponding count routines before every bbl, passing the number of instructions
        
        // Increment Inst count by trace
        if(totalBytesWrittenInBBL)
            BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR) BytesWrittenInBBL, IARG_UINT32, totalBytesWrittenInBBL, IARG_THREAD_ID, IARG_END);
    }
}

#define HANDLE_CASE(NUM, BUFFER_INDEX) \
case (NUM):{INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) RedSpyAnalysis<(NUM), (BUFFER_INDEX)>::RecordNByteValueBeforeWrite, IARG_MEMORYOP_EA, memOp, IARG_THREAD_ID, IARG_END);\
INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) RedSpyAnalysis<(NUM), (BUFFER_INDEX)>::CheckNByteValueAfterWrite, IARG_MEMORYOP_EA, memOp, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_INST_PTR,IARG_END);}break


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
    static inline void InstrumentReadValueBeforeAndAfterWriting(INS ins, UINT32 memOp, uint32_t opaqueHandle){
        UINT32 refSize = INS_MemoryOperandSize(ins, memOp);
        switch(refSize) {
                HANDLE_CASE(1, readBufferSlotIndex);
                HANDLE_CASE(2, readBufferSlotIndex);
                HANDLE_CASE(4, readBufferSlotIndex);
                HANDLE_CASE(8, readBufferSlotIndex);
                HANDLE_CASE(10, readBufferSlotIndex);
                HANDLE_CASE(16, readBufferSlotIndex);
                
            default: {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) RecordValueBeforeLargeWrite, IARG_MEMORYOP_EA, memOp, IARG_MEMORYWRITE_SIZE, IARG_UINT32, readBufferSlotIndex, IARG_THREAD_ID, IARG_END);
                INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) CheckAfterLargeWrite, IARG_MEMORYOP_EA, memOp, IARG_MEMORYREAD_SIZE, IARG_UINT32, readBufferSlotIndex, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_END);
            }
        }
    }
};

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
               INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) CheckIntraArrayElements, IARG_MEMORYOP_EA, memop, IARG_THREAD_ID, IARG_UINT32,opaqueHandle, IARG_END);    
           }else if(INS_MemoryOperandIsWritten(ins,memop)){
               RedSpyInstrument<0>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, opaqueHandle);
           }
        }
        return;
    }
    
    int readBufferSlotIndex=0;
    for(UINT32 memOp = 0; memOp < memOperands; memOp++) {
        if(INS_MemoryOperandIsRead(ins,memOp)){
             INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) CheckIntraArrayElements, IARG_MEMORYOP_EA, memOp, IARG_THREAD_ID, IARG_UINT32,opaqueHandle, IARG_END);    
        }       
 
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


struct RedundacyData {
    ContextHandle_t dead;
    ContextHandle_t kill;
    uint64_t frequency;
    list<uint32_t> index;
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
                  uint32_t val = (*it).second & 0x00000000ffffffff;
                  uint32_t ind = (*it).second >> 32;
                  (*tmpIt).frequency += val;
                  grandTotalRedundantBytes += val;
                  if(ind & 0xffffffff)
                      break;
                  list<uint32_t>::iterator findit = find((*tmpIt).index.begin(),(*tmpIt).index.end(),ind);
                  if(findit == (*tmpIt).index.end())
                      (*tmpIt).index.push_back(ind);
                  break;
             }
        }
        if(tmpIt == tmpList.end()){
             uint32_t val = (*it).second & 0x00000000ffffffff;
             uint32_t ind = (*it).second >> 32;
             list<uint32_t> newInd;
             newInd.push_back(ind);
             RedundacyData tmp = { dead, kill, val, newInd};
             tmpList.push_back(tmp);
             grandTotalRedundantBytes += tmp.frequency;
        }
    }   
    fprintf(gTraceFile, "\n Total redundant bytes = %f %%\n", grandTotalRedundantBytes * 100.0 / ClientGetTLS(threadId)->bytesWritten);
    
    sort(tmpList.begin(), tmpList.end(), RedundacyCompare);
    vector<struct AnalyzedMetric_t>::iterator listIt;
    int cntxtNum = 0;
    for (vector<RedundacyData>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if (cntxtNum < MAX_REDUNDANT_CONTEXTS_TO_LOG) {
            fprintf(gTraceFile, "\n========== (%f) %% ==========\n", (*listIt).frequency * 100.0 / grandTotalRedundantBytes);
            if ((*listIt).dead == 0) {
                fprintf(gTraceFile, "\n Prepopulated with  by OS\n");
            } else {
                PrintFullCallingContext((*listIt).dead);
            }
            string indexlist = ConvertListToString((*listIt).index);
            fprintf(gTraceFile, "\n-------------Redundantly written at index:%s by---------------------------\n",indexlist.c_str());
            PrintFullCallingContext((*listIt).kill);
        }
        else {
            break;
        }
        cntxtNum++;
    }
    fprintf(gTraceFile,"\n*************** Intra Array Redundancy of Thread %d ***************\n",threadId);
    unordered_map<uint64_t,list<IntraRedIndexPair>>::iterator itIntra;
    uint8_t staticAccount = 0;
    fprintf(gTraceFile,"========== Static Dataobjecy Redundancy ==========\n");
    for(itIntra = stIntraDataRed[threadId].begin(); itIntra != stIntraDataRed[threadId].end(); ++itIntra){
        uint64_t keyhash = itIntra->first;
        uint32_t dataObj = keyhash >> 32;
        uint32_t contxt = keyhash & 0xffffffff;
        char *symName = GetStringFromStringPool(dataObj);
        fprintf(gTraceFile,"Variable %s redudancy at %d\n",symName,contxt);
        PrintFullCallingContext(contxt);
        list<IntraRedIndexPair>::iterator listit;
        fprintf(gTraceFile,"\n");
        for(listit = itIntra->second.begin(); listit != itIntra->second.end(); ++listit){
            fprintf(gTraceFile,"Red:%.2f, at Indexes:",(*listit).redundancy);
            string indexlist = ConvertListToString((*listit).indexes);
            fprintf(gTraceFile,"%s",indexlist.c_str());
        }
        fprintf(gTraceFile,"\n----------------------------");
        staticAccount++;
        if(staticAccount > 100)
            break;
    }
    fprintf(gTraceFile,"########## Dynamic Dataobjecy Redundancy ##########\n");
    for(itIntra = dyIntraDataRed[threadId].begin(); itIntra != dyIntraDataRed[threadId].end(); ++itIntra){
        uint64_t keyhash = itIntra->first;
        uint32_t dataObj = keyhash >> 32;
        uint32_t contxt = keyhash & 0xffffffff;        
        PrintFullCallingContext(dataObj);
        fprintf(gTraceFile,"\n--- redundancy at:\n");
        PrintFullCallingContext(contxt);
        list<IntraRedIndexPair>::iterator listit;
        fprintf(gTraceFile,"\n");
        for(listit = itIntra->second.begin(); listit != itIntra->second.end(); ++listit){
            fprintf(gTraceFile,"Red:%.2f,at indexes:",(*listit).redundancy);
            string indexlist = ConvertListToString((*listit).indexes);
            fprintf(gTraceFile,"%s",indexlist.c_str());
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
    RedMap[threadid].clear();
    dyIntraDataRed[threadid].clear();
    stIntraDataRed[threadid].clear();
}

static VOID ThreadFiniFunc(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v) {
}

static VOID FiniFunc(INT32 code, VOID *v) {
    // do whatever you want to the full CCT with footpirnt
}


static void InitThreadData(RedSpyThreadData* tdata){
    tdata->bytesWritten = 0;
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
    TRACE_AddInstrumentFunction(InstrumentTrace, 0);
    
    
    // Register ImageUnload to be called when an image is unloaded
    IMG_AddUnloadFunction(ImageUnload, 0);
    
    // Launch program now
    PIN_StartProgram();
    return 0;
}


