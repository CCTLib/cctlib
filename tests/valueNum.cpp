/* This file is created by Shasha Wen at College of William and Mary. This is a cctlib client for detecting computation redundancies using dynamic value numbering */

#include <stdio.h>
#include <stdlib.h>
#include "pin.H"
#include "pin_isa.H"
#include <map>
#include <ext/hash_map>
#include <list>
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
#include <pthread.h>
// Need GOOGLE sparse hash tables
#include <google/sparse_hash_map>
#include <google/dense_hash_map>
using google::sparse_hash_map;  // namespace where class lives by default
using google::dense_hash_map;   // namespace where class lives by default

using namespace __gnu_cxx;
using namespace std;

#include "cctlib.H"
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





// All globals
#define MAX_FILE_PATH   (200)
#define MAX_DEAD_CONTEXTS_TO_LOG (5000)
#define MAX_LOG_NUM (110)
#define MAX_OPERAND (10)

namespace __gnu_cxx{

    template<> struct hash<const string>
    {
        size_t operator()(const string& s) const
        { return hash<const char*>()( s.c_str() ); } //__stl_hash_string
    };
    template<> struct hash<string>
    {
        size_t operator()(const string& s) const
        { return hash<const char*>()( s.c_str() ); }
    };
}

enum AccessType{
    READ_ACCESS = 0,
    WRITE_ACCESS = 1
};

FILE *gTraceFile;
static uint64_t gValue;
static uint8_t ** gL1PageTable[LEVEL_1_PAGE_TABLE_SIZE];

typedef struct opMap{ 
    uint64_t vNum;
    uint32_t ip;
}OPMap;


class ThreadData_t {
public:
    uint64_t regNumber[REG_LAST];
    hash_map<uint64_t, uint64_t> immediateMap;
    hash_map<uint64_t, uint64_t>::iterator immediateMapIt;
    
    /*hash_map<string, uint64_t> opcodeMap;
    hash_map<string, uint64_t>::iterator opcodeMapIt;
    map<string, uint32_t> opcodeContext;
    map<string, uint32_t>::iterator opcodeContextIt;
    hash_map<uint32_t, string> IPstring;
    hash_map<uint32_t, string>::iterator IPstringIt;*/
    dense_hash_map<string, OPMap> opcodeMap;
    dense_hash_map<string, OPMap>::iterator opcodeMapIt;
    dense_hash_map<uint32_t, string> IPstring;
    dense_hash_map<uint32_t, string>::iterator IPstringIt;

    dense_hash_map<uint64_t, uint64_t> redundantMap;
    dense_hash_map<uint64_t, uint64_t>::iterator redundantMapIt;

    /*dense_hash_map<uint64_t, uint64_t> redundantMap;
    dense_hash_map<uint64_t, uint64_t>::iterator redundantMapIt;*/

    ThreadData_t(){
	memset(regNumber, sizeof(uint64_t) * REG_LAST, 0);
    }
};

typedef struct opcodeInfo{
    OPCODE opCode; 
    vector<REG> sRegs;
    vector<uint64_t> immediates;
    vector<REG> tRegs;
}OPInfo;

struct RedundantInfoForPresentation{
    uint64_t key;
    uint64_t count;
};



// key for accessing TLS storage in the threads. initialized once in main()
static  TLS_KEY tls_key;
static PIN_MUTEX  gMutex;

list<RedundantInfoForPresentation> gRedundantList;


// If it is one of ignoreable instructions, then skip instrumentation.
bool IsIgnorableIns(INS ins){
    if(INS_IsFarJump(ins) || INS_IsDirectFarJump(ins) || INS_IsMaskedJump(ins))
        return true;
    else if(INS_IsRet(ins) || INS_IsIRet(ins))
        return true;
    else if(INS_IsCall(ins) || INS_IsSyscall(ins))
        return true;
    else if(INS_IsBranch(ins) || INS_IsRDTSC(ins) || INS_IsNop(ins))
        return true;
    return false;
}

// function to access thread-specific data
inline ThreadData_t* GetTLS(THREADID threadid)
{
    ThreadData_t* tdata =
    static_cast<ThreadData_t*>(PIN_GetThreadData(tls_key, threadid));
    return tdata;
}

/* helper functions for shadow memory */
static uint8_t* GetOrCreateShadowBaseAddress(uint64_t address) {
    uint8_t *shadowPage;
    uint8_t ***l1Ptr = &gL1PageTable[LEVEL_1_PAGE_TABLE_SLOT(address)];
    if(*l1Ptr == 0) {
        *l1Ptr = (uint8_t **) calloc(1, LEVEL_2_PAGE_TABLE_SIZE);
        shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] =  (uint8_t *) mmap(0, PAGE_SIZE * (sizeof(bool) + sizeof(uint64_t)), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    }
    else if((shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)]) == 0 ){
        shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] =  (uint8_t *) mmap(0, PAGE_SIZE * (sizeof(bool) + sizeof(uint64_t)), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    }
    return shadowPage;
}

//get the value number from the shadow memory
inline uint64_t getMemValueNum(uint64_t addr, THREADID threadid){

    uint8_t* status = GetOrCreateShadowBaseAddress(addr);
    uint64_t *prevAddr = (uint64_t *)(status + PAGE_SIZE +  PAGE_OFFSET(addr) * sizeof(uint64_t));
    if(*prevAddr==0)
    {
        gValue++;
        *prevAddr = gValue;
    }

    return *prevAddr;
}


//get the value number from the register
inline uint64_t getRegValueNum(REG reg, THREADID threadid){

    ThreadData_t * td = GetTLS(threadid);
    if(td->regNumber[reg] == 0)
    {
        gValue++;
        td->regNumber[reg] = gValue;
    }
//fprintf(gTraceFile,"get register %d value number:%lu\n",reg,td->regNumber[reg]);
    return td->regNumber[reg];
}

//set a new value number to the memory
inline VOID setMemValueNum(uint64_t addr, THREADID threadid, uint64_t value){

    uint8_t* status = GetOrCreateShadowBaseAddress(addr);
    uint64_t *prevAddr = (uint64_t *)(status + PAGE_SIZE +  PAGE_OFFSET(addr) * sizeof(uint64_t));
    *prevAddr = value;
}

//set a new value number to the register
inline VOID setRegValueNum(REG reg, THREADID threadid, uint64_t value){

    ThreadData_t * td = GetTLS(threadid);
//fprintf(gTraceFile,"set register %d value number:%lu\n",reg,value);
    td->regNumber[reg] = value;
}


//get the value number for the immediate data
inline uint64_t getImmediateValueNum(uint64_t immediate, THREADID threadid){

    ThreadData_t * td = GetTLS(threadid);
    td->immediateMapIt = td->immediateMap.find(immediate);
    if(td->immediateMapIt == td->immediateMap.end())
    {
        gValue++;
        td->immediateMap.insert(std::pair<uint64_t, uint64_t>(immediate,gValue));
//fprintf(gTraceFile,"get immediate %lu value number:%lu\n",immediate,gValue);
        return gValue;
    }
//fprintf(gTraceFile,"get immediate %lu value number:%lu\n",immediate,td->immediateMapIt->second);
    return td->immediateMapIt->second;
}


inline void recordRedundantOperation(uint32_t deadCtxt, uint32_t killerCtxt, ThreadData_t * td) {

    uint64_t deadIndex = (uint64_t)deadCtxt;
    uint64_t killerIndex = (uint64_t)killerCtxt;
    uint64_t key = (deadIndex << 32) | killerIndex;

    if ( (td->redundantMapIt = td->redundantMap.find(key))  == td->redundantMap.end()) {
        td->redundantMap.insert(std::pair<uint64_t, uint64_t>(key,1));
    } else {
        (td->redundantMapIt->second) += 1;
    }
}


void deleteString(string str, THREADID threadid){
    
    ThreadData_t * td = GetTLS(threadid);\
    //string str(arr);
    td->opcodeMapIt = td->opcodeMap.find(str);
    if(td->opcodeMapIt != td->opcodeMap.end()){

        td->opcodeMap.erase(td->opcodeMapIt);
    }
    //delete str;
}

//delete the old string if the string for the same IP is changed
void removeOldstring(void *ip, char *str, THREADID threadid){

    uint64_t addr = (uint64_t)ip;
    uint8_t* status = GetOrCreateShadowBaseAddress(addr);
    char **prevAddr = (char **)(status + PAGE_SIZE +  PAGE_OFFSET(addr) * sizeof(char *));
 
    if(*prevAddr == (char *)0){

        *prevAddr = str;
    }else{

        if(*prevAddr != str){
            string old(*prevAddr);
            deleteString(old, threadid);
            *prevAddr = str;
        }
    }
}

void checkMovValueNum(int opcode, uint64_t svalue, uint64_t target, THREADID threadid, void *ip, const uint32_t opHandle){

    ThreadData_t * td = GetTLS(threadid);
    uint32_t curCtxt = GetContextHandle(threadid, opHandle);

    string str = to_string(opcode);
    str += "_";
    str += to_string(svalue);
    str += "_";
    str += to_string(target);

    /*bool flag = 1;
    td->IPstringIt = td->IPstring.find(curCtxt);
    if(td->IPstringIt == td->IPstring.end()){
        td->IPstring.insert(std::pair<uint32_t, string>(curCtxt,str));
        flag = 0;
    }*/
    
    td->opcodeMapIt = td->opcodeMap.find(str);
    if(td->opcodeMapIt == td->opcodeMap.end()){
        OPMap opmap = {svalue, curCtxt}; 
        td->opcodeMap.insert(std::pair<string, OPMap>(str,opmap));
        //removeOldstring(ip, (char *)str.c_str(), threadid);
        return;
    }
    recordRedundantOperation(td->opcodeMapIt->second.ip, curCtxt, td);

    /*char *strArray;
    strArray = new char[50];
    strcpy (strArray,str.c_str());*/

    removeOldstring(ip, (char *)str.c_str(), threadid);

    /*if(flag){
        if(td->IPstringIt->second != str){
            deleteString(td->IPstringIt->second, threadid);
            td->IPstringIt->second = str;
        }
    }*/
}

static inline string sortSvalues(uint64_t svalues[], int count, bool sort){
    string result;
    uint64_t temp;

    if(sort){

        for(int i = 1; i < count; ++i){
            for(int j = 0; j < i; ++j){
                if(svalues[j] > svalues[i]){
                    temp = svalues[j];
                    svalues[j] = svalues[i];
                    svalues[i] = temp;
                }
            }
        }
        for(int i = 0; i < count; ++i){
            result += svalues[i];
            result += "_";
        }

    }else{

        for(int i = 0; i < count; ++i){
            result += svalues[i];
            result += "_";
        }
    }
    return result;
}

//get the value number of the opcode and check the redundancy
uint64_t checkOpcodeValueNum(int op, uint64_t  svalues[], int sCount, THREADID threadid, void *ip, const uint32_t opHandle){

    ThreadData_t * td = GetTLS(threadid);
    uint32_t curCtxt = GetContextHandle(threadid, opHandle);
    string str = to_string(op);
    
    switch (sCount){

        case (0):
            return gValue++;
            break;
        case (1):
            str += "_";
            str += to_string(svalues[0]);
            break;
        case (2):
        case (3):
        case (4):
            str += "_";
            if(op != XED_ICLASS_DIV){
                str += sortSvalues(svalues,3,true);
            }else{
                str += sortSvalues(svalues,3,false);
            }
            break;
        default:
            printf("Source values more than 4!\n");
            break;
    }
    
    /*bool flag = 1;
    td->IPstringIt = td->IPstring.find(curCtxt);
    if(td->IPstringIt == td->IPstring.end()){
        td->IPstring.insert(std::pair<uint32_t, string>(curCtxt,str));
        flag = 0;
    }*/

    // use google's dense/sparse hash map
    td->opcodeMapIt = td->opcodeMap.find(str);
    if(td->opcodeMapIt == td->opcodeMap.end())
    {
        gValue++;
        OPMap opmap = {gValue, curCtxt}; 
        td->opcodeMap.insert(std::pair<string, OPMap>(str,opmap));
        //removeOldstring(ip, (char *)str.c_str(), threadid);
        return gValue;
    }
    uint64_t value = td->opcodeMapIt->second.vNum;

    recordRedundantOperation(td->opcodeMapIt->second.ip, curCtxt,td);
    
    /*char *strArray;
    strArray = new char[50];
    strcpy (strArray,str.c_str());*/

    removeOldstring(ip, (char *)str.c_str(), threadid);

    /*if(flag){
        if(td->IPstringIt->second != str){
            deleteString(td->IPstringIt->second, threadid);
            td->IPstringIt->second = str;
        }
    }*/

    return value;
}


VOID valueNumbering(void * op, bool movOrnot, THREADID threadID, void *ip, const uint32_t opHandle){
    OPInfo * opinfo = (OPInfo *) op;
    uint64_t value;
    int sRegsCount = opinfo->sRegs.size();
    int immediateCount = opinfo->immediates.size();

    if (movOrnot) {

        if(sRegsCount == 1)
            value = getRegValueNum(opinfo->sRegs[0], threadID);
        else if(immediateCount == 1)
            value = opinfo->immediates[0]; // enconding immediate numbers to avoid the hash map

        setRegValueNum(opinfo->tRegs[0],threadID,value);
    }else {
	// avoid using vectors, using constant sized array instead
        uint64_t sValues[6];
        int index = 0;

        for(int i = 0;i < sRegsCount;++i)
            sValues[index++] = getRegValueNum(opinfo->sRegs[i], threadID);

        for(int i = 0;i < immediateCount;++i)
            sValues[index++] = opinfo->immediates[i];
        
        value = checkOpcodeValueNum(opinfo->opCode, sValues, index, threadID, ip, opHandle);
        //value = gValue;

        int tRegsCount = opinfo->tRegs.size();
        if (tRegsCount == 1) {
            setRegValueNum(opinfo->tRegs[0], threadID,value);
        } else {
            for (int i = 0; i < tRegsCount; i++) {
                gValue++;
                setRegValueNum(opinfo->tRegs[i], threadID, gValue);
            }
        }
    }
}

VOID valueNumberingMem1(void * op, void * addr, uint32_t rMem, uint32_t wMem, bool movOrnot, THREADID threadID, void *ip, const uint32_t opHandle){
   
    OPInfo *opinfo = (OPInfo *) op;
    assert(rMem+wMem==1);
    uint64_t value = 0;

    int sRegsCount = opinfo->sRegs.size();
    int immediateCount = opinfo->immediates.size();
    
    if (movOrnot) {
        if (rMem == 1) {
            assert(opinfo->tRegs.size() == 1);

            value = getMemValueNum((uint64_t)addr, threadID);
            setRegValueNum(opinfo->tRegs[0], threadID, value);

            ////checkMovValueNum(opinfo->opCode, value, opinfo->tRegs[0], threadID, opHandle);
        } else {
            assert(sRegsCount == 1);
            if(sRegsCount == 1)
                value = getRegValueNum(opinfo->sRegs[0], threadID);
            else if(immediateCount == 1)
                value = opinfo->immediates[0];

            setMemValueNum((uint64_t)addr, threadID, value);
            checkMovValueNum(opinfo->opCode, value, (uint64_t)addr, threadID, ip, opHandle);
        }
    } else {

        uint64_t sValues[6];
        int index = 0;

        for(int i = 0;i < sRegsCount;++i)
            sValues[index++] = getRegValueNum(opinfo->sRegs[i], threadID);

        for(int i = 0;i < immediateCount;++i)
            sValues[index++] = opinfo->immediates[i];

        int tRegsCount = opinfo->tRegs.size();

        if (rMem == 1) {

            value = getMemValueNum((uint64_t)addr, threadID);
            sValues[index++] = value;
            
            value = checkOpcodeValueNum(opinfo->opCode, sValues, index, threadID, ip, opHandle);
            //value = gValue;
            
            if (tRegsCount == 1) {
                setRegValueNum(opinfo->tRegs[0], threadID, value);
            } else {
                for (int i = 0; i < tRegsCount; i++) {
                    gValue++;
                    setRegValueNum(opinfo->tRegs[i], threadID, gValue);
                }
            }
            
        } else {

            value = checkOpcodeValueNum(opinfo->opCode, sValues, index, threadID, ip, opHandle);
            //value = gValue;

            uint64_t add = (uint64_t)addr;
            uint8_t* status = GetOrCreateShadowBaseAddress(add);
            uint64_t *prevAddr = (uint64_t *)(status + PAGE_SIZE +  PAGE_OFFSET(add) * sizeof(uint64_t));
            if(*prevAddr==0)
            {
                gValue++;
                *prevAddr = gValue;
            }
      
            if (tRegsCount == 0) {

                setMemValueNum((uint64_t)addr, threadID, value);
            } else {
                gValue++;
                setMemValueNum((uint64_t)addr, threadID, gValue);
                
                for (int i = 0; i < tRegsCount; i++) {
                    gValue++;
                    setRegValueNum(opinfo->tRegs[i], threadID, gValue);
                }
            }
        }
    }
}

VOID valueNumberingMem2(void * op, void * addr1, void * addr2, uint32_t rMem, uint32_t wMem, bool movOrnot, THREADID threadID, void *ip, const uint32_t opHandle){
    
    OPInfo *opinfo = (OPInfo *) op;
    assert(rMem+wMem == 2);
    uint64_t value;

    int sRegsCount = opinfo->sRegs.size();
    int immediateCount = opinfo->immediates.size();
    
    if (movOrnot) {
        if (rMem == 1 && wMem == 1) {
            value = getMemValueNum((uint64_t)addr1, threadID);
            setMemValueNum((uint64_t)addr2, threadID, value);
            checkMovValueNum(opinfo->opCode, value, (uint64_t)addr2, threadID, ip, opHandle);
        }
    } else {

        uint64_t sValues[6];
        int index = 0;

        for(int i = 0;i < sRegsCount;++i)
            sValues[index++] = getRegValueNum(opinfo->sRegs[i], threadID);

        for(int i = 0;i < immediateCount;++i)
            sValues[index++] = opinfo->immediates[i];

        int tRegsCount = opinfo->tRegs.size();

//value = gValue;
        if (rMem == 0){
            
            value = checkOpcodeValueNum(opinfo->opCode, sValues, index, threadID, ip, opHandle);
            
            assert(wMem == 2);
            gValue++;
            setMemValueNum((uint64_t)addr1, threadID, gValue);
            gValue++;
            setMemValueNum((uint64_t)addr2, threadID, gValue);
            
        }else if (rMem == 1) {
            assert(wMem == 1);
            value = getMemValueNum((uint64_t)addr1, threadID);
            sValues[index++] = value;
            
            value = checkOpcodeValueNum(opinfo->opCode, sValues, index, threadID, ip, opHandle);
           
            if (tRegsCount == 0) {
                setMemValueNum((uint64_t)addr2, threadID, value);
            } else {
                
                gValue++;
                setMemValueNum((uint64_t)addr2, threadID, gValue);
                
                for (int i = 0; i < tRegsCount; i++) {
                    gValue++;
                    setRegValueNum(opinfo->tRegs[i], threadID, gValue);
                }
            }
            
        } else {
            assert(wMem == 0);
            value = getMemValueNum((uint64_t)addr1, threadID);
            sValues[index++] = value;
            
            value = getMemValueNum((uint64_t)addr2, threadID);
            sValues[index++] = value;


            value = checkOpcodeValueNum(opinfo->opCode, sValues, index, threadID, ip, opHandle);

            if (tRegsCount == 1) {
                setRegValueNum(opinfo->tRegs[0], threadID, value);
            } else {
                
                for (int i = 0; i < tRegsCount; i++) {
                    gValue++;
                    setRegValueNum(opinfo->tRegs[i], threadID, gValue);
                }
            }
        }
    }
}


VOID valueNumberingMem3(void * op, void * addr1, void * addr2, void * addr3, uint32_t rMem, uint32_t wMem, bool movOrnot, THREADID threadID, void *ip, const uint32_t opHandle){
    
    OPInfo *opinfo = (OPInfo *) op;
    assert(rMem+wMem == 3);
    uint64_t value;

    int sRegsCount = opinfo->sRegs.size();
    int immediateCount = opinfo->immediates.size();
    
    if (movOrnot) {
        printf("MOV with 3 memory addresses evloved!\n");
    } else {

        uint64_t sValues[6];
        int index = 0;

        for(int i = 0;i < sRegsCount;++i)
            sValues[index++] = getRegValueNum(opinfo->sRegs[i], threadID);

        for(int i = 0;i < immediateCount;++i)
            sValues[index++] = opinfo->immediates[i];

        int tRegsCount = opinfo->tRegs.size();

        value = gValue;/////////////////////////////

        switch (rMem) {
            case (0):
                assert(wMem == 3);
                value = checkOpcodeValueNum(opinfo->opCode, sValues, index, threadID, ip, opHandle);
                
                gValue++;
                setMemValueNum((uint64_t)addr1, threadID, gValue);
                gValue++;
                setMemValueNum((uint64_t)addr2, threadID, gValue);
                gValue++;
                setMemValueNum((uint64_t)addr3, threadID, gValue);
                
                for (int i = 0; i < tRegsCount; i++) {
                    gValue++;
                    setRegValueNum(opinfo->tRegs[i], threadID, gValue);
                }
                break;
                
            case (1):
                assert(wMem == 2);
                value = getMemValueNum((uint64_t)addr1, threadID);
                sValues[index++] = value;
                
                value = checkOpcodeValueNum(opinfo->opCode, sValues, index, threadID, ip, opHandle);
                
                gValue++;
                setMemValueNum((uint64_t)addr2, threadID, gValue);
                gValue++;
                setMemValueNum((uint64_t)addr3, threadID, gValue);

                for (int i = 0; i < tRegsCount; i++) {
                    gValue++;
                    setRegValueNum(opinfo->tRegs[i], threadID, gValue);
                }
                break;
                
            case (2):
                assert(wMem == 1);
                value = getMemValueNum((uint64_t)addr1, threadID);
                sValues[index++] = value;
                
                value = getMemValueNum((uint64_t)addr2, threadID);
                sValues[index++] = value;
                
                value = checkOpcodeValueNum(opinfo->opCode, sValues, index, threadID, ip, opHandle);
                
                if (tRegsCount == 0) {
                    setMemValueNum((uint64_t)addr3, threadID, value);
                } else {
                    
                    gValue++;
                    setMemValueNum((uint64_t)addr3, threadID, gValue);
                    
                    for (int i = 0; i < tRegsCount; i++) {
                        gValue++;
                        setRegValueNum(opinfo->tRegs[i], threadID, gValue);
                    }
                }
                break;
                
            case (3):
                assert(wMem == 0);
                value = getMemValueNum((uint64_t)addr1, threadID);
                sValues[index++] = value;
                
                value = getMemValueNum((uint64_t)addr2, threadID);
                sValues[index++] = value;
                
                value = getMemValueNum((uint64_t)addr3, threadID);
                sValues[index++] = value;
                
                value = checkOpcodeValueNum(opinfo->opCode, sValues, index, threadID, ip, opHandle);

                if (tRegsCount == 1) {
                    setRegValueNum(opinfo->tRegs[0], threadID, value);
                } else {
                    
                    for (int i = 0; i < tRegsCount; i++) {
                        gValue++;
                        setRegValueNum(opinfo->tRegs[i], threadID, gValue);
                    }
                }
                break;
                
            default:
                break;
        }
    }
}


VOID valueNumberingMem4(void * op, void * addr1, void * addr2, void * addr3, void * addr4, uint32_t rMem, uint32_t wMem, bool movOrnot, THREADID threadID, void *ip, const uint32_t opHandle){
    
    OPInfo *opinfo = (OPInfo *) op;
    assert(rMem+wMem == 4);
    uint64_t value;

    int sRegsCount = opinfo->sRegs.size();
    int immediateCount = opinfo->immediates.size();
    
    if (movOrnot) {
        printf("MOV with 4 memory addresses evloved!\n");
    } else {

        uint64_t sValues[6];
        int index = 0;

        for(int i = 0;i < sRegsCount;++i)
            sValues[index++] = getRegValueNum(opinfo->sRegs[i], threadID);

        for(int i = 0;i < immediateCount;++i)
            sValues[index++] = opinfo->immediates[i];

        int tRegsCount = opinfo->tRegs.size();

        value = gValue;/////////////////////////////

        switch (rMem) {
            case (0):
                value = checkOpcodeValueNum(opinfo->opCode, sValues, index, threadID, ip, opHandle);
                
                gValue++;
                setMemValueNum((uint64_t)addr1, threadID, gValue);
                gValue++;
                setMemValueNum((uint64_t)addr2, threadID, gValue);
                gValue++;
                setMemValueNum((uint64_t)addr3, threadID, gValue);
                gValue++;
                setMemValueNum((uint64_t)addr4, threadID, gValue);

                
                for (int i = 0; i < tRegsCount; i++) {
                    gValue++;
                    setRegValueNum(opinfo->tRegs[i], threadID, gValue);
                }
                break;
                
            case (1):
                value = getMemValueNum((uint64_t)addr1, threadID);
                sValues[index++] = value;
                
                value = checkOpcodeValueNum(opinfo->opCode, sValues, index, threadID, ip, opHandle);
                
                gValue++;
                setMemValueNum((uint64_t)addr2, threadID, gValue);
                gValue++;
                setMemValueNum((uint64_t)addr3, threadID, gValue);
                gValue++;
                setMemValueNum((uint64_t)addr4, threadID, gValue);

                for (int i = 0; i < tRegsCount; i++) {
                    gValue++;
                    setRegValueNum(opinfo->tRegs[i], threadID, gValue);
                }
                break;
                
            case (2):
                value = getMemValueNum((uint64_t)addr1, threadID);
                sValues[index++] = value;
                
                value = getMemValueNum((uint64_t)addr2, threadID);
                sValues[index++] = value;
                
                value = checkOpcodeValueNum(opinfo->opCode, sValues, index, threadID, ip, opHandle);
                
                gValue++;
                setMemValueNum((uint64_t)addr3, threadID, gValue);
                gValue++;
                setMemValueNum((uint64_t)addr4, threadID, gValue);

                for (int i = 0; i < tRegsCount; i++) {
                    gValue++;
                    setRegValueNum(opinfo->tRegs[i], threadID, gValue);
                }
                break;
                
            case (3):
                value = getMemValueNum((uint64_t)addr1, threadID);
                sValues[index++] = value;
                
                value = getMemValueNum((uint64_t)addr2, threadID);
                sValues[index++] = value;
                
                value = getMemValueNum((uint64_t)addr3, threadID);
                sValues[index++] = value;
                
                value = checkOpcodeValueNum(opinfo->opCode, sValues, index, threadID, ip, opHandle);

                if (tRegsCount == 0) {
                    setMemValueNum((uint64_t)addr4, threadID, value);
                } else {
                    
                    gValue++;
                    setMemValueNum((uint64_t)addr4, threadID, gValue);
                    
                    for (int i = 0; i < tRegsCount; i++) {
                        gValue++;
                        setRegValueNum(opinfo->tRegs[i], threadID, gValue);
                    }
                }
                break;
                
            case (4):
                value = getMemValueNum((uint64_t)addr1, threadID);
                sValues[index++] = value;
                
                value = getMemValueNum((uint64_t)addr2, threadID);
                sValues[index++] = value;
                
                value = getMemValueNum((uint64_t)addr3, threadID);
                sValues[index++] = value;
                
                value = getMemValueNum((uint64_t)addr4, threadID);
                sValues[index++] = value;
                
                value = checkOpcodeValueNum(opinfo->opCode, sValues, index, threadID, ip, opHandle);

                if (tRegsCount == 1) {
                    setRegValueNum(opinfo->tRegs[0], threadID, value);
                } else {
                    
                    for (int i = 0; i < tRegsCount; i++) {
                        gValue++;
                        setRegValueNum(opinfo->tRegs[i], threadID, gValue);
                    }
                }
                break;
                
            default:
                break;
        }
    }
}


// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID * v, const uint32_t opHandle) {
    // Note: predicated instructions are correctly handled as given in PIN's sample example pinatrace.cpp
    
    /* Comment taken from PIN sample :
     Instruments memory accesses using a predicated call, i.e.
     the instrumentation is called iff the instruction will actually be executed.
     
     The IA-64 architecture has explicitly predicated instructions.
     On the IA-32 and Intel(R) 64 architectures conditional moves and REP
     prefixed instructions appear as predicated instructions in Pin. */
    

 
    if (IsIgnorableIns(ins))
        return;

    //if (INS_IsJZ(ins) || INS_IsJNZ(ins))
    //    return;

    //**********************************************
    //compare the opcode and the value number of its operand, check the redundancy
    //what if there is only one REG operand

    THREADID threadID = PIN_ThreadId();

    UINT32 memOpCount = INS_MemoryOperandCount(ins);

    UINT32 rMemCount = 0;
    UINT32 wMemCount = 0;
    vector<int> rMem;
    vector<int> wMem;
    
    for(UINT32 memOp = 0; memOp < memOpCount; memOp++) {
        if (INS_IsMemoryRead(ins)){
            rMemCount++;
            rMem.push_back(memOp);
        }
        if (INS_IsMemoryWrite(ins)){
            wMemCount++;
            wMem.push_back(memOp);
        }
    }
    
    rMem.insert(rMem.end(), wMem.begin(), wMem.end());
    
    memOpCount = rMemCount + wMemCount;

    OPInfo  * opinfo = new OPInfo;
    opinfo->opCode = INS_Opcode(ins);
    
    bool flag = false;

    if(INS_IsMov(ins)){
        
        UINT32 n = INS_OperandCount(ins);

        flag = true;

        for(UINT32 i = 0; i < n; ++i){
            
             if(INS_OperandRead(ins,i)){
                 
                  if(INS_OperandIsReg(ins,i)){
                     REG readReg = INS_OperandReg(ins,i); 
                     opinfo->sRegs.push_back(readReg);
                      
                  }else if(INS_OperandIsImmediate(ins,i)){
                     uint64_t immediate = INS_OperandImmediate(ins,i);
                     opinfo->immediates.push_back(getImmediateValueNum(immediate, threadID));
                     //opinfo->immediates.push_back(immediate);
                  }
             }
             if(INS_OperandWritten(ins,i)){
                 
                  if(INS_OperandIsReg(ins,i)){
                     REG writeReg = INS_OperandReg(ins,i); 
                     opinfo->tRegs.push_back(writeReg);
                  }
             }
        }
    }else{
        
        UINT32 n = INS_OperandCount(ins);
        
        if (n < 1) {
            return;
        }
        
        for(UINT32 i = 0; i < n; ++i){
            
             if(INS_OperandRead(ins,i)){
                 
                  if(INS_OperandIsReg(ins,i)){
                     REG readReg = INS_OperandReg(ins,i); 
                     opinfo->sRegs.push_back(readReg);
                  }else if(INS_OperandIsImmediate(ins,i)){
                     uint64_t immediate = INS_OperandImmediate(ins,i);
                     opinfo->immediates.push_back(getImmediateValueNum(immediate, threadID));
                     //opinfo->immediates.push_back(immediate);
                  }
             }
             if(INS_OperandWritten(ins,i)){
                 
                 if(INS_OperandIsReg(ins,i)){
                     REG write = INS_OperandReg(ins,i);
                     if (write != REG_GFLAGS)
                         opinfo->tRegs.push_back(INS_OperandReg(ins,i));
                 }
             }
        }
    } 
    
    switch(memOpCount){
        case(0):
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)valueNumbering, IARG_PTR, opinfo, IARG_BOOL, flag, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32, opHandle, IARG_END);
            break;
        case(1):
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)valueNumberingMem1, IARG_PTR, opinfo, IARG_MEMORYOP_EA, rMem[0], IARG_ADDRINT, rMemCount, IARG_ADDRINT, wMemCount, IARG_BOOL, flag, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32, opHandle, IARG_END);
            break;
        case(2):
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)valueNumberingMem2, IARG_PTR, opinfo, IARG_MEMORYOP_EA, rMem[0], IARG_MEMORYOP_EA, rMem[1], IARG_ADDRINT, rMemCount, IARG_ADDRINT, wMemCount, IARG_BOOL, flag, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32, opHandle, IARG_END);
            break;
        case(3):
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)valueNumberingMem3, IARG_PTR, opinfo, IARG_MEMORYOP_EA, rMem[0], IARG_MEMORYOP_EA, rMem[1], IARG_MEMORYOP_EA, rMem[2], IARG_ADDRINT, rMemCount, IARG_ADDRINT, wMemCount, IARG_BOOL, flag, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32, opHandle, IARG_END);
            break;
        case(4):
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)valueNumberingMem4, IARG_PTR, opinfo, IARG_MEMORYOP_EA, rMem[0], IARG_MEMORYOP_EA, rMem[1], IARG_MEMORYOP_EA, rMem[2], IARG_MEMORYOP_EA, rMem[3], IARG_ADDRINT, rMemCount, IARG_ADDRINT, wMemCount, IARG_BOOL, flag, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32, opHandle, IARG_END);
            break;
        default:
            assert(memOpCount<5);
            break;
    }
    
}

//
VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v) {
    
    // Get the stack base address:
    ThreadData_t* tdata = new ThreadData_t();
    tdata->opcodeMap.set_empty_key("");
    tdata->IPstring.set_empty_key(-1);
    tdata->redundantMap.set_empty_key(-1);
 
    // Label will be NULL
    PIN_SetThreadData(tls_key, tdata, threadid);
}


inline bool MergedRedundantInfoComparer(const RedundantInfoForPresentation & first, const RedundantInfoForPresentation  &second) {
    return first.count > second.count ? true : false;
}

static void DumpInfo(uint32_t oldIndex, uint32_t  newIndex){
    PIN_LockClient();
    fprintf(gTraceFile, "\n ----------");
    PrintFullCallingContext(newIndex);
    fprintf(gTraceFile, "\n *****is redundant because of*****");
    PrintFullCallingContext(oldIndex);
    fprintf(gTraceFile, "\n ----------");
    PIN_UnlockClient();
}

VOID ImageUnload(IMG img, VOID * v) {
    fprintf(gTraceFile, "\nUnloading %s", IMG_Name(img).c_str());
        
    ThreadData_t * td = GetTLS(PIN_ThreadId ());
    PIN_MutexLock(&gMutex);

    dense_hash_map<uint64_t, uint64_t>::iterator mapIt = td->redundantMap.begin();

    // Push it all into a List so that it can be sorted.
    // No 2 pairs will ever be same since they are unique across threads
    for (; mapIt != td->redundantMap.end(); mapIt++) {
        if(mapIt->second >= MAX_DEAD_CONTEXTS_TO_LOG){
            RedundantInfoForPresentation redundantInfoForPresentation;
            redundantInfoForPresentation.key = mapIt->first;
            redundantInfoForPresentation.count = mapIt->second;
            gRedundantList.push_back(redundantInfoForPresentation);
        }
    }
    // clear dead map now
    td->redundantMap.clear();
    td->immediateMap.clear();
    td->opcodeMap.clear();    
    gRedundantList.sort(MergedRedundantInfoComparer);
    
    //present and delete all
    list<RedundantInfoForPresentation>::iterator dipIter = gRedundantList.begin();
    int redundancyWrite = 0;
    for (; dipIter != gRedundantList.end(); dipIter++) {
        // Print just first MAX_DEAD_CONTEXTS_TO_LOG contexts
        if(redundancyWrite<MAX_LOG_NUM){
            redundancyWrite++;
            fprintf(gTraceFile,"\nCTXT_REDUNDANT_CNT:%lu",dipIter->count);
            DumpInfo(dipIter->key >> 32, dipIter->key & 0xffffffff);
        }
    }
    
    
    gRedundantList.clear();
    
    PIN_MutexUnlock(&gMutex);
    
}

VOID RegDeadFini(INT32 code, VOID * v){
    fprintf(gTraceFile,"\nfinish");    
}

INT32 Usage() {
    PIN_ERROR("PinTool for dynamic valueNumbering.\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

// Initialized the needed data structures before launching the target program
void InitValueNumbering(int argc, char *argv[]){
    
    // Create output file
    
    char name[MAX_FILE_PATH] = "ValueNumbering.out.";
    char * envPath = getenv("OUTPUT_FILE");
    if(envPath){
        // assumes max of MAX_FILE_PATH
        strcpy(name, envPath);
    }
    gethostname(name + strlen(name), MAX_FILE_PATH - strlen(name));
    pid_t pid = getpid();
    sprintf(name + strlen(name),"%d",pid);
    cerr << "\n Creating info file at:" << name << "\n";
    
    gTraceFile = fopen(name, "w");
    // print the arguments passed
    fprintf(gTraceFile,"\n");
    for(int i = 0 ; i < argc; i++){
        fprintf(gTraceFile,"%s ",argv[i]);
    }
    fprintf(gTraceFile,"\n");
    
    // Obtain  a key for TLS storage.
    tls_key = PIN_CreateThreadDataKey(0);

    //initilize the global value used for value numbering
    gValue = 0;
    
    // Register ThreadStart to be called when a thread starts.
    PIN_AddThreadStartFunction(ThreadStart, 0);
    
    // INitialize the mutex
    PIN_MutexInit (&gMutex);

    
    // Register ImageUnload to be called when the image is unloaded
    IMG_AddUnloadFunction(ImageUnload, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(RegDeadFini, 0);
    
}


// Main for Value Numbering, initialize the tool, register instrumentation functions and call the target program.

int main(int argc, char *argv[]) {
    
    // Initialize PIN
    if (PIN_Init(argc, argv))
        return Usage();
    
    // Initialize Symbols, we need them to report functions and lines
    PIN_InitSymbols();
    
    // Intialize Value Numbering
    InitValueNumbering(argc, argv);
    
    // Init CCTlib
    PinCCTLibInit(INTERESTING_INS_ALL, gTraceFile, Instruction, 0, false);
    
    
    // When line level info in not needed, simplt instrument each instruction
    //INS_AddInstrumentFunction(, 0);
    
    
    // Launch program now
    PIN_StartProgram();
    return 0;
}
