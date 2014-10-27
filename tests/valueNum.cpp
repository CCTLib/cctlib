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

#include "cctlib.cpp"
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
#define MAX_OPERAND (10)

namespace __gnu_cxx
{
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


class ThreadData_t {
public:
    uint64_t regNumber[REG_LAST];
    hash_map<uint64_t, uint64_t> immediateMap;
    hash_map<uint64_t, uint64_t>::iterator immediateMapIt;
    hash_map<uint64_t, uint64_t> memoryMap;
    hash_map<uint64_t, uint64_t>::iterator memoryMapIt;
    
    hash_map<string, uint64_t> opcodeMap;
    hash_map<string, uint64_t>::iterator opcodeMapIt;
    map<string, uint32_t> opcodeContext;
    map<string, uint32_t>::iterator opcodeContextIt;

    hash_map<uint64_t, uint64_t> redundantMap;
    hash_map<uint64_t, uint64_t>::iterator redundantMapIt;

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
ThreadData_t* GetTLS(THREADID threadid)
{
    ThreadData_t* tdata =
    static_cast<ThreadData_t*>(PIN_GetThreadData(tls_key, threadid));
    return tdata;
}

void UpdateValue(uint32_t reg, ThreadData_t * td, uint64_t value) {

   /* switch (reg) {
        case REG_GAX:
        case REG_EAX:
        case REG_AX:
            td->regNumber[REG_GAX] = td->regNumber[REG_EAX] = td->regNumber[REG_AX] = td->regNumber[REG_AL] = td->regNumber[REG_AH] = value;
            break;
        case REG_AH:
            td->regNumber[REG_GAX] = td->regNumber[REG_EAX] = td->regNumber[REG_AX] = td->regNumber[REG_AH] = value;
            break;
        case REG_AL:
            td->regNumber[REG_GAX] = td->regNumber[REG_EAX] = td->regNumber[REG_AX] = td->regNumber[REG_AL] = value;
            break;
            
            
        case REG_GBX:
        case REG_EBX:
        case REG_BX:
            td->regNumber[REG_GBX] = td->regNumber[REG_EBX] = td->regNumber[REG_BX] = td->regNumber[REG_BL] = td->regNumber[REG_BH] = value;
            break;
        case REG_BH:
            td->regNumber[REG_GBX] = td->regNumber[REG_EBX] = td->regNumber[REG_BX] = td->regNumber[REG_BH] = value;
            break;
        case REG_BL:
            td->regNumber[REG_GBX] = td->regNumber[REG_EBX] = td->regNumber[REG_BX] = td->regNumber[REG_BL] = value;
            break;
            
        case REG_GCX:
        case REG_ECX:
        case REG_CX:
            td->regNumber[REG_GCX] = td->regNumber[REG_ECX] = td->regNumber[REG_CX] = td->regNumber[REG_CL] = td->regNumber[REG_CH] = value;
            break;
        case REG_CH:
            td->regNumber[REG_GCX] = td->regNumber[REG_ECX] = td->regNumber[REG_CX] = td->regNumber[REG_CH] = value;
            break;
        case REG_CL:
            td->regNumber[REG_GCX] = td->regNumber[REG_ECX] = td->regNumber[REG_CX] = td->regNumber[REG_CL] = value;
            break;
            
        case REG_GDX:
        case REG_EDX:
        case REG_DX:
            td->regNumber[REG_GDX] = td->regNumber[REG_EDX] = td->regNumber[REG_DX] = td->regNumber[REG_DL] = td->regNumber[REG_DH] = value;
            break;
        case REG_DH:
            td->regNumber[REG_GDX] = td->regNumber[REG_EDX] = td->regNumber[REG_DX] = td->regNumber[REG_DH] = value;
            break;
        case REG_DL:
            td->regNumber[REG_GDX] = td->regNumber[REG_EDX] = td->regNumber[REG_DX] = td->regNumber[REG_DL] = value;
            break;
            
        default:
            td->regNumber[reg] = value;
    }*/
    td->regNumber[reg] = value;
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
uint64_t getMemValueNum(uint64_t addr, THREADID threadid)
{
    /*uint8_t* status = GetOrCreateShadowBaseAddress(addr);
    uint64_t *prevAddr = (uint64_t *)(status + PAGE_SIZE +  PAGE_OFFSET(addr) * sizeof(uint64_t));
    if(*prevAddr==0)
    {
        gValue++;
        *prevAddr = gValue;
    }
    return *prevAddr;*/
    
    ThreadData_t * td = GetTLS(threadid);
    td->memoryMapIt = td->memoryMap.find(addr);
    if(td->memoryMapIt == td->memoryMap.end())
    {
        gValue++;
        td->memoryMap.insert(std::pair<uint64_t, uint64_t>(addr,gValue));
//fprintf(gTraceFile,"get memory %lu value number gvalue:%lu\n",addr,gValue);
        return gValue;
    }
//fprintf(gTraceFile,"get memory %lu value number:%lu\n",addr,td->memoryMapIt->second);
    return td->memoryMapIt->second;
}


//get the value number from the register
uint64_t getRegValueNum(REG reg, THREADID threadid)
{
    ThreadData_t * td = GetTLS(threadid);
    if(td->regNumber[reg] == 0)
    {
        gValue++;
        UpdateValue(reg, td, gValue);
    }
//fprintf(gTraceFile,"get register %d value number:%lu\n",reg,td->regNumber[reg]);
    return td->regNumber[reg];
}

//set a new value number to the memory
VOID setMemValueNum(uint64_t addr, THREADID threadid, uint64_t value)
{
    /*ThreadData_t * td = GetTLS(threadid);
    uint64_t val = value;
    
    uint8_t* status = GetOrCreateShadowBaseAddress(addr);
    uint64_t *prevAddr = (uint64_t *)(status + PAGE_SIZE +  PAGE_OFFSET(addr) * sizeof(uint64_t));
    *prevAddr = val;*/
    ThreadData_t * td = GetTLS(threadid);
    td->memoryMapIt = td->memoryMap.find(addr);
//fprintf(gTraceFile,"set memory %lu value number:%lu\n",addr,value);
    if(td->memoryMapIt == td->memoryMap.end())
        td->memoryMap.insert(std::pair<uint64_t, uint64_t>(addr,value));
    else
        td->memoryMapIt->second = value;
}

//set a new value number to the register
VOID setRegValueNum(REG reg, THREADID threadid, uint64_t value)
{
    ThreadData_t * td = GetTLS(threadid);
//fprintf(gTraceFile,"set register %d value number:%lu\n",reg,value);
    UpdateValue(reg, td, value);
}


//get the value number for the immediate data
uint64_t getImmediateValueNum(uint64_t immediate, THREADID threadid)
{
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


void recordRedundantOperation(uint32_t deadCtxt, uint32_t killerCtxt, ThreadData_t * td) {
    /*if(deadCtxt == killerCtxt)
        fprintf(gTraceFile,"The instruction is redundant with itself?%d\n",deadCtxt);*/
    uint64_t deadIndex = (uint64_t)deadCtxt;
    uint64_t killerIndex = (uint64_t)killerCtxt;
    uint64_t key = (deadIndex << 32) | killerIndex;

    if ( (td->redundantMapIt = td->redundantMap.find(key))  == td->redundantMap.end()) {
        td->redundantMap.insert(std::pair<uint64_t, uint64_t>(key,1));
    } else {
        (td->redundantMapIt->second) += 1;
    }
}

void checkMovValueNum(int opcode, uint64_t svalue, uint64_t target, THREADID threadid, const uint32_t opHandle){

    ThreadData_t * td = GetTLS(threadid);
    uint32_t curCtxt = GetContextHandle(threadid, opHandle);

    string str = to_string(opcode);
    str += "_";
    str += to_string(svalue);
    str += "_";
    str += to_string(target);
    
    td->opcodeContextIt = td->opcodeContext.find(str);
    if(td->opcodeContextIt == td->opcodeContext.end()){
        td->opcodeContext.insert(pair<string, uint32_t>(str, curCtxt));
        return;
    }
    recordRedundantOperation(td->opcodeContextIt->second, curCtxt, td);
}

//get the value number of the opcode and check the redundancy
uint64_t checkOpcodeValueNum(int op, vector<uint64_t> * svalues, THREADID threadid, const uint32_t opHandle)
{
    ThreadData_t * td = GetTLS(threadid);
    uint32_t curCtxt = GetContextHandle(threadid, opHandle);

    int sCount = (* svalues).size();

    if(sCount == 0)
        return gValue++;
    
    /***********  sort vector ***************/
    if(op != XED_ICLASS_DIV)
        sort((* svalues).begin(),(* svalues).begin()+sCount);

    string str = to_string(op);
    
    for(int i = 0; i<sCount; i++)
    {
        str +="_";
        str += to_string((* svalues)[i]);
    }

    td->opcodeMapIt = td->opcodeMap.find(str);
    if(td->opcodeMapIt == td->opcodeMap.end())
    {
        gValue++;
        td->opcodeMap.insert(std::pair<string, uint64_t>(str,gValue));
        td->opcodeContext.insert(pair<string, uint32_t>(str,curCtxt));
/*PIN_LockClient();
fprintf(gTraceFile,"string %s --------%lu---------%d\n",str.c_str(), gValue, curCtxt);
PrintFullCallingContext(curCtxt);
fprintf(gTraceFile,"\n");
PIN_UnlockClient();*/
        return gValue;
    }
    td->opcodeContextIt = td->opcodeContext.find(str);
/*PIN_LockClient();
fprintf(gTraceFile,"string %s --------%lu----------%d\n",str.c_str(), td->opcodeMapIt->second,td->opcodeContextIt->second);
PrintFullCallingContext(curCtxt);
fprintf(gTraceFile,"\n");
PIN_UnlockClient();*/
    recordRedundantOperation(td->opcodeContextIt->second, curCtxt,td);
    return td->opcodeMapIt->second;
}


VOID valueNumbering(void * op, bool movOrnot, THREADID threadID, const uint32_t opHandle){
    OPInfo * opinfo = (OPInfo *) op;
    uint64_t value;
    int sRegsCount = opinfo->sRegs.size();
    int immediateCount = opinfo->immediates.size();

    if (movOrnot) {

        if(sRegsCount == 1)
            value = getRegValueNum(opinfo->sRegs[0], threadID);
        else if(immediateCount == 1)
            value = getImmediateValueNum(opinfo->immediates[0], threadID);

        setRegValueNum(opinfo->tRegs[0],threadID,value);
    } else {
        vector<uint64_t> sValues;

        for(int i = 0;i < sRegsCount;++i)
            sValues.push_back(getRegValueNum(opinfo->sRegs[i], threadID));

        for(int i = 0;i < immediateCount;++i)
            sValues.push_back(getImmediateValueNum(opinfo->immediates[i], threadID));
        
        value = checkOpcodeValueNum(opinfo->opCode, &sValues, threadID, opHandle);

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

VOID valueNumberingMem1(void * op, void * addr, uint32_t rMem, uint32_t wMem, bool movOrnot, THREADID threadID, const uint32_t opHandle){
    
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

            //checkMovValueNum(opinfo->opCode, value, opinfo->tRegs[0], threadID, opHandle);
        } else {
            assert(sRegsCount == 1);
            if(sRegsCount == 1)
                value = getRegValueNum(opinfo->sRegs[0], threadID);
            else if(immediateCount == 1)
                value = getImmediateValueNum(opinfo->immediates[0], threadID);

            setMemValueNum((uint64_t)addr, threadID, value);
            checkMovValueNum(opinfo->opCode, value, (uint64_t)addr, threadID, opHandle);
        }
    } else {

        vector<uint64_t> sValues;

        for(int i = 0;i < sRegsCount;++i)
            sValues.push_back(getRegValueNum(opinfo->sRegs[i], threadID));

        for(int i = 0;i < immediateCount;++i)
            sValues.push_back(getImmediateValueNum(opinfo->immediates[i], threadID));

        int tRegsCount = opinfo->tRegs.size();

        if (rMem == 1) {

            value = getMemValueNum((uint64_t)addr, threadID);
            sValues.push_back(value);
            
            value = checkOpcodeValueNum(opinfo->opCode, &sValues, threadID, opHandle);
            
            if (tRegsCount == 1) {
                setRegValueNum(opinfo->tRegs[0], threadID, value);
            } else {
                for (int i = 0; i < tRegsCount; i++) {
                    gValue++;
                    setRegValueNum(opinfo->tRegs[i], threadID, gValue);
                }
            }
            
        } else {

            value = checkOpcodeValueNum(opinfo->opCode, &sValues, threadID, opHandle);
        
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

VOID valueNumberingMem2(void * op, void * addr1, void * addr2, uint32_t rMem, uint32_t wMem, bool movOrnot, THREADID threadID, const uint32_t opHandle){
    
    OPInfo *opinfo = (OPInfo *) op;
    assert(rMem+wMem == 2);
    uint64_t value;

    int sRegsCount = opinfo->sRegs.size();
    int immediateCount = opinfo->immediates.size();
    
    if (movOrnot) {
        if (rMem == 1 && wMem == 1) {
            value = getMemValueNum((uint64_t)addr1, threadID);
            setMemValueNum((uint64_t)addr2, threadID, value);
            checkMovValueNum(opinfo->opCode, value, (uint64_t)addr2, threadID, opHandle);
        }
    } else {

        vector<uint64_t> sValues;

        for(int i = 0;i < sRegsCount;++i)
            sValues.push_back(getRegValueNum(opinfo->sRegs[i], threadID));

        for(int i = 0;i < immediateCount;++i)
            sValues.push_back(getImmediateValueNum(opinfo->immediates[i], threadID));

        int tRegsCount = opinfo->tRegs.size();

        if (rMem == 0){
            
            value = checkOpcodeValueNum(opinfo->opCode, &sValues, threadID, opHandle);
            
            assert(wMem == 2);
            gValue++;
            setMemValueNum((uint64_t)addr1, threadID, gValue);
            gValue++;
            setMemValueNum((uint64_t)addr2, threadID, gValue);
            
        }else if (rMem == 1) {
            assert(wMem == 1);
            value = getMemValueNum((uint64_t)addr1, threadID);
            sValues.push_back(value);
            
            value = checkOpcodeValueNum(opinfo->opCode, &sValues, threadID, opHandle);
           
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
            sValues.push_back(value);
            
            value = getMemValueNum((uint64_t)addr2, threadID);
            sValues.push_back(value);


            value = checkOpcodeValueNum(opinfo->opCode, &sValues, threadID, opHandle);

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


VOID valueNumberingMem3(void * op, void * addr1, void * addr2, void * addr3, uint32_t rMem, uint32_t wMem, bool movOrnot, THREADID threadID, const uint32_t opHandle){
    
    OPInfo *opinfo = (OPInfo *) op;
    assert(rMem+wMem == 3);
    uint64_t value;

    int sRegsCount = opinfo->sRegs.size();
    int immediateCount = opinfo->immediates.size();
    
    if (movOrnot) {
        printf("MOV with 3 memory addresses evloved!\n");
    } else {

        vector<uint64_t> sValues;

        for(int i = 0;i < sRegsCount;++i)
            sValues.push_back(getRegValueNum(opinfo->sRegs[i], threadID));

        for(int i = 0;i < immediateCount;++i)
            sValues.push_back(getImmediateValueNum(opinfo->immediates[i], threadID));

        int tRegsCount = opinfo->tRegs.size();

        switch (rMem) {
            case (0):
                assert(wMem == 3);
                value = checkOpcodeValueNum(opinfo->opCode, &sValues, threadID, opHandle);
                
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
                sValues.push_back(value);
                
                value = checkOpcodeValueNum(opinfo->opCode, &sValues, threadID, opHandle);
                
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
                sValues.push_back(value);
                
                value = getMemValueNum((uint64_t)addr2, threadID);
                sValues.push_back(value);
                
                value = checkOpcodeValueNum(opinfo->opCode, &sValues, threadID, opHandle);
                
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
                sValues.push_back(value);
                
                value = getMemValueNum((uint64_t)addr2, threadID);
                sValues.push_back(value);
                
                value = getMemValueNum((uint64_t)addr3, threadID);
                sValues.push_back(value);
                
                value = checkOpcodeValueNum(opinfo->opCode, &sValues, threadID, opHandle);

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


VOID valueNumberingMem4(void * op, void * addr1, void * addr2, void * addr3, void * addr4, uint32_t rMem, uint32_t wMem, bool movOrnot, THREADID threadID,  const uint32_t opHandle){
    
    OPInfo *opinfo = (OPInfo *) op;
    assert(rMem+wMem == 4);
    uint64_t value;

    int sRegsCount = opinfo->sRegs.size();
    int immediateCount = opinfo->immediates.size();
    
    if (movOrnot) {
        printf("MOV with 4 memory addresses evloved!\n");
    } else {

        vector<uint64_t> sValues;

        for(int i = 0;i < sRegsCount;++i)
            sValues.push_back(getRegValueNum(opinfo->sRegs[i], threadID));

        for(int i = 0;i < immediateCount;++i)
            sValues.push_back(getImmediateValueNum(opinfo->immediates[i], threadID));

        int tRegsCount = opinfo->tRegs.size();

        switch (rMem) {
            case (0):
                value = checkOpcodeValueNum(opinfo->opCode, &sValues, threadID, opHandle);
                
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
                sValues.push_back(value);
                
                value = checkOpcodeValueNum(opinfo->opCode, &sValues, threadID, opHandle);
                
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
                sValues.push_back(value);
                
                value = getMemValueNum((uint64_t)addr2, threadID);
                sValues.push_back(value);
                
                value = checkOpcodeValueNum(opinfo->opCode, &sValues, threadID, opHandle);
                
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
                sValues.push_back(value);
                
                value = getMemValueNum((uint64_t)addr2, threadID);
                sValues.push_back(value);
                
                value = getMemValueNum((uint64_t)addr3, threadID);
                sValues.push_back(value);
                
                value = checkOpcodeValueNum(opinfo->opCode, &sValues, threadID, opHandle);

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
                sValues.push_back(value);
                
                value = getMemValueNum((uint64_t)addr2, threadID);
                sValues.push_back(value);
                
                value = getMemValueNum((uint64_t)addr3, threadID);
                sValues.push_back(value);
                
                value = getMemValueNum((uint64_t)addr4, threadID);
                sValues.push_back(value);
                
                value = checkOpcodeValueNum(opinfo->opCode, &sValues, threadID, opHandle);

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

    //THREADID threadID = PIN_ThreadId();

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
                     opinfo->immediates.push_back(immediate);
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
                     opinfo->immediates.push_back(immediate);
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
        
        /*if(opinfo->opCode == 7 || opinfo->opCode == 651 || opinfo->opCode == 82)
        {
           printf("opcode %d -- mem read: %d -- mem write: %d -- source values: %d -- tvalues: %d\n",opinfo->opCode, rMemCount, wMemCount, opinfo->sValueCount, opinfo->tRegsCount);
           //for(int i = 0; i< opinfo->tRegsCount;++i)
           //    printf("target register: %d\n",opinfo->tRegs[i]);
        }*/
    } 
    
    switch(memOpCount){
        case(0):
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)valueNumbering, IARG_PTR, opinfo, IARG_BOOL, flag, IARG_THREAD_ID, IARG_UINT32, opHandle, IARG_END);
            break;
        case(1):
//fprintf(gTraceFile,"source value count:%p\n",opinfo);
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)valueNumberingMem1, IARG_PTR, opinfo, IARG_MEMORYOP_EA, rMem[0], IARG_ADDRINT, rMemCount, IARG_ADDRINT, wMemCount, IARG_BOOL, flag, IARG_THREAD_ID, IARG_UINT32, opHandle, IARG_END);
            break;
        case(2):
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)valueNumberingMem2, IARG_PTR, opinfo, IARG_MEMORYOP_EA, rMem[0], IARG_MEMORYOP_EA, rMem[1], IARG_ADDRINT, rMemCount, IARG_ADDRINT, wMemCount, IARG_BOOL, flag, IARG_THREAD_ID, IARG_UINT32, opHandle, IARG_END);
            break;
        case(3):
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)valueNumberingMem3, IARG_PTR, opinfo, IARG_MEMORYOP_EA, rMem[0], IARG_MEMORYOP_EA, rMem[1], IARG_MEMORYOP_EA, rMem[2], IARG_ADDRINT, rMemCount, IARG_ADDRINT, wMemCount, IARG_BOOL, flag, IARG_THREAD_ID, IARG_UINT32, opHandle, IARG_END);
            break;
        case(4):
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)valueNumberingMem4, IARG_PTR, opinfo, IARG_MEMORYOP_EA, rMem[0], IARG_MEMORYOP_EA, rMem[1], IARG_MEMORYOP_EA, rMem[2], IARG_MEMORYOP_EA, rMem[3], IARG_ADDRINT, rMemCount, IARG_ADDRINT, wMemCount, IARG_BOOL, flag, IARG_THREAD_ID, IARG_UINT32, opHandle, IARG_END);
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
    hash_map<uint64_t, uint64_t>::iterator mapIt = td->redundantMap.begin();

    // Push it all into a List so that it can be sorted.
    // No 2 pairs will ever be same since they are unique across threads
    for (; mapIt != td->redundantMap.end(); mapIt++) {
        RedundantInfoForPresentation redundantInfoForPresentation;
        redundantInfoForPresentation.key = mapIt->first;
        redundantInfoForPresentation.count = mapIt->second;
        gRedundantList.push_back(redundantInfoForPresentation);
    }
    // clear dead map now
    td->redundantMap.clear();
    td->immediateMap.clear();
    td->opcodeMap.clear();
    td->opcodeContext.clear();
    
    gRedundantList.sort(MergedRedundantInfoComparer);
    
    //present and delete all
    list<RedundantInfoForPresentation>::iterator dipIter = gRedundantList.begin();
    for (; dipIter != gRedundantList.end(); dipIter++) {
        // Print just first MAX_DEAD_CONTEXTS_TO_LOG contexts
        if(dipIter->count >= MAX_DEAD_CONTEXTS_TO_LOG){
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
