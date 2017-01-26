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
#include <sys/time.h>
#include <sys/resource.h>
#include "pin.H"
using namespace std;

INT32 Usage2() {
    PIN_ERROR("Pin tool to gather calling context on each load and store.\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

// Main for RedSpy, initialize the tool, register instrumentation functions and call the target program.
static FILE* gTraceFile;


#define CACHE_LINE_BITS (6)
#define CACHE_INDEX_BITS (20)
#define CACHE_WAY_BITS (3)


#define CACHE_SZ (1L<< (CACHE_LINE_BITS + CACHE_INDEX_BITS))
#define CACHE_NUM_WAYS (1L<< CACHE_WAY_BITS)
#define CACHE_LINE_SZ (1L << CACHE_LINE_BITS)
#define CACHE_LINE_MASK (CACHE_LINE_SZ-1)

#define CACHE_LINE_BASE(addr) ((size_t)(addr) & (~CACHE_LINE_MASK))

#define CACHE_NUM_LINES (CACHE_SZ/CACHE_LINE_SZ)
#define CACHE_TAG_MASK (~CACHE_LINE_MASK)
#define CACHE_TAG(address) (((size_t)address) & CACHE_TAG_MASK)
#define CACHE_LINE_INDEX(address)  (((size_t)(address) & (CACHE_SZ - 1)) >> CACHE_LINE_BITS)
#define IS_VALID(index, address) (cache[index].isInUse &&  (cache[index].tag == CACHE_TAG(((size_t)address))))
#define IS_INUSE(index) (cache[index].isInUse)



#define SET_TAG(index, address) (cache[index].tag = CACHE_TAG(address))
#define SET_DIRTY(index) (cache[index].isDirty = true)
#define SET_CLEAN(index) (cache[index].isDirty = false)
#define SET_ISZERO(index) (cache[index].isZero = true)

#define IS_DIRTY(index) (cache[index].isDirty)

#define SET_INUSE(index) (cache[index].isInUse = true)
#define GET_TAG(index) (cache[index].tag)
#define WAS_DIFFERENT(index) (cache[index].wasDifferent)
#define SET_ACCESSTIME(index) (cache[index].lastAcceessTime = accessTime)

#define SHADOW_CACHE_INDEX_BITS (16)
#define SHADOW_CACHE_SZ (1L<< (CACHE_LINE_BITS + SHADOW_CACHE_INDEX_BITS))
#define SHADOW_CACHE_LINE_MASK (CACHE_LINE_SZ-1)
#define SHADOW_CACHE_TAG_MASK (~SHADOW_CACHE_LINE_MASK)
#define SHADOW_CACHE_TAG(address) (((size_t)address) & SHADOW_CACHE_TAG_MASK)

#define SHADOW_CACHE_NUM_WAYS (CACHE_NUM_WAYS)
#define SHADOW_CACHE_NUM_LINES (SHADOW_CACHE_SZ/CACHE_LINE_SZ)
#define SHADOW_CACHE_LINE_INDEX(address)  (((size_t)(address) & (SHADOW_CACHE_SZ - 1)) >> CACHE_LINE_BITS)
#define SHADOW_IS_VALID(idx, tag) (shadowCache[idx].isInUse &&  (shadowCache[idx].tag == tag))
#define SHADOW_SET_TAG(index, address) (shadowCache[index].tag = SHADOW_CACHE_TAG(address))
#define SHADOW_SET_INUSE(index) (shadowCache[index].isInUse = true)
#define SHADOW_GET_TAG(index) (shadowCache[index].tag)
#define SHADOW_IS_INUSE(index) (shadowCache[index].isInUse)
#define SHADOW_WAS_REDUNDANT(index) (shadowCache[index].wasRedundant)


#define MAX_WRITE_OP_LENGTH (512)
#define MAX_WRITE_OPS_IN_INS (8)

//#define DO_REDSPY


struct Cache_t{
    size_t tag;
    bool isDirty;
    bool isInUse;
    bool isZero;
    bool wasDifferent;
    uint8_t value[CACHE_LINE_SZ];
    uint64_t lastAcceessTime;
    Cache_t(): tag(-1), isDirty(false), isInUse(false), isZero(false), wasDifferent(false), lastAcceessTime(0) {}
    void ReInit(){
        tag = -1;
        isDirty = false;
        isInUse = false;
        wasDifferent = false;
        lastAcceessTime = 0;
        isZero = false;
    }
};

struct ShadowCache_t{
    size_t tag;
    bool isInUse;
    bool wasRedundant;
    uint64_t lastAcceessTime;
    uint8_t value[CACHE_LINE_SZ];
    ShadowCache_t(): tag(-1), isInUse(false), wasRedundant(false), lastAcceessTime(0) {}
    void ReInit(){
        tag = -1;
        isInUse = false;
        wasRedundant = false;
        lastAcceessTime = 0;
    }
};

struct Stats_t{
    uint64_t sameData;
    uint64_t evicts;
    uint64_t unchanged;
    uint64_t dirtyEvicts;
    uint64_t shadowDetects;
    uint64_t zeroDetect;
    Stats_t() : sameData(0), evicts(0), unchanged(0), dirtyEvicts(0), shadowDetects(0), zeroDetect(0) {}
};

struct AddrValPair{
    void * address;
    uint8_t value[MAX_WRITE_OP_LENGTH];
};

struct RedSpyThreadData{
    AddrValPair buffer[MAX_WRITE_OPS_IN_INS];
    uint64_t bytesWritten;
    uint64_t bytesRedundant;
};

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


//thread_local Stats_t stats;
//thread_local Cache_t cache[CACHE_NUM_LINES];
//thread_local ShadowCache_t shadowCache[SHADOW_CACHE_NUM_LINES];
 Stats_t stats;
 Cache_t cache[CACHE_NUM_LINES];
 ShadowCache_t shadowCache[SHADOW_CACHE_NUM_LINES];

uint64_t accessTime;

enum LineStatus{CACHED, EMPTY, OCCUPIED};

LineStatus IsCached(uint64_t address, uint64_t &cacheLineIdx){
    uint64_t baseAddr = CACHE_LINE_BASE(address);
    uint64_t tag = CACHE_TAG(baseAddr);
    // Most likely place
    cacheLineIdx = CACHE_LINE_INDEX(baseAddr);
    if (IS_VALID(cacheLineIdx, tag))
        return CACHED;
    
    uint64_t idxAvailable = UINT64_MAX;
    uint64_t oldest = cacheLineIdx;
    
    // Search the N-ways
    const uint64_t stride = CACHE_NUM_LINES / CACHE_NUM_WAYS;
    
    for(int i = 0; i < CACHE_NUM_WAYS-1; i++) {
        cacheLineIdx = (cacheLineIdx + stride) % CACHE_NUM_LINES;
        if (IS_VALID(cacheLineIdx, tag))
            return CACHED;
        if ( (idxAvailable != UINT64_MAX) && (!IS_INUSE(cacheLineIdx))){
            idxAvailable = cacheLineIdx;
        }
        if (cache[cacheLineIdx].lastAcceessTime < cache[oldest].lastAcceessTime){
            oldest = cacheLineIdx;
        }
    }
    
    if(idxAvailable != UINT64_MAX){
        cacheLineIdx = idxAvailable;
        return EMPTY;
    } else {
        cacheLineIdx = oldest;
        return OCCUPIED;
    }
}


bool HasDataChanged(uint64_t shadowCacheLineIdx){
    uint8_t * originalData = shadowCache[shadowCacheLineIdx].value;
    uint8_t * curData = (uint8_t *) shadowCache[shadowCacheLineIdx].tag;
    
    for (int i = 0; i < CACHE_LINE_SZ; i++) {
        if(originalData[i] != curData[i]){
            return true;
        }
    }
    return false;
}

LineStatus IsShadowCached(uint64_t tag, uint64_t &shadowCacheLineIdx){
    // Most likely place
    shadowCacheLineIdx = SHADOW_CACHE_LINE_INDEX(tag);
    if (SHADOW_IS_VALID(shadowCacheLineIdx, tag))
        return CACHED;
    
    uint64_t idxAvailable = UINT64_MAX;
    uint64_t preferred = UINT64_MAX;
    uint64_t oldest = shadowCacheLineIdx;
    uint64_t mostPreferred = UINT64_MAX;
    uint64_t dataChangedIndex = UINT64_MAX;
    
    // Search the N-ways
    const uint64_t stride = SHADOW_CACHE_NUM_LINES / SHADOW_CACHE_NUM_WAYS;
    
    for(int i = 0; i < SHADOW_CACHE_NUM_WAYS-1; i++) {
        shadowCacheLineIdx = (shadowCacheLineIdx + stride) % SHADOW_CACHE_NUM_LINES;
        if (SHADOW_IS_VALID(shadowCacheLineIdx, tag))
            return CACHED;
        
        if ( (mostPreferred != UINT64_MAX) && (!SHADOW_IS_INUSE(shadowCacheLineIdx) && SHADOW_WAS_REDUNDANT(shadowCacheLineIdx))){
            mostPreferred = shadowCacheLineIdx;
        }
        
        if ( (idxAvailable != UINT64_MAX)  && (!SHADOW_IS_INUSE(shadowCacheLineIdx))){
            idxAvailable = shadowCacheLineIdx;
        }
        
        if ((dataChangedIndex != UINT64_MAX) && (SHADOW_IS_INUSE(shadowCacheLineIdx) && HasDataChanged(shadowCacheLineIdx))){
            dataChangedIndex = shadowCacheLineIdx;
        }
        
        if (shadowCache[shadowCacheLineIdx].lastAcceessTime < shadowCache[oldest].lastAcceessTime){
            oldest = shadowCacheLineIdx;
        }
    }
    
    if(mostPreferred != UINT64_MAX){
        shadowCacheLineIdx = mostPreferred;
        return EMPTY;
    }
    
    if(idxAvailable != UINT64_MAX){
        shadowCacheLineIdx = idxAvailable;
        return EMPTY;
    }
    
    if(dataChangedIndex != UINT64_MAX){
        shadowCacheLineIdx = dataChangedIndex;
        return OCCUPIED;
    }
    
    shadowCacheLineIdx = oldest;
    return OCCUPIED;
}


void CacheFlush(){
#pragma omp simd
    for(int i = 0; i < CACHE_NUM_LINES; i++){
        cache[i].ReInit();
    }
    
#pragma omp simd
    for(int i = 0; i < SHADOW_CACHE_NUM_LINES; i++){
        shadowCache[i].ReInit();
    }
}

static inline void Allocate(uint64_t addr, uint64_t index) {
    uint64_t address = CACHE_LINE_BASE((uint64_t)addr);
    uint8_t * newValue = (uint8_t *) (address);
    uint8_t * originalVal = cache[index].value;
    SET_CLEAN(index);
    SET_TAG(index, address);
    WAS_DIFFERENT(index) = false;
    SET_INUSE(index);

    

    bool isAllZero = true;
#pragma omp simd
    for(int i = 0; i < CACHE_LINE_SZ; i++){
        originalVal[i] = newValue[i];
        if(newValue[i] != 0)
            isAllZero = false;
    }
    
    if(isAllZero)
        SET_ISZERO(index);
}


static inline void MakeShadowCopy(uint64_t cacheLineIdx){
    uint64_t tag = cache[cacheLineIdx].tag;
    uint64_t shadowCacheLineIdx;
    LineStatus s = IsShadowCached(tag, shadowCacheLineIdx);
    switch (s) {
        case CACHED:
            assert(0 && "IMPOSSIBLE");
            break;
        case EMPTY:
        case OCCUPIED:{
            // copy to shadow and make it active
            SHADOW_SET_INUSE(shadowCacheLineIdx);
            SHADOW_SET_TAG(shadowCacheLineIdx, tag);
            shadowCache[shadowCacheLineIdx].lastAcceessTime = accessTime;
            
            uint8_t * baseLocation = cache[cacheLineIdx].value;
            uint8_t * shadowLocation = shadowCache[shadowCacheLineIdx].value;
#pragma omp simd
            for(int i = 0; i < CACHE_LINE_SZ; i++){
                shadowLocation[i] = baseLocation[i];
            }
#if 0
            fprintf(stderr, "\n MakeShadowCopy: idx=%lx s-idx=%lx, tag =%lx", cacheLineIdx, shadowCacheLineIdx, tag);
#endif
        }
            break;
        default:
            break;
    }
}

static inline void CleanShadowCopy(uint64_t shadowCacheIdx, bool isRedundantviaShadow){
    // copy to shadow and make it active
    shadowCache[shadowCacheIdx].isInUse = false;
    shadowCache[shadowCacheIdx].tag = UINT64_MAX;
    shadowCache[shadowCacheIdx].wasRedundant = isRedundantviaShadow;
    shadowCache[shadowCacheIdx].lastAcceessTime = 0;
}

bool HasShadowCache(uint64_t cacheLineIdx, uint64_t &shadowCacheIdx){
    uint64_t tag = cache[cacheLineIdx].tag;
    shadowCacheIdx = SHADOW_CACHE_LINE_INDEX(tag);
    if (SHADOW_IS_VALID(shadowCacheIdx, tag))
        return true;
    // Search the N-ways
    const uint64_t stride = SHADOW_CACHE_NUM_LINES / SHADOW_CACHE_NUM_WAYS;
    
    for(int i = 0; i < SHADOW_CACHE_NUM_WAYS-1; i++) {
        shadowCacheIdx = (shadowCacheIdx + stride) % SHADOW_CACHE_NUM_LINES;
        if (SHADOW_IS_VALID(shadowCacheIdx, tag))
            return true;
    }
#if 0
    fprintf(stderr, "\n HasShadowCache: idx=%lx s-idx=%lx, tag =%lx", cacheLineIdx, shadowCacheIdx, tag);
    shadowCacheIdx = SHADOW_CACHE_LINE_INDEX(tag);
    for(int i = 0; i < SHADOW_CACHE_NUM_WAYS; i++) {
        shadowCacheIdx = (shadowCacheIdx + stride) % SHADOW_CACHE_NUM_LINES;
        fprintf(stderr, "\n XX: idx=%lx s-idx=%lx, tag =%lx s-Tag=%lx", cacheLineIdx, shadowCacheIdx, tag,shadowCache[shadowCacheIdx].tag);
    }
#endif
    
    return false;
}



static inline void OnEvict(uint64_t addr, uint64_t index) {
    uint64_t address = CACHE_LINE_BASE((uint64_t)addr);
    uint8_t * newValue = (uint8_t *) (address);
    uint8_t * originalVal = cache[index].value;
    uint8_t * curValue = (uint8_t *) (GET_TAG(index));
    bool isDirty = IS_DIRTY(index);
    
    if (isDirty) {
        //        fprintf(stderr, "\n E: address=%lx, newValue=%p, originalVal=%p, curValue=%p, idx=%lx, tag=%lx\n", address, newValue, originalVal, curValue, CACHE_LINE_INDEX(address), GET_TAG(address));
        bool isRedundant = true;
        for(int i = 0; i < CACHE_LINE_SZ; i++){
            if(originalVal[i] != curValue[i]) {
                isRedundant = false;
                break;
            }
        }
        
        if(cache[index].isZero) {
            bool foundAllZeros = true;
            for(int i = 0; i < CACHE_LINE_SZ; i++){
                if(curValue[i] != 0) {
                    foundAllZeros = false;
                    break;
                }
            }
            
            if(foundAllZeros)
                stats.zeroDetect++;
//            if(!isRedundant && foundAllZeros)
//                assert(0);
        }
        
        if (!WAS_DIFFERENT(index)) {
            stats.unchanged++;
        }
        if (isRedundant) {
            stats.sameData++;
        }
        
        //        uint64_t oldAddress = GET_TAG(address);
        
        uint64_t shadowCacheIdx;
        //SHADOW_IS_VALID(address)
        if(HasShadowCache(index, shadowCacheIdx)){
            bool isRedundantviaShadow = true;
            uint8_t * originalValInShadow = shadowCache[shadowCacheIdx].value;
#if 0
            for(int i = 0; i < CACHE_LINE_SZ; i++){
                fprintf(stderr, "%d:%d", originalValInShadow[i],curValue[i]);
            }
            fprintf(stderr, "\n");
#endif
            for(int i = 0; i < CACHE_LINE_SZ; i++){
                if(originalValInShadow[i] != curValue[i]) {
                    isRedundantviaShadow = false;
                    break;
                }
            }
            if (isRedundantviaShadow) {
                stats.shadowDetects++;
            }
            if(isRedundantviaShadow != isRedundant){
//                fprintf(stderr, "\n disagreement!");
            }
            
            CleanShadowCopy(shadowCacheIdx, isRedundantviaShadow);
        } else {
            //fprintf(stderr, "\n no shadow");
           // fprintf(stderr, "\n INVALID: idx=%lx, tag=%lx, s-tag=%lx, inuse = %d \n", SHADOW_CACHE_LINE_INDEX(address), GET_TAG(address), SHADOW_GET_TAG(address), shadowCache[CACHE_LINE_INDEX(address)].isInUse);
        }
        stats.dirtyEvicts++;
    } else {
        //      fprintf(stderr, "\n X: address=%lx, newValue=%p, originalVal=%p, curValue=%p, idx=%lx, tag=%lx\n", address, newValue, originalVal, curValue, CACHE_LINE_INDEX(address), GET_TAG(address));
    }
#pragma omp simd
    for(int i = 0; i < CACHE_LINE_SZ; i++){
        originalVal[i] = newValue[i];
    }
    stats.evicts++;
}

static inline void HandleOneCacheLine(void ** addr, bool isWrite, bool print=false){
    uint64_t address = CACHE_LINE_BASE((uint64_t)addr);
    uint64_t cacheLineIdx;
    LineStatus s = IsCached(address, cacheLineIdx);
    
    switch (s) {
        case EMPTY:
            // Allocate
            Allocate(address, cacheLineIdx);
            break;
        case OCCUPIED:
            // cache miss write back
            OnEvict(address, cacheLineIdx);
            // Allocate
            Allocate(address, cacheLineIdx);
            break;
        default:
            break;
    }
//    if(print)
//        fprintf(stderr, "\n CACHE: addr=%p, base =%lx, status=%d, idx = %lx, who=%lx", addr, CACHE_LINE_BASE(((uint64_t)addr)), s, cacheLineIdx, cache[cacheLineIdx].tag);
    // by now we have the line in cache and old one is written back if needed
    // if this is a first time write to this line, mark it dirty and copy to the shadow cache
    if(isWrite){
        if(!IS_DIRTY(cacheLineIdx)){
            SET_DIRTY(cacheLineIdx);
            MakeShadowCopy(cacheLineIdx);
        }
    }
    // Update access time
    SET_ACCESSTIME(cacheLineIdx);
}

static inline void OnAccess(void ** address, uint64_t accessLen, bool isWrite){
    // Is within cache line?
    if(CACHE_LINE_INDEX(address) == CACHE_LINE_INDEX((size_t)(address) + accessLen - 1)) {
        
//        fprintf(stderr, "\n == address=%p, accessLen=%lx", address, accessLen);
        HandleOneCacheLine(address, isWrite, true);
    } else {
        bool print = true;
/*       fprintf(stderr, "\n address=%p, accessLen=%lx", address, accessLen);
        fprintf(stderr, "\n cur+CACHE_LINE_SZ=%lx, end=%p", CACHE_LINE_BASE(address)+CACHE_LINE_SZ, address + accessLen);
        fflush(stderr); */
        for(uint64_t cur =  CACHE_LINE_BASE(address); cur < ((size_t)address )+ accessLen; cur += CACHE_LINE_SZ){
/*            fprintf(stderr, "\n TRIP cur=%lx", cur);
            fflush(stderr); */
            HandleOneCacheLine((void ** )cur, isWrite, print);
//            fflush(stderr);
        }
    }
}
#define MAX_FILE_PATH (1000)

// Initialized the needed data structures before launching the target program
static void ClientInit(int argc, char* argv[]) {
    // Create output file
    char name[MAX_FILE_PATH] = "cache.out.";
    char* envPath = getenv("CACHE_CLIENT_OUTPUT_FILE");
    
    if(envPath) {
        // assumes max of MAX_FILE_PATH
        strcpy(name, envPath);
    }
    
    gethostname(name + strlen(name), MAX_FILE_PATH - strlen(name));
    pid_t pid = getpid();
    sprintf(name + strlen(name), "%d", pid);
    cerr << "\n Creating log file at:" << name << "\n";
    gTraceFile = fopen(name, "w");
    fprintf(gTraceFile, "CONFIG:\n");
    fprintf(gTraceFile, "CACHE_SZ:%lu\n", CACHE_SZ);
    fprintf(gTraceFile, "CACHE_NUM_WAYS:%lu\n", CACHE_NUM_WAYS);
    fprintf(gTraceFile, "SHADOW_CACHE_SZ:%lu\n", SHADOW_CACHE_SZ);
    fprintf(gTraceFile, "---------------\n");
    // print the arguments passed
    fprintf(gTraceFile, "\n");
    
    for(int i = 0 ; i < argc; i++) {
        fprintf(gTraceFile, "%s ", argv[i]);
    }
    
    fprintf(gTraceFile, "\n");
    fflush(gTraceFile);
    CacheFlush();
}



template<uint16_t AccessLen, uint32_t bufferOffset>
struct RedSpyAnalysis{
    static __attribute__((always_inline)) bool IsPartialWriteRedundant(size_t startOffset, size_t length, THREADID threadId){
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        AddrValPair * avPair = & tData->buffer[bufferOffset];
        return memcmp(avPair->value + startOffset, (void **)(avPair->address) + startOffset, length) == 0;
    }
    
    static __attribute__((always_inline)) bool IsWriteRedundant(void * &addr, THREADID threadId){
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
    static __attribute__((always_inline)) VOID RecordNByteValueBeforeWrite(void* addr, THREADID threadId){
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        AddrValPair * avPair = & tData->buffer[bufferOffset];
        avPair->address = addr;
        switch(AccessLen){
            case 1: *((uint8_t*)(&avPair->value)) = *(static_cast<uint8_t*>(addr)); break;
            case 2: *((uint16_t*)(&avPair->value)) = *(static_cast<uint16_t*>(addr)); break;
            case 4: *((uint32_t*)(&avPair->value)) = *(static_cast<uint32_t*>(addr)); break;
            case 8: *((uint64_t*)(&avPair->value)) = *(static_cast<uint64_t*>(addr)); break;
            default:memcpy(&avPair->value, addr, AccessLen);
        }
    }
    static __attribute__((always_inline)) VOID CheckNByteValueAfterWrite(THREADID threadId){
        RedSpyThreadData* const tData = ClientGetTLS(threadId);
        void * addr;
        bool isRedundantWrite = IsWriteRedundant(addr, threadId);
        if(isRedundantWrite) {
            tData->bytesRedundant += AccessLen;
            // increment the metric
        } else {
            bool isSameCacheLine = CACHE_LINE_INDEX(addr) == CACHE_LINE_INDEX((size_t)(addr) + AccessLen - 1);
            if(isSameCacheLine){
                uint64_t cacheLineIdx;
                LineStatus s = IsCached((uint64_t)addr, cacheLineIdx);
/*                if(s != CACHED){
                    fprintf(stderr, "\n addr=%p, base =%lx, len=%d, status=%d, idx=%lx, who=%lx", addr, CACHE_LINE_BASE(((uint64_t)addr)), AccessLen, s, cacheLineIdx, cache[cacheLineIdx].tag);
                    fflush(stderr);
                } */
                
                
                assert(s == CACHED);
                
                if(!WAS_DIFFERENT(cacheLineIdx))
                    WAS_DIFFERENT(cacheLineIdx) = true;
            }else {
                size_t firstCacheLineAccessLength = CACHE_LINE_BASE(addr) + CACHE_LINE_SZ - (size_t)(addr);
                size_t firstCacheLineStart = 0;
                size_t lastCacheLineAccessLength = (size_t) addr + AccessLen - CACHE_LINE_BASE((size_t)addr + AccessLen - 1);
                size_t lastCacheLineStart = CACHE_LINE_BASE((size_t)(addr) + AccessLen - 1) - (size_t)(addr);

                uint64_t cacheLineIdx;
                LineStatus s = IsCached((uint64_t)addr, cacheLineIdx);

/*                if(s != CACHED){
                    fprintf(stderr, "\n addr=%p, base =%lx, len=%d, status=%d, idx=%lx, who=%lx", addr, CACHE_LINE_BASE(((uint64_t)addr)), AccessLen, s, cacheLineIdx, cache[cacheLineIdx].tag);
                    fflush(stderr);
                }
                assert(s == CACHED); */
                
                if( (!WAS_DIFFERENT(cacheLineIdx)) && IsPartialWriteRedundant(firstCacheLineStart, firstCacheLineAccessLength, threadId)){
                    WAS_DIFFERENT(cacheLineIdx) = true;
                }
                
                
                s = IsCached(((uint64_t)addr) + AccessLen - 1, cacheLineIdx);
/*                if(s!=CACHED) {
                    fprintf(stderr, "\n addr=%p, base =%lx, len=%d, status=%d, who=%lx", addr, CACHE_LINE_BASE(((uint64_t)addr) + AccessLen - 1), AccessLen, s, cache[cacheLineIdx].tag);
                    fflush(stderr);
                } */
                assert(s == CACHED);

                if( (!WAS_DIFFERENT(cacheLineIdx)) && IsPartialWriteRedundant(lastCacheLineStart, lastCacheLineAccessLength, threadId)){
                    WAS_DIFFERENT(cacheLineIdx) = true;
                }
                for(int startOffset = firstCacheLineAccessLength ;  startOffset < lastCacheLineStart; startOffset += CACHE_LINE_SZ){
                    s = IsCached(((uint64_t)addr) + startOffset, cacheLineIdx);
                    assert(s == CACHED);

                    
                    if((!WAS_DIFFERENT(cacheLineIdx)) && IsPartialWriteRedundant(startOffset, CACHE_LINE_SZ, threadId))
                        WAS_DIFFERENT(cacheLineIdx) = true;
                }
            }
        }
    }
};

static inline VOID RecordValueBeforeLargeWrite(void* addr, UINT32 accessLen,  uint32_t bufferOffset, THREADID threadId){
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    memcpy(& (tData->buffer[bufferOffset].value), addr, accessLen);
    tData->buffer[bufferOffset].address = addr;
}

static inline VOID CheckAfterLargeWrite(UINT32 accessLen,  uint32_t bufferOffset, THREADID threadId){
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    size_t  addr = (size_t) (tData->buffer[bufferOffset].address);
    if(memcmp(tData->buffer[bufferOffset].value, (void *)addr, accessLen) == 0){
        tData->bytesRedundant += accessLen;
    }else{
        size_t firstCacheLineAccessLength = CACHE_LINE_BASE(addr) + CACHE_LINE_SZ - (size_t)(addr);
        size_t firstCacheLineStart = 0;
        size_t lastCacheLineAccessLength = addr + accessLen - CACHE_LINE_BASE((size_t)(addr) + accessLen - 1);
        size_t lastCacheLineStart = CACHE_LINE_BASE((size_t)(addr) + accessLen - 1) - addr;
        
        uint64_t cacheLineIdx;
        LineStatus s = IsCached((uint64_t)addr, cacheLineIdx);
        assert(s == CACHED);

        
        if( (!WAS_DIFFERENT(cacheLineIdx)) && (0 == memcmp((void *) (tData->buffer[bufferOffset].value + firstCacheLineStart), (void *) ( addr + firstCacheLineStart), firstCacheLineAccessLength))){
            WAS_DIFFERENT(cacheLineIdx) = true;
        }
        
        s = IsCached(((uint64_t)addr) + accessLen - 1, cacheLineIdx);
        assert(s == CACHED);

        if( (!WAS_DIFFERENT(cacheLineIdx)) && (0 == memcmp((void *) (tData->buffer[bufferOffset].value + lastCacheLineStart), (void *) (addr + lastCacheLineStart), lastCacheLineAccessLength))){
            WAS_DIFFERENT(cacheLineIdx) = true;
        }
        for(size_t startOffset = firstCacheLineAccessLength ;  startOffset < lastCacheLineStart; startOffset += CACHE_LINE_SZ){
            s = IsCached(((uint64_t)addr) + startOffset, cacheLineIdx);
            assert(s == CACHED);
            if((!WAS_DIFFERENT(cacheLineIdx)) && (0 == memcmp((void *) (tData->buffer[bufferOffset].value), (void *)(addr + startOffset), CACHE_LINE_SZ)))
                WAS_DIFFERENT(cacheLineIdx) = true;
        }
    }
}

#define HANDLE_CASE(NUM, BUFFER_INDEX, HAS_FALLTHRU) \
case (NUM):{INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) RedSpyAnalysis<(NUM), (BUFFER_INDEX)>::RecordNByteValueBeforeWrite, IARG_MEMORYOP_EA, memOp, IARG_THREAD_ID, IARG_END);\
INS_InsertPredicatedCall(ins, HAS_FALLTHRU? IPOINT_AFTER : IPOINT_TAKEN_BRANCH, (AFUNPTR) RedSpyAnalysis<(NUM), (BUFFER_INDEX)>::CheckNByteValueAfterWrite, IARG_THREAD_ID, IARG_INST_PTR,IARG_END);}break

#define HANDLE_LARGE(HAS_FALLTHRU) \
INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) RecordValueBeforeLargeWrite, IARG_MEMORYOP_EA, memOp, IARG_MEMORYWRITE_SIZE, IARG_UINT32, readBufferSlotIndex, IARG_THREAD_ID, IARG_END);\
INS_InsertPredicatedCall(ins, HAS_FALLTHRU? IPOINT_AFTER : IPOINT_TAKEN_BRANCH, (AFUNPTR) CheckAfterLargeWrite, IARG_MEMORYREAD_SIZE, IARG_UINT32, readBufferSlotIndex, IARG_THREAD_ID, IARG_END)

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
    static __attribute__((always_inline)) void InstrumentReadValueBeforeAndAfterWriting(INS ins, UINT32 memOp, bool hasFallThru){
        UINT32 refSize = INS_MemoryOperandSize(ins, memOp);
        switch(refSize) {
                HANDLE_CASE(1, readBufferSlotIndex, hasFallThru);
                HANDLE_CASE(2, readBufferSlotIndex, hasFallThru);
                HANDLE_CASE(4, readBufferSlotIndex, hasFallThru);
                HANDLE_CASE(8, readBufferSlotIndex, hasFallThru);
                HANDLE_CASE(10, readBufferSlotIndex, hasFallThru);
                HANDLE_CASE(16, readBufferSlotIndex, hasFallThru);
            default: {
                HANDLE_LARGE(hasFallThru);
            }
        }
    }
};



static VOID InstrumentInsCallback(INS ins, VOID* v) {
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    if (memOperands == 0)
        return;
    
    for(UINT32 memOp = 0; memOp < memOperands; memOp++) {
        if(INS_MemoryOperandIsWritten(ins, memOp)) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) OnAccess, IARG_MEMORYOP_EA, memOp, IARG_MEMORYWRITE_SIZE, IARG_BOOL, 1, IARG_END);
        } else {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) OnAccess, IARG_MEMORYOP_EA, memOp, IARG_MEMORYREAD_SIZE, IARG_BOOL, 0,  IARG_END);
        }
    }

#ifdef DO_REDSPY
    // Now do the redSpy business
    
    bool hasFallThu = INS_HasFallThrough(ins);
    
    // Special case, if we have only one write operand
    
    UINT32 whichOp = 0;
    
    if(GetNumWriteOperandsInIns(ins, whichOp) == 1){
        // Read the value at location before and after the instruction
        RedSpyInstrument<0>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, hasFallThu);
    }else{
        
        UINT32 memOperands = INS_MemoryOperandCount(ins);
        
        int readBufferSlotIndex=0;
        
        for(UINT32 memOp = 0; memOp < memOperands; memOp++) {
            if(!INS_MemoryOperandIsWritten(ins, memOp))
                continue;
            switch (readBufferSlotIndex) {
                case 0:
                    // Read the value at location before and after the instruction
                    RedSpyInstrument<0>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, hasFallThu);
                    break;
                case 1:
                    // Read the value at location before and after the instruction
                    RedSpyInstrument<1>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, hasFallThu);
                    break;
                case 2:
                    // Read the value at location before and after the instruction
                    RedSpyInstrument<2>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, hasFallThu);
                    break;
                case 3:
                    // Read the value at location before and after the instruction
                    RedSpyInstrument<3>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, hasFallThu);
                    break;
                case 4:
                    // Read the value at location before and after the instruction
                    RedSpyInstrument<4>::InstrumentReadValueBeforeAndAfterWriting(ins, whichOp, hasFallThu);
                    break;
                default:
                    assert(0 && "NYI");
                    break;
            }
            // use next slot for the next write operand
            readBufferSlotIndex++;
        }
    }
#endif
    
}

size_t getPeakRSS() {
    struct rusage u;
    getrusage(RUSAGE_SELF, &u);
    return (size_t)(u.ru_maxrss);
}


static VOID FiniFunc(INT32 code, VOID *v) {
    fprintf(gTraceFile, "\n Total evict=%lu, dirtyEvicts=%lu, shadowDetects=%lu, redundant=%lu, unchanged=%lu, zeroDetectCnt=%lu, waste=%f, cacheFixable=%f, shadowFixable=%f, zeroDetect=%f, Peak RSS=%zu\n", stats.evicts, stats.dirtyEvicts, stats.shadowDetects, stats.sameData, stats.unchanged, stats.zeroDetect, 100.0 * stats.sameData/ stats.dirtyEvicts, 100.0 * stats.unchanged/stats.dirtyEvicts , 100.0 * stats.shadowDetects / stats.sameData, 100.0 * stats.zeroDetect/stats.sameData, getPeakRSS());
}

static VOID ImageUnload(IMG img, VOID* v) {
    //fprintf(stderr, "\n ImageUnload\n");
    CacheFlush();
}

static void HandleSysCall(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v){
    //fprintf(stderr, "\n HandleSysCall\n");
    CacheFlush();
}

inline VOID Update(uint32_t bytes, THREADID threadId){
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    tData->bytesWritten += bytes;
}

inline VOID UpdateTime(){
    accessTime++;
}


//instrument the trace, count the number of ins in the trace, decide to instrument or not
static void InstrumentTrace(TRACE trace, void* f) {
    
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        uint32_t totBytes = 0;
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if(INS_IsMemoryWrite(ins)) {
                totBytes += INS_MemoryWriteSize(ins);
            }
        }
        BBL_InsertCall(bbl,IPOINT_ANYWHERE,(AFUNPTR)Update, IARG_UINT32, totBytes, IARG_THREAD_ID, IARG_END);

        // Update access time counter
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)UpdateTime, IARG_END);
    }
}


static VOID ThreadFiniFunc(THREADID threadId, const CONTEXT *ctxt, INT32 code, VOID *v) {
    RedSpyThreadData* const tData = ClientGetTLS(threadId);
    fprintf(gTraceFile, "\n Bytes written=%lu, Bytes redundant=%lu, redundant=%f \n", tData->bytesWritten, tData->bytesRedundant, 100.0 * tData->bytesRedundant/ tData->bytesWritten);
}

static void InitThreadData(RedSpyThreadData* tdata){
    tdata->bytesWritten = 0;
    tdata->bytesRedundant = 0;
}

static VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    RedSpyThreadData* tdata = new RedSpyThreadData();
    InitThreadData(tdata);
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
    
    // Obtain  a key for TLS storage.
    client_tls_key = PIN_CreateThreadDataKey(0 /*TODO have a destructir*/);
    // Register ThreadStart to be called when a thread starts.
    PIN_AddThreadStartFunction(ThreadStart, 0);
    
    
    // fini function for post-mortem analysis
    PIN_AddThreadFiniFunction(ThreadFiniFunc, 0);
    
    // Register SyscallEntry
    PIN_AddSyscallEntryFunction (HandleSysCall, 0);
    //  PIN_AddSyscallExitFunction (HandleSysCall, 0);
    
    INS_AddInstrumentFunction(InstrumentInsCallback, 0);
    // fini function for post-mortem analysis
    PIN_AddFiniFunction(FiniFunc, 0);
    
    TRACE_AddInstrumentFunction(InstrumentTrace, 0);
    
    // Launch program now
    PIN_StartProgram();
    return 0;
}


