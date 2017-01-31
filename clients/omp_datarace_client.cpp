// @COPYRIGHT@
// Licensed under MIT license.
// See LICENSE.TXT file in the project root for more information.
// ==============================================================

#include <stdio.h>
#include <atomic>
#include <stdlib.h>
#include <map>
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
#include "pin.H"
#include "cctlib.H"
#include "shadow_memory.cpp"

using namespace std;
using namespace PinCCTLib;
using namespace ShadowMemory;

// All globals
#define MAX_FILE_PATH   (200)

// Enter rank of a phase is twice the number of ordered sections it has entered
// This is same as the phase number rounded up to the next multiple of 2.
#define ENTER_RANK(phase) (((phase) + 1)& 0xfffffffffffffffe)

// Exit rank of a phase is twice the number of ordered sections it has exited.
// This is same as the phase number rounded down to the next multiple of 2.
#define EXIT_RANK(phase) ((phase) & 0xfffffffffffffffe)

#define MAX_REGIONS (1<<20)


//#define DEBUG_LOOP
enum LabelCreationType {
    CREATE_FIRST,
    CREATE_AFTER_FORK,
    CREATE_AFTER_JOIN,
    CREATE_AFTER_BARRIER,
    CREATE_AFTER_ENTERING_ORDERED_SECTION,
    CREATE_AFTER_EXITING_ORDERED_SECTION,
};

enum AccessType{
    READ_ACCESS = 0,
    WRITE_ACCESS = 1
};

// Fwd declarations
class Label;

// Data structures

// A full label is name of many concatenated label segments. Each LabelSegment has 3 components--offset, span, and sphase.
struct LabelSegment{
    uint64_t offset;
    uint64_t span;
    uint64_t phase;
};


static const LabelSegment defaultExtension = {};
static FILE *gTraceFile;
const static char * HW_LOCK = "HW_LOCK";
static Label ** gRegionIdToMasterLabelMap;
// key for accessing TLS storage in the threads. initialized once in main()
static  TLS_KEY tls_key;
// Range of address where images to skip are loaded e.g., OMP runtime, linux loader.
#define OMP_RUMTIMR_LIB_NAME "/home/xl10/support/gcc-4.7-install/lib64/libgomp.so.1"
#define LINUX_LD_NAME    "/lib64/ld-linux-x86-64.so.2"
#define MAX_SKIP_IMAGES (2)
static ADDRINT gSkipImageAddressRanges[MAX_SKIP_IMAGES][2];
static int gNumCurSkipImages;
static string skipImages[] = {OMP_RUMTIMR_LIB_NAME, LINUX_LD_NAME};


// VersionInfo_t is a concurrency control mechanism on the labels stored in the shadow memory.
// Readers read from one end (readStart->data->readEnd) and writers update from another (writeStart->data->writeEnd).
// A reader is assured of a consistent snapshot if readStart equals readEnd.
// A writer first increments writeStart via a CAS and then writes the data and then increments writeEnd.
// Two writers use "writeStart" as their lock to ensure mutual exclusion.

typedef struct VersionInfo_t{
    union{
        volatile atomic<uint64_t> readStart;
        volatile atomic<uint64_t> writeEnd;
    };
    union{
        volatile atomic<uint64_t> writeStart;
        volatile atomic<uint64_t> readEnd;
    };
}VersionInfo_t;


// 2 readers and 1 writer are recorded per byte of memory.
// In addition, a concurrency control mechanism is used for atomic accesses to the shadow memory.
// TODO: One may optimize the granularity of locking

typedef struct DataraceInfo_t{
    // Concurreny control via versioning
    VersionInfo_t versionInfo;

    // Read1's label
    Label * read1;
    //Reader1's CCT id
    ContextHandle_t read1Context;

    // Read2's label
    Label * read2;
    //Reader2's CCT id
    ContextHandle_t read2Context;

    // Last writer
    Label * write1;
    // Last writer's CCT id
    ContextHandle_t  write1Context;
}DataraceInfo_t;

// This is just a wrapper for a piece of Label along with a pointer to the location of the shadow memory.
// This is used for updating the shadow memory after reading from it.
// By remembering the shadowAddress, we don't have to recompute it by following the page table indices.
typedef struct ExtendedDataraceInfo_t{
    DataraceInfo_t * shadowAddress;
    DataraceInfo_t data;
}ExtendedDataraceInfo_t;



// A label is a concatenation of several LabelSegments
class Label {
private:
    LabelSegment * m_LabelSegment;
    uint8_t m_labelLength;
    volatile atomic<uint64_t> m_refCount;
    
public:
    inline uint8_t GetLength() const { return m_labelLength;}
    inline void SetLength(uint64_t len) { m_labelLength = len;}
    inline void IncrementRef() { m_refCount.fetch_add(1, memory_order_acq_rel);}
    inline void DecrementRef(){
        if (m_refCount.fetch_sub(1, memory_order_acq_rel) == 1){
            /*TODO free if 0 assert(0 && "Free label NYI"); */
        }
    }
    
    // Initial label
    Label() : m_labelLength(1), m_refCount(0){
        m_LabelSegment = new LabelSegment[GetLength()];
        m_LabelSegment[0].offset = 0;
        m_LabelSegment[0].span = 1;
        m_LabelSegment[0].phase = 0;
    }
    
    
    LabelSegment * GetSegmentAtIndex(int index) const{
        assert(index < GetLength());
        return &m_LabelSegment[index];
    }
    
    void CopyLabelSegments(const Label & label){
        SetLength(label.GetLength());
        m_LabelSegment = new LabelSegment[GetLength()];
        for(uint32_t i = 0; i < GetLength() ; i++){
            m_LabelSegment[i] = label.m_LabelSegment[i];
        }
    }
    
    // After a fork, a new LabelSegment should be appended to the clone of the parent
    void LabelCreateAfterFork(const Label & label, const LabelSegment & extension){
        SetLength(label.GetLength() + 1);
        m_LabelSegment = new LabelSegment[GetLength()];
        uint8_t i = 0;
        for(; i < GetLength()-1; i++){
            m_LabelSegment[i] = label.m_LabelSegment[i];
        }
        m_LabelSegment[i] = extension;
    }
    
    // After a join, a the last segment should be dropped and offset should be incremented by span
    // TODO: possible memory leak? refcount?
    void LabelCreateAfterJoin(const Label & label){
        assert(label.GetLength() > 1);
        SetLength(label.GetLength() - 1);
        m_LabelSegment = new LabelSegment[GetLength()];
        uint8_t i = 0;
        
        for(; i < GetLength(); i++){
            m_LabelSegment[i] = label.m_LabelSegment[i];
        }
        // increase the offset of last component by span
        m_LabelSegment[i-1].offset += m_LabelSegment[i-1].span;
    }
    

    // TODO: possible memory leak? refcount?
    void LabelCreateAfterBarrier(const Label & label) {
        // Create a label with my parent's offset incremanted by span
        assert(label.GetLength() > 1);
        CopyLabelSegments(label);
        m_LabelSegment[GetLength()-2].offset += m_LabelSegment[GetLength()-2].span;
        // What to do about m_LabelSegment[GetLength()-1] ????
    }
    
    // TODO: possible memory leak? refcount?
    void LabelCreateAfterEneringOrderedSection(const Label & label) {
        // Increment phase
        assert(label.GetLength() > 1);
        CopyLabelSegments(label);
        m_LabelSegment[GetLength()-1].phase ++;
    }

    // TODO: possible memory leak? refcount?
    void LabelCreateAfterExitingOrderedSection(const Label & label) {
        // Increment phase
        assert(label.GetLength() > 1);
        CopyLabelSegments(label);
        m_LabelSegment[GetLength()-1].phase ++;
    }
    
    explicit Label(LabelCreationType type, const Label & label, const LabelSegment & extension = defaultExtension) {
        switch(type){
            case CREATE_AFTER_FORK: LabelCreateAfterFork(label, extension); break;
            case CREATE_AFTER_JOIN: LabelCreateAfterJoin(label); break;
            case CREATE_AFTER_BARRIER: LabelCreateAfterBarrier(label); break;
            case CREATE_AFTER_ENTERING_ORDERED_SECTION: LabelCreateAfterEneringOrderedSection(label); break;
            case CREATE_AFTER_EXITING_ORDERED_SECTION: LabelCreateAfterExitingOrderedSection(label); break;
            default: assert(false);
        }
    }

    void PrintLabel() const{
        fprintf(gTraceFile,"\n");
        for(uint8_t i = 0; i < GetLength() ; i++){
            fprintf(gTraceFile,"[%lu,%lu,%lu]", m_LabelSegment[i].offset, m_LabelSegment[i].span, m_LabelSegment[i].phase);
        }
    }
    
};

class LabelIterator {
private:
    const Label & m_label;
    uint8_t m_curLoc;
    uint8_t m_len;
public:
    LabelIterator(const Label & label) : m_label(label) {
        m_curLoc = 0;
        m_len = label.GetLength();
    }
    
    LabelSegment * NextSegment() {
        if(m_len == m_curLoc) {
            return NULL;
        }
        return m_label.GetSegmentAtIndex(m_curLoc++);
    }
};


// Holds thread local info
class ThreadData_t {
    Label * m_curLable;
    ADDRINT m_stackBaseAddress;
    ADDRINT m_stackEndAddress;
    ADDRINT m_stackCurrentFrameBaseAddress;
public:
    ThreadData_t(ADDRINT stackBaseAddress, ADDRINT stackEndAddress, ADDRINT stackCurrentFrameBaseAddress) :
    m_curLable(NULL),
    m_stackBaseAddress(stackBaseAddress),
    m_stackEndAddress(stackEndAddress),
    m_stackCurrentFrameBaseAddress(stackCurrentFrameBaseAddress){}
    inline Label * GetLabel() const {return m_curLable;}
    inline void SetLabel(Label * label) {
        // TODO: If the current label had a zero ref count, we can possibly delete it
        m_curLable = label;
    }
};

// function to access thread-specific data
ThreadData_t* GetTLS(THREADID threadid) {
    ThreadData_t* tdata =
    static_cast<ThreadData_t*>(PIN_GetThreadData(tls_key, threadid));
    return tdata;
}

// Atomically reads the version number at the beginning for a reader
static inline uint64_t GetReadStartForLoc(const DataraceInfo_t * const shadowAddress){
    return shadowAddress->versionInfo.readStart.load(memory_order_acquire);
}

// Atomically reads the version number at the end for a reader
static inline uint64_t GetReadEndForLoc(const DataraceInfo_t * const shadowAddress){
    return shadowAddress->versionInfo.readEnd.load(memory_order_acquire);
}

// Atomically reads the version number at the beginning for a writer
static inline uint64_t GetWriteStartForLoc(const DataraceInfo_t * const shadowAddress){
    return shadowAddress->versionInfo.writeStart.load(memory_order_acquire);
}

// Atomically reads the version number at the end for a writer
static inline uint64_t GetWriteEndForLoc(const DataraceInfo_t * const shadowAddress){
    return shadowAddress->versionInfo.writeEnd.load(memory_order_acquire);
}

static inline volatile atomic<uint64_t> * GetWriteStartAddressForLoc( DataraceInfo_t * const shadowAddress){
    return &(shadowAddress->versionInfo.writeEnd);
}

// Updates the shadow memory with new labels and contexts information
static inline void UpdateShadowDataAtShadowAddress(DataraceInfo_t * shadowAddress, const DataraceInfo_t &  info){
    shadowAddress->read1 = info.read1;
    shadowAddress->read1Context = info.read1Context;
    shadowAddress->read2 = info.read2;
    shadowAddress->read2Context = info.read2Context;
    shadowAddress->write1 = info.write1;
    shadowAddress->write1Context = info.write1Context;

    // Update the version number at writeEnd
    shadowAddress->versionInfo.writeEnd.store(shadowAddress->versionInfo.writeStart, memory_order_release); //writeStart will be most upto date
}

// Reads the labels and contexts from shadow memory
static inline void ReadShadowData(DataraceInfo_t * info, DataraceInfo_t * shadowAddress){
    info->read1 = shadowAddress->read1;
    info->read1Context = shadowAddress->read1Context;
    info->read2 = shadowAddress->read2;
    info->read2Context = shadowAddress->read2Context;
    info->write1 = shadowAddress->write1;
    info->write1Context = shadowAddress->write1Context;
}

// Snapshot is consistent iff both version numbers are same.
static inline bool IsConsistentSpapshot(const DataraceInfo_t * const info){
    return info->versionInfo.readStart == info->versionInfo.readEnd;
}
// Read a consistent snapshot of the shadow address:
// Uses Leslie Lamport's algorithm listed for readers and writers with two integers.
inline void ReadShadowMemory(DataraceInfo_t * shadowAddress, DataraceInfo_t * info) {
#ifdef DEBUG_LOOP
    int trip = 0;
#endif
    
    do{
        // Read first version number
        info->versionInfo.readStart = GetReadStartForLoc(shadowAddress);
        // Read data
        ReadShadowData(info, shadowAddress);
        // Read second version number
        info->versionInfo.readEnd = GetReadEndForLoc(shadowAddress);
#ifdef DEBUG_LOOP
        if(trip++ > 100000){
            fprintf(stderr,"\n Loop trip > %d in line %d ... Ver1 = %lu .. ver2 = %lu ... %d", trip, __LINE__, info->versionInfo.readStart, info->versionInfo.readEnd, PIN_ThreadId());
        }
#endif
    }while(!IsConsistentSpapshot(info));

#ifdef DEBUG_LOOP
    if(trip > 100000){
        fprintf(stderr,"\n Done ... %d", PIN_ThreadId());
    }
#endif
    
}

// Write a consistent snapshot of the shadow address:
// Uses Leslie Lamport algorithm listed for readers and writers with two integers.
static inline bool TryWriteShadowMemory(DataraceInfo_t *  shadowAddress, const DataraceInfo_t &  info) {
    // Get the first integer for this shadow location:
    volatile atomic<uint64_t> * firstVersionLoc = GetWriteStartAddressForLoc(shadowAddress);
    uint64_t version = info.versionInfo.writeStart;
    if(! firstVersionLoc->compare_exchange_strong(version, version+1))
        return false; // fail retry
    
    UpdateShadowDataAtShadowAddress(shadowAddress, info);
    return true;
}

// Fetch the current threads's logical label
static inline Label * GetMyLabel(THREADID threadId) {
    return GetTLS(threadId)->GetLabel();
}

// Fetch the current threads's logical label
static inline void SetMyLabel(THREADID threadId, Label * label) {
    GetTLS(threadId)->SetLabel(label);
}

static inline void UpdateLabel(Label ** oldLabel, Label * newLabel){
    (*oldLabel) = newLabel;
}

static inline void UpdateContext(ContextHandle_t * oldCtxt, ContextHandle_t  ctxt){
    (*oldCtxt) = ctxt;
}

static inline void CommitChangesToShadowMemory(Label * oldLabel, Label * newLabel){
    if(oldLabel) {
        oldLabel->DecrementRef();
    }
    newLabel->IncrementRef();
}

static inline bool HappensBefore(const Label * const oldLabel, const Label * const newLabel){
    // newLabel ought to be non null
    assert(newLabel && "newLabel can't be NULL");
    
    /*
     [0,1,0][2,200,0]
     [0,1,0][1,200,0]
     
     if ((oldLabel && newLabel) &&  (oldLabel->GetLength () == 2) && (newLabel->GetLength() == 2) && (oldLabel != newLabel))  {
     bar();
     }
     */
    
    // If oldLabel is null, then this is the first access, hence return true
    if (oldLabel == NULL)
        return true;
    
    // Case 1: oldLabel is a prefix of newLabel
    LabelIterator oldLabelIter = LabelIterator(*oldLabel);
    LabelIterator newLabelIter = LabelIterator(*newLabel);
    
    // Special case TODO // if oldLabel == newLabel , return true;
    LabelSegment * oldLabelSegment = NULL;
    LabelSegment * newLabelSegment = NULL;
    
    while (1){
        oldLabelSegment = oldLabelIter.NextSegment();
        newLabelSegment = newLabelIter.NextSegment();
        if (oldLabelSegment == NULL)
            return true; // Found a prefix
        
        if(newLabelSegment == NULL) {
            assert(0 && "I don't expect this to happen");
            return false; // oldLabel is longer than newLabel
        }
        
        if(oldLabelSegment->offset != newLabelSegment->offset)
            break;
    }
    
    //Case 2: The place where they diverge are of the form P[O(x),SPAN]S_x
    // and P[O(y),SPAN]S_y and O(x)  < O(y) and ( O(x) mod SPAN == O(y) mod SPAN )
    assert(oldLabelSegment->span == newLabelSegment->span);
    
    if ((oldLabelSegment->offset < newLabelSegment->offset ) &&
        (oldLabelSegment->offset % newLabelSegment->span == newLabelSegment->offset % newLabelSegment->span) ) {
        return true;
    }
    
    // Now check the ordered secton case:
    if ((oldLabelSegment->offset < newLabelSegment->offset) &&
        (EXIT_RANK(oldLabelSegment->phase) < ENTER_RANK(newLabelSegment->phase)) ) {
        return true;
    }
    return false;
}

static inline bool IsLeftOf(const Label * const newLabel, const Label * const oldLabel){
    // newLabel ought to be non null
    assert(newLabel && "newLabel can't be NULL");
    
    // If oldLabel is null, then this is the first access, hence return false
    if (oldLabel == NULL)
        return false;
    
    LabelIterator oldLabelIter = LabelIterator(*oldLabel);
    LabelIterator newLabelIter = LabelIterator(*newLabel);
    
    
    while (1){
        LabelSegment * oldLabelSegment = oldLabelIter.NextSegment();
        LabelSegment * newLabelSegment = newLabelIter.NextSegment();
        if (oldLabelSegment == NULL || newLabelSegment == NULL)
            return false; // Found a prefix
        
        if( (oldLabelSegment->offset % newLabelSegment->span < newLabelSegment->offset % newLabelSegment->span)) {
            return true;
        }
    }
    
    return false;
}

static inline bool MaximizesExitRank(const Label * const newLabel, const Label * const oldLabel){
    // newLabel ought to be non null
    assert(newLabel && "newLabel can't be NULL");
    
    // If oldLabel is null, then this is the first access, hence return false
    if (oldLabel == NULL)
        return false;
    
    LabelIterator oldLabelIter = LabelIterator(*oldLabel);
    LabelIterator newLabelIter = LabelIterator(*newLabel);
    
    while (1){
        LabelSegment * oldLabelSegment = oldLabelIter.NextSegment();
        LabelSegment * newLabelSegment = newLabelIter.NextSegment();
        if (oldLabelSegment == NULL || newLabelSegment == NULL)
            return false;
        
        if( (oldLabelSegment->offset % newLabelSegment->span != newLabelSegment->offset % newLabelSegment->span)) {
            // At the level where offsets diverge
            if( (EXIT_RANK(newLabelSegment->phase) > EXIT_RANK(oldLabelSegment->phase))) {
                return true;
            }
            return false;
        }
        oldLabelSegment = oldLabelIter.NextSegment();
        newLabelSegment = newLabelIter.NextSegment();
    }
    return false;
}


static inline void DumpRaceInfo(ContextHandle_t oldCtxt,Label * oldLbl, ContextHandle_t newCtxt, Label * newLbl){
    PIN_LockClient();
    fprintf(gTraceFile, "\n ----------");
    oldLbl->PrintLabel();
    PrintFullCallingContext(oldCtxt);
    fprintf(gTraceFile, "\n *****RACES WITH*****");
    newLbl->PrintLabel();
    PrintFullCallingContext(newCtxt);
    fprintf(gTraceFile, "\n ----------");
    PIN_UnlockClient();
}

static inline void CheckRead(DataraceInfo_t * shadowAddress, Label * myLabel, uint32_t opaqueHandle, THREADID threadId) {
    bool reported = false;
    // TODO .. Is this do-while excessive?
    do{
        DataraceInfo_t shadowData;
        ReadShadowMemory(shadowAddress, &shadowData);
        bool updated1 = false;
        Label * oldR1Label = NULL;
        Label * oldR2Label = NULL;
        bool updated2 = false;
        
        // If we have reported a data race originating from this read
        // then let's not inundate with more data races at the same location.
        if (!reported && !HappensBefore(shadowData.write1, myLabel)) {
            // Report W->R Data race
            fprintf(stderr, "\n W->R race");
            DumpRaceInfo(shadowData.write1Context, shadowData.write1, GetContextHandle(threadId, opaqueHandle), myLabel);
            reported = true;
        }
        
        // Update labels
        /* TODO replace HappensBefore with SAME THREAD */
        if(MaximizesExitRank(myLabel, shadowData.read1) || IsLeftOf(myLabel, shadowData.read1) || HappensBefore(shadowData.read1, myLabel)) {
            oldR1Label = shadowData.read1;
            UpdateLabel(&shadowData.read1, myLabel);
            UpdateContext(&shadowData.read1Context, GetContextHandle(threadId, opaqueHandle));
            updated1 = true;
        }
        
        /* TODO replace HappensBefore with SAME THREAD */
        if( (shadowData.read2 && IsLeftOf(shadowData.read2, myLabel))  || HappensBefore(shadowData.read2, myLabel)) {
            oldR2Label = shadowData.read2;
            UpdateLabel(&shadowData.read2, myLabel);
            UpdateContext(&shadowData.read2Context, GetContextHandle(threadId, opaqueHandle));
            updated2 = true;
        }
        
        if (updated1 || updated2) {
            if(!TryWriteShadowMemory(shadowAddress, shadowData)) {
                // someone updated the shadow memory before we could, we need to redo the entire process
                continue;
            }
            // Commit ref count to labels
            if (updated1) {
                CommitChangesToShadowMemory(oldR1Label, myLabel);
            }
            if (updated2) {
                CommitChangesToShadowMemory(oldR2Label, myLabel);
            }
        }
        break;
    }while(1);
}

static inline void CheckWrite(DataraceInfo_t * shadowAddress, Label * myLabel, uint32_t opaqueHandle, THREADID threadId) {
    bool reported = false;
    do {
        DataraceInfo_t shadowData;
        ReadShadowMemory(shadowAddress, &shadowData);
        //#define DEBUG
#ifdef DEBUG
        if(shadowData.write1) {
            fprintf(stderr,"\n Comparing labels:");
            myLabel->PrintLabel();
            shadowData.write1->PrintLabel();
        } else {
            fprintf(stderr,"\n shadowData.write1 is NULL");
        }
#endif
        // If we have reported a data race originating from this read
        // then let's not inundate with more data races at the same location.
        if (!reported && !HappensBefore(shadowData.write1, myLabel)) {
            // Report W->W Data race
            reported = true;
            fprintf(stderr, "\n W->W race");
            DumpRaceInfo(shadowData.write1Context,shadowData.write1, GetContextHandle(threadId, opaqueHandle), myLabel);
        }
        if (!reported && !HappensBefore(shadowData.read1, myLabel)) {
            // Report R->W Data race
            reported = true;
            fprintf(stderr, "\n R->W race");
            DumpRaceInfo(shadowData.read1Context, shadowData.read1, GetContextHandle(threadId, opaqueHandle), myLabel);
        }
        if (!reported && !HappensBefore(shadowData.read2, myLabel)) {
            // Report R->W Data race
            fprintf(stderr, "\n R->W race");
            DumpRaceInfo(shadowData.read2Context, shadowData.read2, GetContextHandle(threadId, opaqueHandle), myLabel);
            reported = true;
        }
        Label * oldW1Label = shadowData.write1;
        // Update label
        UpdateLabel(&shadowData.write1, myLabel);
        UpdateContext(&shadowData.write1Context, GetContextHandle(threadId, opaqueHandle));
        if(!TryWriteShadowMemory(shadowAddress, shadowData)) {
            // someone updated the shadow memory before we could, we need to redo the entire process
            continue;
        }
        CommitChangesToShadowMemory(oldW1Label, myLabel);
        break;
    }while(1);
}


// Run the datarace protocol and report race.
static inline void ExecuteOffsetSpanPhaseProtocol(DataraceInfo_t *status, Label * myLabel, bool accessType, uint32_t opaqueHandle, THREADID threadId) {
    if(accessType == WRITE_ACCESS){
        CheckWrite(status, myLabel, opaqueHandle, threadId);
    } else { // READ_ACCESS
        CheckRead(status, myLabel, opaqueHandle, threadId);
    }
}


static inline VOID CheckRace( VOID * addr, uint32_t accessLen, bool accessType, uint32_t opaqueHandle, THREADID threadId) {
    // Get my Label
    Label * myLabel = GetMyLabel(threadId);
    // if myLabel is NULL, then we are in the initial serial part of the program, hence we can skip the rest
    if (myLabel == NULL)
        return;
    
    DataraceInfo_t * status = GetOrCreateShadowBaseAddress<DataraceInfo_t>(addr);
    int overflow = (int)(PAGE_OFFSET((uint64_t)addr)) -  (int)((PAGE_OFFSET_MASK - (accessLen-1)));
    status += PAGE_OFFSET((uint64_t)addr);
    
    if(overflow <= 0 ){
        // The accessed word's shadow memory does not straddle 2 64K shadow pages.
        // Execute the protocol for each byte of the memory accessed.
        for(uint32_t i = 0 ; i < accessLen; i++){
            ExecuteOffsetSpanPhaseProtocol(&status[i], myLabel, accessType, opaqueHandle, threadId);
        }
    } else {
        // The accessed word's shadow memory straddles 2 64K shadow pages.
        // Execute the protocol for each byte of the memory accessed in the first page
        for(uint32_t nonOverflowBytes = 0 ; nonOverflowBytes < accessLen - overflow; nonOverflowBytes++){
            ExecuteOffsetSpanPhaseProtocol(&status[nonOverflowBytes], myLabel, accessType, opaqueHandle, threadId);
        }
        // Execute the protocol for each byte of the memory accessed in the next page
        status = GetOrCreateShadowBaseAddress<DataraceInfo_t>(((char *)addr) + accessLen); // +accessLen so that we get next page
        for( int i = 0; i < overflow; i++){
            ExecuteOffsetSpanPhaseProtocol(&status[i], myLabel, accessType, opaqueHandle, threadId);
        }
        // TODO: We never expect the access to straddle more than 2 pages. If that happens we are hosed.
    }
}


// If it is one of ignoreable instructions, then skip instrumentation.
static inline bool IsIgnorableIns(INS ins){
    //TODO .. Eliminate this check with a better one
    /*
     Access to the stack simply means that the instruction accesses memory relative to the stack pointer (ESP or RSP), or the frame pointer (EBP or RBP). In code compiled without a frame pointer (where EBP/RBP is used as a general register), this may give a misleading result.
     */
    if (INS_IsStackRead(ins) || INS_IsStackWrite(ins) )
        return true;
    
    // skip call, ret and JMP instructions
    if(INS_IsBranchOrCall(ins) || INS_IsRet(ins)){
        return true;
    }
    // If ins is in libgomp.so, or /lib64/ld-linux-x86-64.so.2 skip it
    for(int i = 0; i < gNumCurSkipImages ; i++) {
        if( (INS_Address(ins) >= gSkipImageAddressRanges[i][0])  && ((INS_Address(ins) < gSkipImageAddressRanges[i][1]))){
            return true;
        }
    }
    return false;
}
#define MASTER_BEGIN_FN_NAME "gomp_datarace_master_begin_dynamic_work"
#define DYNAMIC_BEGIN_FN_NAME "gomp_datarace_begin_dynamic_work"
#define DYNAMIC_END_FN_NAME "gomp_datarace_master_end_dynamic_work"
#define ORDERED_ENTER_FN_NAME "gomp_datarace_begin_ordered_section"
#define ORDERED_EXIT_FN_NAME "gomp_datarace_end_ordered_section"
#define CRITICAL_ENTER_FN_NAME "gomp_datarace_begin_critical"
#define CRITICAL_EXIT_FN_NAME "gomp_datarace_end_critical"
//    void gomp_datarace_begin_dynamic_work(uint64_t region_id, long span, long iter);
//    void gomp_datarace_master_end_dynamic_work()
//    void gomp_datarace_master_begin_dynamic_work(uint64_t region_id, long span);
//    void gomp_datarace_begin_ordered_section(uint64_t region_id);
//    void gomp_datarace_begin_critical(void *);
//    void gomp_datarace_end_critical(void *);
typedef void (*FP_MASTER)(uint64_t region_id, long span);
typedef void (*FP_WORKER)(uint64_t region_id, long span, long iter);
typedef void (*FP_WORKER_END)();
typedef void (*FP_ORDERED_ENTER)(uint64_t region_id);
typedef void (*FP_ORDERED_EXIT)(uint64_t region_id);
typedef void (*FP_CRITICAL_ENTER)(void *);
typedef void (*FP_CRITICAL_EXIT)(void *);


void new_MASTER_BEGIN_FN_NAME(uint64_t region_id, long span, THREADID threadid){
    assert(region_id < MAX_REGIONS);
    // Publish my label into the labelHashTable
    assert(gRegionIdToMasterLabelMap[region_id] == 0);
    Label * myLabel =  GetMyLabel(threadid);
    // if the label was NULL, let us create a new initial label
    if (myLabel == NULL) {
        myLabel = new Label();
        SetMyLabel(threadid, myLabel);
    }
    gRegionIdToMasterLabelMap[region_id] = myLabel;
}

void new_DYNAMIC_BEGIN_FN_NAME(uint64_t region_id, long span, long iter, THREADID threadid){
    // Fetch parent label and create new one
    //fprintf(stderr,"\n fetched parent label");
    
    assert(gRegionIdToMasterLabelMap[region_id] != NULL);
    
    Label * parentLabel =  gRegionIdToMasterLabelMap[region_id];
    // Create child label
    LabelSegment extension;
    extension.span = span;
    extension.offset = iter;
    extension.phase = 0;
    Label * myLabel = new Label(CREATE_AFTER_FORK, *parentLabel, extension);
    SetMyLabel(threadid, myLabel);
    //myLabel->PrintLabel();
}


void new_DYNAMIC_END_FN_NAME(THREADID threadId){
    // Fetch current label and create new one
    Label * parentLabel =  GetMyLabel(threadId);
    Label * myLabel = new Label(CREATE_AFTER_JOIN, *parentLabel);
    SetMyLabel(threadId, myLabel);
    return;
    //myLabel->PrintLabel();
}


void new_ORDERED_ENTER_FN_NAME(uint64_t region_id, THREADID threadId){
    // Fetch current label and create new one
    Label * parentLabel =  GetMyLabel(threadId);
    Label * myLabel = new Label(CREATE_AFTER_ENTERING_ORDERED_SECTION, *parentLabel);
    SetMyLabel(threadId, myLabel);
    return;
    //myLabel->PrintLabel();
}

void new_ORDERED_EXIT_FN_NAME(uint64_t region_id, THREADID threadId){
    // Fetch current label and create new one
    Label * parentLabel =  GetMyLabel(threadId);
    Label * myLabel = new Label(CREATE_AFTER_EXITING_ORDERED_SECTION, *parentLabel);
    SetMyLabel(threadId, myLabel);
    return;
    //myLabel->PrintLabel();
}

void new_CRITICAL_ENTER_FN_NAME( void * name, THREADID threadid){
    if(name){
        // name is the address of the a symbol i.g. 0x602d20 <.gomp_critical_user_FOO> for a lock FOO
    } else {
        // Analymous locks
    }
}

void new_CRITICAL_EXIT_FN_NAME(void * name, THREADID threadid){
    if(name) {
        // name is the address of the a symbol i.g. 0x602d20 <.gomp_critical_user_FOO> for a lock FOO
    } else {
        // Anonymous locks
    }
}

// Overrides for various functions
VOID Overrides (IMG img, VOID * v) {
    // Master setup
    RTN rtn = RTN_FindByName (img, MASTER_BEGIN_FN_NAME);
    if (RTN_Valid (rtn)) {
        // Define a function prototype that describes the application routine
        // that will be replaced.
        //
        PROTO proto_master = PROTO_Allocate (PIN_PARG (void), CALLINGSTD_DEFAULT,
                                             MASTER_BEGIN_FN_NAME, PIN_PARG (uint64_t),PIN_PARG (long),
                                             PIN_PARG_END ());
        
        // Replace the application routine with the replacement function.
        // Additional arguments have been added to the replacement routine.
        //
        RTN_ReplaceSignature (rtn, AFUNPTR (new_MASTER_BEGIN_FN_NAME),
                              IARG_PROTOTYPE, proto_master,
                              IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                              IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                              IARG_THREAD_ID, IARG_END);
        // Free the function prototype.
        PROTO_Free (proto_master);
    }
    
    // Dynamic Start
    rtn = RTN_FindByName (img, DYNAMIC_BEGIN_FN_NAME);
    if (RTN_Valid (rtn)) {
        PROTO proto_worker = PROTO_Allocate (PIN_PARG (void), CALLINGSTD_DEFAULT,
                                             DYNAMIC_BEGIN_FN_NAME, PIN_PARG (uint64_t),PIN_PARG (long),PIN_PARG (long),
                                             PIN_PARG_END ());
        RTN_ReplaceSignature (rtn, AFUNPTR (new_DYNAMIC_BEGIN_FN_NAME),
                              IARG_PROTOTYPE, proto_worker,
                              IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                              IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                              IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                              IARG_THREAD_ID, IARG_END);
        PROTO_Free (proto_worker);
    }
    
    // Dynamic end
    rtn = RTN_FindByName (img, DYNAMIC_END_FN_NAME);
    if (RTN_Valid (rtn)) {
        PROTO proto_end = PROTO_Allocate (PIN_PARG (void), CALLINGSTD_DEFAULT,
                                          DYNAMIC_END_FN_NAME, PIN_PARG_END ());
        RTN_ReplaceSignature (rtn, AFUNPTR (new_DYNAMIC_END_FN_NAME),
                              IARG_PROTOTYPE, proto_end,
                              IARG_THREAD_ID, IARG_END);
        PROTO_Free (proto_end);
    }
    
    // Ordered Enter
    rtn = RTN_FindByName (img, ORDERED_ENTER_FN_NAME);
    if (RTN_Valid (rtn)) {
        PROTO ordered_enter = PROTO_Allocate (PIN_PARG (void), CALLINGSTD_DEFAULT,
                                              ORDERED_ENTER_FN_NAME, PIN_PARG (uint64_t), PIN_PARG_END ());
        RTN_ReplaceSignature (rtn, AFUNPTR (new_ORDERED_ENTER_FN_NAME),
                              IARG_PROTOTYPE, ordered_enter,
                              IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                              IARG_THREAD_ID, IARG_END);
        PROTO_Free (ordered_enter);
    }
    
    // Ordered Exit
    rtn = RTN_FindByName (img, ORDERED_EXIT_FN_NAME);
    if (RTN_Valid (rtn)) {
        PROTO ordered_exit = PROTO_Allocate (PIN_PARG (void), CALLINGSTD_DEFAULT,
                                             ORDERED_EXIT_FN_NAME, PIN_PARG (uint64_t), PIN_PARG_END ());
        RTN_ReplaceSignature (rtn, AFUNPTR (new_ORDERED_EXIT_FN_NAME),
                              IARG_PROTOTYPE, ordered_exit,
                              IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                              IARG_THREAD_ID, IARG_END);
        PROTO_Free (ordered_exit);
    }
    
    // Critical Enter
    rtn = RTN_FindByName (img, CRITICAL_ENTER_FN_NAME);
    if (RTN_Valid (rtn)) {
        PROTO critical_enter = PROTO_Allocate (PIN_PARG (void), CALLINGSTD_DEFAULT,
                                               CRITICAL_ENTER_FN_NAME, PIN_PARG (void*), PIN_PARG_END ());
        RTN_ReplaceSignature (rtn, AFUNPTR (new_CRITICAL_ENTER_FN_NAME),
                              IARG_PROTOTYPE, critical_enter,
                              IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                              IARG_THREAD_ID, IARG_END);
        PROTO_Free (critical_enter);
    }
    // Critical Exit
    rtn = RTN_FindByName (img, CRITICAL_EXIT_FN_NAME);
    if (RTN_Valid (rtn)) {
        PROTO critical_exit = PROTO_Allocate (PIN_PARG (void), CALLINGSTD_DEFAULT,
                                              CRITICAL_EXIT_FN_NAME, PIN_PARG (void*), PIN_PARG_END ());
        RTN_ReplaceSignature (rtn, AFUNPTR (new_CRITICAL_EXIT_FN_NAME),
                              IARG_PROTOTYPE, critical_exit,
                              IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                              IARG_THREAD_ID, IARG_END);
        PROTO_Free (critical_exit);
    }
}


// Is called for every load, store instruction to insert necessary instrumentation.
static VOID InstrumentInsCallback(INS ins, VOID* v, const uint32_t opaqueHandle) {
    if (IsIgnorableIns(ins))
        return;
    
    // If this is an atomic instruction, act as if a lock (HW LOCK) was taken and released
    if (INS_IsAtomicUpdate(ins)) {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                 (AFUNPTR) new_CRITICAL_ENTER_FN_NAME,
                                 IARG_PTR,HW_LOCK,
                                 IARG_THREAD_ID, IARG_END);
    }
    
    // How may memory operations?
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    // Iterate over each memory operand of the instruction and add Analysis routine to check races.
    // We correctly handle instructions that do both read and write.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
        if (INS_MemoryOperandIsWritten(ins, memOp)) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                     (AFUNPTR) CheckRace,
                                     IARG_MEMORYOP_EA,memOp, IARG_MEMORYWRITE_SIZE,  IARG_BOOL, WRITE_ACCESS /* write */, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_END);
        } else if (INS_MemoryOperandIsRead(ins, memOp)) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,(AFUNPTR) CheckRace, IARG_MEMORYOP_EA, memOp, IARG_MEMORYREAD_SIZE, IARG_BOOL, READ_ACCESS /* read */, IARG_UINT32, opaqueHandle, IARG_THREAD_ID, IARG_END);
        }
    }
    if (INS_IsAtomicUpdate(ins)) {
        INS_InsertPredicatedCall(ins, IPOINT_AFTER,
                                 (AFUNPTR) new_CRITICAL_EXIT_FN_NAME,
                                 IARG_PTR,HW_LOCK,
                                 IARG_THREAD_ID, IARG_END);
    }
}



static INT32 Usage() {
    PIN_ERROR("PinTool for datarace detection.\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v) {
    // Get the stack base address:
    ADDRINT stackBaseAddr = PIN_GetContextReg(ctxt, REG_STACK_PTR);
    pthread_attr_t attr;
    size_t stacksize;
    pthread_attr_init(&attr);
    pthread_attr_getstacksize(&attr, &stacksize);
    ThreadData_t* tdata = new ThreadData_t(stackBaseAddr, stackBaseAddr + stacksize, stackBaseAddr);
    //fprintf(stderr,"\n m_stackBaseAddress = %lu, m_stackEndAddress = %lu, size = %lu", stackBaseAddr, stackBaseAddr + stacksize, stacksize);
    // Label will be NULL
    PIN_SetThreadData(tls_key, tdata, threadid);
}

static inline VOID InstrumentImageLoad(IMG img, VOID *v){
    for(uint i = 0; i < MAX_SKIP_IMAGES; i++) {
        if(IMG_Name(img) == skipImages[i]){
            gSkipImageAddressRanges[gNumCurSkipImages][0] = IMG_LowAddress(img);
            gSkipImageAddressRanges[gNumCurSkipImages][1]  = IMG_HighAddress(img);
            gNumCurSkipImages++;
            fprintf(stderr,"\n Skipping image %s", skipImages[i].c_str());
            break;
        }
    }
}

// Initialize the data structures needed before launching the target program
void InitDataRaceSpy(int argc, char *argv[]){
    // Create output file
    char name[MAX_FILE_PATH] = "DataRaceSpy.out.";
    char * envPath = getenv("OUTPUT_FILE");
    if(envPath){
        // assumes max of MAX_FILE_PATH
        strcpy(name, envPath);
    }
    gethostname(name + strlen(name), MAX_FILE_PATH - strlen(name));
    pid_t pid = getpid();
    sprintf(name + strlen(name),"%d",pid);
    cerr << "\n Creating dead info file at:" << name << "\n";
    
    gTraceFile = fopen(name, "w");
    // print the arguments passed
    fprintf(gTraceFile,"\n");
    for(int i = 0 ; i < argc; i++){
        fprintf(gTraceFile,"%s ",argv[i]);
    }
    fprintf(gTraceFile,"\n");
    
    // Allocate gRegionIdToMasterLabelMap
    gRegionIdToMasterLabelMap = (Label **) calloc(sizeof(Label*) * MAX_REGIONS, 1);
    
    // Obtain  a key for TLS storage.
    tls_key = PIN_CreateThreadDataKey(0);
    
    // Register ThreadStart to be called when a thread starts.
    PIN_AddThreadStartFunction(ThreadStart, 0);
    
    // Record Module information about OMP runtime
    IMG_AddInstrumentFunction(InstrumentImageLoad, 0);
}

// Main for DataraceSpy, initialize the tool, register instrumentation functions and call the target program.
int main(int argc, char *argv[]) {
    // Initialize PIN
    if (PIN_Init(argc, argv))
        return Usage();
    // Initialize Symbols, we need them to report functions and lines
    PIN_InitSymbols();
    // Intialize DataraceSpy
    InitDataRaceSpy(argc, argv);
    // Intialize CCTLib
    PinCCTLibInit(INTERESTING_INS_MEMORY_ACCESS, gTraceFile, InstrumentInsCallback, 0);
    // Look up and replace some functions
    IMG_AddInstrumentFunction (Overrides, 0);
    fprintf(stderr,"\n TODO TODO ... eliminate stack local check and make it robust");
    // Launch program now
    PIN_StartProgram();
    return 0;
}


