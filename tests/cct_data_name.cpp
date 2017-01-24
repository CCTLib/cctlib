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
#include <string>
#include <boost/algorithm/string.hpp>
#include <math.h> //Du
#include <sstream>
#include <locale>
#include <unordered_map>
#include "pin.H"

#define OFFSET 20000000
//#define MAX_WINDOW_ALLOWED 200
//#define ChunkSize 512*(1<<10)
//#define WINDOW 100000

#define USE_TREE_BASED_FOR_DATA_CENTRIC
#include "cctlib.H"
using namespace std;
using namespace boost;
using namespace PinCCTLib;


INT32 Usage2() {
    PIN_ERROR("Pin tool to gather calling context on each instruction and associate each memory access to its data object (shadow memory technique).\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

FILE* gTraceFile;

struct DataObj {
	long counter; // # of total accesses by all threads.
	int threads; //# of threads.
	DataHandle_t data;
} ;



PIN_LOCK clientLock;



long long CTR = 0;
int WINDOW_WIDTH = 500*1000;
int MAX_WINDOW_ALLOWED = 1000;
int ChunkSize = 512*(1<<10);

int window;
int TH = 0;//thread to listen
//unsigned long dataSizeTh = 1 << 10;//listen on data that is larger.
bool outputflag = true;
bool errflag = true;
float OutputTH = 0.5; //threshold for output similar data objects.
unordered_map <uint32_t, DataObj> DataObjectMap;
unordered_map <uint32_t, long*> DataWindowMap;//(data ID, array(Windows))
unordered_map <uint32_t, int*> DataThreadMap;//(data ID, array(Windows))

//unordered_map <uint32_t, vector<int>> DataWindowMap;//(data ID, Vector(Windows))




VOID ImageUnload(IMG img, VOID * v) {
	//this routine runs only once.
	if (outputflag==false) return;
	//printf("I AM HERE!2\n");
	outputflag = false;
	int ii, jj;
	fprintf(gTraceFile, "Unloading %s\n", IMG_Name(img).c_str());
	printf("\n [CCTLIB client] Unloading....");
	printf("\n [CCTLIB client] Total accesses: ");
	if (CTR>1000000)
		printf("%d,%.3d,%.3d.\n\n", CTR/1000000, (CTR%1000000)/1000,CTR%1000);	
	else
		printf("%d,%.3d.\n\n", CTR/1000,CTR%1000);	


	//sort
	int length = DataObjectMap.size();
	uint32_t indexList[length], ind_tmp;
	long counterList[length],temp;
	float ratioList[length],ratio_temp;
	DataObj tempData;

	fprintf(gTraceFile,"\n\nA total of %ld memeroy accesses.\n",CTR);
	fprintf(gTraceFile,"Window Width: %ld .\n",WINDOW_WIDTH);
	fprintf(gTraceFile,"total windows: %d .\n",window+1);


	ii = 0;
	for ( auto iter = DataObjectMap.begin(); iter != DataObjectMap.end(); ++iter )
	{		
		indexList[ii] = iter->first;
		tempData = iter->second;
		counterList[ii] = tempData.counter;
		ii++;
	}

	for(ii = 0; ii < length; ii++)
        for(int jj = 0; jj < ii; jj++)
		{//sort by # of access
            if(counterList[jj] < counterList[ii]){
                temp = counterList[jj];
                counterList[jj] = counterList[ii];
                counterList[ii] = temp;//
				ind_tmp = indexList[jj];
                indexList[jj] = indexList[ii];
                indexList[ii] = ind_tmp;//
			}
		}
	
	fprintf(gTraceFile,"\n");
	
	for(ii = 0; ii < min(60,length); ii++)
	{
		uint32_t index = indexList[ii];
		uint32_t sysIndex;
		int chunk = 0;

		auto search = DataObjectMap.find(index);
		if(search != DataObjectMap.end())
		{
			tempData = search->second;
//			printf("1index = %d, 1synName=%d, chunk = %d\n", index, tempData.data.symName, chunk);
			if (index > OFFSET)
			{
//				printf("[CCTLIB] large arrays: %d\n",index);
				chunk = index%100;
				sysIndex = (uint32_t)((index - chunk - OFFSET)/100);
//				printf("index = %d, synName=%d, chunk = %d\n", index, tempData.data.symName, chunk);
			}
			else 
				sysIndex = index;

			uint64_t head = tempData.data.beg_addr;
			uint64_t tail = tempData.data.end_addr;
			int sizeInBytes = (int)tail-head;

			if (tempData.data.objectType == DYNAMIC_OBJECT)
				fprintf(gTraceFile,"\n\n\nRank %d >>>> Dynamic Data %d chunk %d accessed %ld times, range:[%p,%p]\n",
					ii,sysIndex, chunk, tempData.counter, head, tail);
			else if(tempData.data.objectType == STATIC_OBJECT)
				fprintf(gTraceFile,"\n\n\nRank %d >>>> Static Data %d: \"%s\", accessed %ld times, range:[%p,%p]\n",
					ii,sysIndex, GetStringPool()+tempData.data.symName, tempData.counter, head, tail);

			if (sizeInBytes > 1<<20)
				fprintf(gTraceFile,"size = %.3f MB.\n", (float)(sizeInBytes)/(float)(1<<20));
			else if (sizeInBytes > 1<<10)
				fprintf(gTraceFile,"size = %.3f KB.\n", (float)(sizeInBytes)/(float)(1<<10));
			else 
				fprintf(gTraceFile,"size = %d B.\n", sizeInBytes);

			//data - window
			auto search1 = DataWindowMap.find(index);
			if(search1 != DataWindowMap.end())
			{
				long *window_arr = search1->second;

				fprintf(gTraceFile,"distribtion among windows: \n");

				for (jj=0;jj<min(window+1,MAX_WINDOW_ALLOWED);jj++ )
				{
					fprintf(gTraceFile,"|%ld\t",window_arr[jj]);
				}
				fprintf(gTraceFile,"\n");
			}
			else
			{
				fprintf(gTraceFile,"!!not here!!\n");
			}

			//data - thread
			auto search2 = DataThreadMap.find(index);
			if(search2 != DataThreadMap.end())
			{
				int *th_arr = search2->second;
				fprintf(gTraceFile,"accessed by threads: \n");
				for (jj=0;jj<32;jj++ )
				{
					fprintf(gTraceFile,"|%d\t",th_arr[jj]);
				}
				fprintf(gTraceFile,"\n");
			}
			else
			{
				fprintf(gTraceFile,"!!not here!!\n");
			}

			
			PrintFullCallingContext(sysIndex);
//			printf("here6\n");
		}
	}

	fprintf(gTraceFile,"\n\n\n End...");
}


// Initialized the needed data structures before launching the target program
void ClientInit(int argc, char* argv[]) {
    // Create output file
    char name[MAX_FILE_PATH] = "client.out.data_pattern.";
    char* envPath = getenv("CCTLIB_CLIENT_OUTPUT_FILE");

    if(envPath) {
        // assumes max of MAX_FILE_PATH
        strcpy(name, envPath);
    }

    gethostname(name + strlen(name), MAX_FILE_PATH - strlen(name));
    pid_t pid = getpid();
    sprintf(name + strlen(name), "%d", pid);
    cerr << "\n [CCTLIB client] Creating log file at:" << name << "\n\n";
    gTraceFile = fopen(name, "w");
    // print the arguments passed
    fprintf(gTraceFile, "\n");

    for(int i = 0 ; i < argc; i++) {
        fprintf(gTraceFile, "%s ", argv[i]);
    }
    fprintf(gTraceFile, "\n");
	
	// Register ImageUnload to be called when the image is unloaded
	IMG_AddUnloadFunction(ImageUnload, 0);
}


VOID SimpleCCTQuery(THREADID id, const uint32_t slot) {
    GetContextHandle(id, slot);
}


uint32_t getIndex(uint64_t beg, uint64_t end, void* addr, uint32_t sysIndex, THREADID threadId)
{
	int size = (int)((end - beg)/1024);
	int offset = (int)(((long)addr - beg)/1024);
	
	int chunk  = floor(offset/(ChunkSize/1024)) + 1;
	if (chunk>99)
	{
		if(errflag)
		{
			printf("\n [CCTLIB client] !!too large array!! Results of window distribution may be iffy.\n\n");
			PIN_GetLock(&clientLock, threadId + 1);
			errflag = false;
			PIN_ReleaseLock(&clientLock);
		}
		chunk = chunk%100;
	}

	uint32_t localIndex = (sysIndex*100 + OFFSET + chunk);

//	printf(" %d, %d,  %d, %d => %d\n ", size, offset, chunk, sysIndex, localIndex);

	return localIndex;
}


void updateDataList(void* addr, DataHandle_t data, THREADID threadId)
{
	uint32_t sysIndex = data.symName;
	uint32_t index;

	int size = data.end_addr - data.beg_addr;
	if (size < (800* (1<<10) ))
		index = sysIndex;
	else
		index = getIndex(data.beg_addr, data.end_addr, addr, sysIndex, threadId);//divide into chunks

	auto search = DataObjectMap.find(index);
	if(search != DataObjectMap.end()) {
		//update existing one:
		__sync_fetch_and_add(&(search->second).counter,1);
	}
	else{//insert new one
		DataObj newDataObj;
		newDataObj.counter = 1;
		newDataObj.data = data;
		PIN_GetLock(&clientLock, threadId + 1);
		DataObjectMap.insert({index,newDataObj});
		PIN_ReleaseLock(&clientLock);
	}
	

 // TODO: dynamically ajust window width
	auto search1 = DataWindowMap.find(index);
	if(search1 != DataWindowMap.end()) {
		if (window < MAX_WINDOW_ALLOWED)
		{	//update existing one:		
			long *window_arr = search1->second;
			__sync_fetch_and_add(&(window_arr[window]),1);
		}
	}
	else {//insert new one
		long *win_arr = new long[MAX_WINDOW_ALLOWED];
		for (int ii=0; ii<MAX_WINDOW_ALLOWED;ii++ )
			win_arr[ii]=0;
		PIN_GetLock(&clientLock, threadId + 1);
		DataWindowMap.insert({index, win_arr});
		PIN_ReleaseLock(&clientLock);
	}


	auto search2 = DataThreadMap.find(index);
	if(search2 != DataThreadMap.end()) {
		if (threadId < 32)
		{	//update existing one:		
			int *th_arr = search2->second;
			//if (th_arr[threadId]==0)
				__sync_fetch_and_add(&(th_arr[threadId]),1);
		}
	}
	else {//insert new one
		int *th_arr = new int[32];
		for (int ii=0; ii<32;ii++ )
			th_arr[ii]=0;
		PIN_GetLock(&clientLock, threadId + 1);
		DataThreadMap.insert({index, th_arr});
		PIN_ReleaseLock(&clientLock);

	}
	
}


VOID MemAnalysisRoutine(void* addr, THREADID threadId)
{
	//{
	__sync_fetch_and_add(&CTR,1);

	if ((window+1)*WINDOW_WIDTH < CTR)
	{
		PIN_GetLock(&clientLock, threadId + 1);
		window = CTR/WINDOW_WIDTH;
		PIN_ReleaseLock(&clientLock);
	}

	DataHandle_t d = GetDataObjectHandle(addr, threadId);
	
	switch (d.objectType) 
	{
		case STACK_OBJECT:
		break;
		case DYNAMIC_OBJECT://printf("Index= %d, DYNAMIC\n",d.pathHandle);//well...
			updateDataList(addr, d, threadId);
		break;
		case STATIC_OBJECT:
			updateDataList(addr, d, threadId);
		break;
		default://printf("not up in here! Index= %d\n",d.symName);//yes, executed.
		break;
	}
	//}

}



VOID InstrumentInsCallback(INS ins, VOID* v, const uint32_t slot) {
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)SimpleCCTQuery, IARG_THREAD_ID, IARG_UINT32, slot, IARG_END);

    // Data centric for mem inst
    // Skip call, ret and JMP instructions
    if(INS_IsBranchOrCall(ins) || INS_IsRet(ins)) {
        return;
    }

    // skip stack ... actually our code handles it
    if(INS_IsStackRead(ins) || INS_IsStackWrite(ins))
        return;

    if(INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins)) {
        // How may memory operations?
        UINT32 memOperands = INS_MemoryOperandCount(ins);

        // Iterate over each memory operand of the instruction and add Analysis routine
        for(UINT32 memOp = 0; memOp < memOperands; memOp++) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) MemAnalysisRoutine, IARG_MEMORYOP_EA, memOp, IARG_THREAD_ID, IARG_END);
        }
    }
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
    PinCCTLibInit(INTERESTING_INS_ALL, gTraceFile, InstrumentInsCallback, 0 ,/*doDataCentric=*/ true);
    // Launch program now
    PIN_StartProgram();
    return 0;
}


