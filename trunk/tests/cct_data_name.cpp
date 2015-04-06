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
#include <tuple>
#include <unordered_map>
#include "pin.H"

#define OFFSET 20000000
#define ChunkSize 512*(1<<10)

//#define USE_SHADOW_FOR_DATA_CENTRIC
#define USE_TREE_BASED_FOR_DATA_CENTRIC
#include "cctlib.H"
using namespace std;
using namespace boost;
using namespace PinCCTLib;

typedef struct DataObj
{
	long counter;
	DataHandle_t data;
} DataObj;

INT32 Usage2() {
    PIN_ERROR("Pin tool to gather calling context on each instruction and associate each memory access to its data object (shadow memory technique).\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

FILE* gTraceFile;
long CTR=0;
int TH = 0;//thread to listen
long window = 100000;//1000000;
//unsigned long dataSizeTh = 1 << 10;//listen on data that is larger.
bool outputflag = true;
float OutputTH = 0.5; //threshold for output similar data objects.
unordered_map <uint32_t, DataObj> dataObjectList;
//unordered_map <string, vector<pair<long,int>> > testList; // (data ID , pair(private counter, bucket0-9))
//unordered_map <int, unordered_map<ContextHandle_t, vector<pair<long,int>>> > allThreadList;
unordered_map <string, vector<tuple<long,long,int>> > testList; // (data ID , pair(icounter, CTR, bucket0-9))

int ID = -1;



VOID ImageUnload(IMG img, VOID * v) {
	//this routine runs only once.
	if (outputflag==false) return;
	//printf("I AM HERE!2\n");
	outputflag = false;
	int ii = 0;
	fprintf(gTraceFile, "\nUnloading %s", IMG_Name(img).c_str());
	printf("\n[CCTLIB] Unloading....\n\n");

	//sort
	int length = dataObjectList.size();
	uint32_t indexList[length], ind_tmp;
	long counterList[length],temp;
	float ratioList[length],ratio_temp;
	DataObj tempData;

	fprintf(gTraceFile,"\n\nA total of %ld memeroy accesses.\n",CTR);
	fprintf(gTraceFile,"Window size: %ld .\n",window);

	ii = 0;
	for ( auto iter = dataObjectList.begin(); iter != dataObjectList.end(); ++iter )
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
	
	fprintf(gTraceFile,"\n\n");
	
	for(ii = 0; ii < min(60,length); ii++)
	{
		uint32_t index = indexList[ii];
		uint32_t sysIndex;
		int chunk = 0;

		auto search = dataObjectList.find(index);
		if(search != dataObjectList.end())
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
				fprintf(gTraceFile,"\n\nRank %d -->> Dynamic Data %d chunk %d accessed %ld times, range:[%p,%p]\n",
					ii,sysIndex, chunk, tempData.counter, head, tail);
			else if(tempData.data.objectType == STATIC_OBJECT)
				fprintf(gTraceFile,"\n\nRank %d -->> Static Data %d: \"%s\", accessed %ld times, range:[%p,%p]\n",
					ii,sysIndex, GetStringPool()+tempData.data.symName, tempData.counter, head, tail);

			if (sizeInBytes > 1<<20)
				fprintf(gTraceFile,"size = %.3f MB.\n", (float)(sizeInBytes)/(float)(1<<20));
			else if (sizeInBytes > 1<<10)
				fprintf(gTraceFile,"size = %.3f KB.\n", (float)(sizeInBytes)/(float)(1<<10));
			else 
				fprintf(gTraceFile,"size = %d B.\n", sizeInBytes);
//			printf("here5\n");

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
    cerr << "\n Creating log file at:" << name << "\n";
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


uint32_t getIndex(uint64_t beg, uint64_t end, void* addr, uint32_t sysIndex)
{
	int size = (int)((end - beg)/1024);
	int offset = (int)(((long)addr - beg)/1024);
	
	int chunk  = floor(offset/(ChunkSize/1024)) + 1;
	if (chunk>99)
	{
		printf("\n!!too large array!! Results may be iffy.\n\n");
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
	if (size > (800* (1 <<10) ))
		index = getIndex(data.beg_addr, data.end_addr, addr, sysIndex);
	else
		index = sysIndex;

	auto search = dataObjectList.find(index);
	if(search != dataObjectList.end()) {
		//update existing one:
		DataObj curDataObj = search->second;//search is an iterator.
		DataObj newDataObj;
		
		newDataObj.counter = curDataObj.counter + 1;
		newDataObj.data = curDataObj.data;
		dataObjectList.erase(index);
		dataObjectList.insert({index,newDataObj});
    }
	else
	{	//insert new one
		DataObj newDataObj;
		newDataObj.counter = 1;
		newDataObj.data = data;

		dataObjectList.insert({index,newDataObj});
	}	
}


VOID MemAnalysisRoutine(void* addr, THREADID threadId) {

	if (((int)threadId==TH))
	{
		CTR ++;

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
	}

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


