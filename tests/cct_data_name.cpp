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
unordered_map <string, DataObj> dataObjectList;
//unordered_map <string, vector<pair<long,int>> > testList; // (data ID , pair(private counter, bucket0-9))
//unordered_map <int, unordered_map<ContextHandle_t, vector<pair<long,int>>> > allThreadList;
unordered_map <string, vector<tuple<long,long,int>> > testList; // (data ID , pair(icounter, CTR, bucket0-9))

int ID = -1;


void ShowPattern(unordered_map <string, vector<tuple<long,long,int>> > List)
{
	if (List.size()==0)
		return;
	
	fprintf(gTraceFile,"\n\n********\n********\nAccess Pattern of top %d data objects.\n********\n********\n\n",List.size());
	vector<tuple<long,long,int>> innerList;
	int index, totalBytes=0;
	string Key;
	unordered_map <int, vector<int>> Arr;
	int ii,jj,kk;
	
	for ( auto iter = List.begin(); iter != List.end(); ++iter )
	{		
		Key = iter->first;
		vector <string> fields;
		split( fields, Key, is_any_of( "_" ) );
		index = atoi(fields[1].c_str()); 
		innerList = iter->second;

		auto search = dataObjectList.find(Key);
		if(search != dataObjectList.end())
		{
			DataObj tempData = search->second;
			uint64_t head = tempData.data.beg_addr;
			uint64_t tail = tempData.data.end_addr;
			int sizeInBytes = (int)tail-head;
			totalBytes = totalBytes + sizeInBytes;
			if (tempData.data.objectType == DYNAMIC_OBJECT)
				fprintf(gTraceFile,"\n\n\n --> Dynamic Data %d accessed %ld times, bytes=%d, elem=%d",
					index,tempData.counter, sizeInBytes, sizeInBytes/4);//assuming 4
			else if(tempData.data.objectType == STATIC_OBJECT)
				fprintf(gTraceFile,"\n\n\n --> Static Data %d: \"%s\", accessed %ld times, bytes=%d, elem=%d",
					index, GetStringPool()+tempData.data.symName, tempData.counter, sizeInBytes, sizeInBytes/4);//assuming 4
			PrintFullCallingContext(index);
		}

		fprintf(gTraceFile,"\n\nAnchor Points of Data %d:\n",index);

		vector<int> vec;
		for ( kk=0; kk< (floor)((float)CTR/(float)window); kk++ )
		{
			vec.insert(vec.end(),0);
		}

		int length = innerList.size();

		for (ii=0; ii<length ; ii++)
		{
			//print out  
			fprintf(gTraceFile," %ld (%ld) @ %d | ", std::get<0>(innerList[ii]), std::get<1>(innerList[ii]), std::get<2>(innerList[ii]));
			
			//construct the matrix
			vec[(floor)((float)std::get<1>(innerList[ii])/(float)window)] = 1;
			//printf("the index: %d\n",(int)((float)std::get<1>(innerList[ii])/(float)window));
		}
		Arr.insert({index,vec});
	}


	fprintf(gTraceFile,"\n\n\n");
	for ( auto iter = Arr.begin(); iter != Arr.end(); ++iter )
	{
		int index = iter->first;
		vector<int> vec = iter->second;
		fprintf(gTraceFile,"\nvector of %d:\n", index);
		for (jj=0; jj<vec.size(); jj++ )
		{
			fprintf(gTraceFile,"%d\t",vec[jj]);
			//printf("%d\t",vec[jj]);
		}
		fprintf(gTraceFile,"\n");
	}


	//cosine similarity
	for ( auto iter1 = Arr.begin(); iter1 != Arr.end(); ++iter1 )
		for ( auto iter2 = iter1; iter2 != Arr.end(); ++iter2 )
	{
		int index1 = iter1->first;
		int index2 = iter2->first;
		if (index1!=index2)
		{
			vector<int> vec1 = iter1->second;
			vector<int> vec2 = iter2->second;
			
			float up = 0.0, a = 0.0, b = 0.0;
			for (ii=0; ii<vec1.size(); ii++ )
			{
				up = up + (float)(vec1[ii]*vec2[ii]);
				a = a + (float)(vec1[ii]*vec1[ii]);
				b = b + (float)(vec2[ii]*vec2[ii]);
			}
			float sim = up/sqrt(a*b);
			//printf("simliarlity between %d and %d : %f\n", index1,index2,sim);
			if (sim> OutputTH)
				fprintf(gTraceFile,"simliarlity between %d and %d:\t %f\n", index1,index2,sim);
			//if (sim>1)
			//	printf("simliarlity between %d and %d : %f = %f/sqrt(%f*%f).\n", index1,index2,sim,up,a,b);
		}		
	}
	
	fprintf(gTraceFile,"\n\nA total of %d data objects,\ntotal size: %f MB.\n\n",List.size(),(float)totalBytes/1024/1024);
}


VOID ImageUnload(IMG img, VOID * v) {
	//this routine runs only once.
	if (outputflag==false) return;
	//printf("I AM HERE!2\n");
	outputflag = false;
	int ii = 0;
	fprintf(gTraceFile, "\nUnloading %s", IMG_Name(img).c_str());

	//sort
	int length = dataObjectList.size();
	uint32_t indexList[length],ind_tmp;
	long counterList[length],temp;
	float ratioList[length],ratio_temp;
	DataObj tempData;


	ii = 0;
	for ( auto iter = dataObjectList.begin(); iter != dataObjectList.end(); ++iter )
	{		
		//indexList[ii] = iter->first;
		string Key = iter->first;
		vector <string> fields;
		split( fields, Key, is_any_of( "_" ) );
		indexList[ii] = atoi(fields[1].c_str()); 

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
	
	//printf("I AM HERE!4\n");
	fprintf(gTraceFile,"\n\n");
	/*
	for(ii = 0; ii < min(50,length); ii++)
	{
		auto search = dataObjectList.find(indexList[ii]);
		if(search != dataObjectList.end())
		{
			tempData = search->second;
			uint64_t head = tempData.data.beg_addr;
			uint64_t tail = tempData.data.end_addr;
			int sizeInBytes = (int)tail-head;
//			if (tempData.data.objectType == DYNAMIC_OBJECT)
//				fprintf(gTraceFile,"\n\nRank %d --> Dynamic Data %d accessed %ld times, range:[%p,%p], bytes=%d, elem=%d",
//					ii,indexList[ii],tempData.counter,head, tail, sizeInBytes, sizeInBytes/4);//assuming 4
//			else if(tempData.data.objectType == STATIC_OBJECT)
//				fprintf(gTraceFile,"\n\nRank %d --> Static Data %d: \"%s\", accessed %ld times, range:[%p,%p], bytes=%d, elem=%d",
//					ii,indexList[ii], GetStringPool()+tempData.data.symName, tempData.counter,head, tail, sizeInBytes, sizeInBytes/4);//assuming 4
//			PrintFullCallingContext(indexList[ii]);			
		}
	}
*/
	///
	/*
	fprintf(gTraceFile,"\n\n***********************\n***********************\n***Rank by access per element***\n***********************\n***********************\n");
	ii = 0;
	for ( auto iter = dataObjectList.begin(); iter != dataObjectList.end(); ++iter )
	{		
		indexList[ii] = iter->first;
		tempData = iter->second;
		ratioList[ii] = (float)tempData.counter/((float)(tempData.data.end_addr-tempData.data.beg_addr)/4.0);
		ii++;
	}
	for(ii = 0; ii < length; ii++)
        for(int jj = 0; jj < ii; jj++)
		{//sort by # of access
            if(ratioList[jj] < ratioList[ii]){
                ratio_temp = ratioList[jj];
                ratioList[jj] = ratioList[ii];
                ratioList[ii] = ratio_temp;//
				ind_tmp = indexList[jj];
                indexList[jj] = indexList[ii];
                indexList[ii] = ind_tmp;//
			}
		}
	for(ii = 0; ii < min(50,length) ; ii++)
	{
		auto search = dataObjectList.find(indexList[ii]);
		if(search != dataObjectList.end())
		{
			tempData = search->second;
			uint64_t head = tempData.data.beg_addr;
			uint64_t tail = tempData.data.end_addr;
			int sizeInBytes = (int)tail-head;
			if (tempData.data.objectType == DYNAMIC_OBJECT)
				fprintf(gTraceFile,"\n\nRank %d --> Dynamic Data %d accessed %ld times, %f times per element, range:[%p,%p], bytes=%d, elem=%d",
					ii,indexList[ii],tempData.counter,ratioList[ii],head, tail, sizeInBytes, sizeInBytes/4);//assuming 4

			else if (tempData.data.objectType == STATIC_OBJECT )
				fprintf(gTraceFile,"\n\nRank %d --> Static Data %d: \"%s\", accessed %ld times, %f times per element, range:[%p,%p], bytes=%d, elem=%d",
					ii,indexList[ii],GetStringPool()+tempData.data.symName,tempData.counter,ratioList[ii],head, tail, sizeInBytes, sizeInBytes/4);//assuming 4

			PrintFullCallingContext(indexList[ii]);
		}
	}
	*/

	//write file

	ShowPattern(testList);
	
	fprintf(gTraceFile,"\n\nA total of %ld memeroy accesses.\n",CTR);
	fprintf(gTraceFile,"Window size: %ld .\n",window);
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


void updateAnchorPoints(THREADID threadId, uint32_t index, long icounter, void* addr, uint64_t beg_addr, uint64_t end_addr)
{
	long ad = (long)addr - beg_addr;
	int range = end_addr - beg_addr;
	
	int bucket = floor((float)ad/(float)range*10);
	//printf("%ld touched bucket %d.\n", icounter, bucket);

	ostringstream convert1, convert2;
	convert1 << threadId;
	convert2 << index;
	string Key = convert1.str() + "_" + convert2.str();	
	//printf("KEY: %s .\n", Key.c_str());
	
	auto search = testList.find(Key);
	if(search != testList.end()) 
	{
		vector<tuple<long,long,int>> anchorList = search->second;
		//printf("length = %d\n", anchorList.size());
			
		int length = anchorList.size();
//		int bucket_1 = anchorList[length-1].third;//length-1 points to the last element
		int bucket_1 = std::get<2>(anchorList[length-1]);

		//printf("length = %d: {%ld,%ld},{%ld,%ld} | {%ld,%ld}\n",length,ic_2,a_2,ic_1,a_1,icounter,ad);

		if ((bucket_1!=bucket))
		{
			anchorList.insert(anchorList.end(),make_tuple(icounter,CTR,bucket));
		
			testList.erase(Key);
			testList.insert({Key,anchorList});
		}
	}//
	else {
		//construct a new vector and insert it to the hash map
		vector<tuple<long,long,int>> tempAnchorList;
		
		tempAnchorList.insert(tempAnchorList.end(),std::make_tuple(icounter,CTR,bucket));
		//fprintf(gTraceFile,"{%ld,%ld} inserted.\n",icounter,ad);
		//printf("{%ld,%ld} inserted.\n",icounter,ad);
		testList.insert({Key,tempAnchorList});
	
	}
}


void updateDataList(void* addr, DataHandle_t data, THREADID threadId)
{
	uint32_t index =  data.symName;
	ostringstream convert1, convert2;
	convert1 << threadId;
	convert2 << index;
	string Key = convert1.str() + "_" + convert2.str();	

	auto search = dataObjectList.find(Key);
	if(search != dataObjectList.end()) {
		//update existing one:
		DataObj curDataObj = search->second;//search is an iterator.
		DataObj newDataObj;
		
		newDataObj.counter = curDataObj.counter + 1;
		newDataObj.data = curDataObj.data;
		dataObjectList.erase(Key);
		dataObjectList.insert({Key,newDataObj});
    }
	else
	{	//insert new one
		DataObj newDataObj;
		newDataObj.counter = 1;
		newDataObj.data = data;

		dataObjectList.insert({Key,newDataObj});
	}


//	if ((ID<0)&&(data.end_addr - data.beg_addr > 40000))
//	{
//		ID = index;
//	}
//	if ((index==ID)&&(CTR<200))
//	{
//		updateAnchorPoints(index, dataObjectList[index].counter, addr, data.beg_addr, data.end_addr);
//		CTR++;
//	}

	if ((data.end_addr - data.beg_addr >  1 << 10 ))
	{
		updateAnchorPoints(threadId, index, dataObjectList[Key].counter, addr, data.beg_addr, data.end_addr);
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
				//updateDataList(addr, d, threadId);
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


