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
#include <string.h>
#include <sstream>
#include "pin.H"

extern "C" {
#include "xed-interface.h"
}

#define MAX_FILE_PATH (1000)

using namespace std;

INT32 Usage2() {
	PIN_ERROR("CCTLib client Pin tool to gather calling context on each instruction.\n" + KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}



// Main for DeadSpy, initialize the tool, register instrumentation functions and call the target program.
FILE* gTraceFile;

xed_state_t xedState;

// Initialized the needed data structures before launching the target program
void ClientInit(int argc, char* argv[]) {
	// Create output file
	char name[MAX_FILE_PATH] = "client.out.";
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


	xed_uint64_t watchpointRegisterValueCallback(xed_reg_enum_t reg, void *context, xed_bool_t *error);

	xed_tables_init();
	xed_state_init (&xedState, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b, XED_ADDRESS_WIDTH_64b);
	xed_agen_register_callback (watchpointRegisterValueCallback, watchpointRegisterValueCallback);


}

xed_uint64_t watchpointRegisterValueCallback(xed_reg_enum_t reg, void * _ctxt, xed_bool_t *error){
	const CONTEXT * ctxt = (const CONTEXT * )_ctxt;
	*error = 0;
	switch(reg) {
		case XED_REG_RAX:
		case XED_REG_EAX:
		case XED_REG_AX:
		case XED_REG_AL:
			return PIN_GetContextReg(ctxt, REG_RAX);
		case XED_REG_AH: assert(0 && "NYI"); *error=1;


		case XED_REG_RCX:
		case XED_REG_ECX:
		case XED_REG_CX:
				 return PIN_GetContextReg(ctxt,REG_RCX);
		case XED_REG_CH: assert(0 && "NYI"); *error=1;

		case XED_REG_RDX:
		case XED_REG_EDX:
		case XED_REG_DX:
				 return PIN_GetContextReg(ctxt, REG_RDX);
		case XED_REG_DH: assert(0 && "NYI"); *error=1;

		case XED_REG_RBX:
		case XED_REG_EBX:
		case XED_REG_BX:
				 return PIN_GetContextReg(ctxt,REG_RBX);
		case XED_REG_BH: assert(0 && "NYI"); *error=1;

		case XED_REG_RSP:
		case XED_REG_ESP:
		case XED_REG_SP:
				 return PIN_GetContextReg(ctxt,REG_RSP);

		case XED_REG_RBP:
		case XED_REG_EBP:
		case XED_REG_BP:
				 return PIN_GetContextReg(ctxt,REG_RBP);

		case XED_REG_RSI:
		case XED_REG_ESI:
		case XED_REG_SI:
				 return PIN_GetContextReg(ctxt,REG_RSI);

		case XED_REG_RDI:
		case XED_REG_EDI:
		case XED_REG_DI:
				 return PIN_GetContextReg(ctxt,REG_RDI);

		case XED_REG_R8:
		case XED_REG_R8D:
		case XED_REG_R8W:
				 return PIN_GetContextReg(ctxt,REG_R8);

		case XED_REG_R9:
		case XED_REG_R9D:
		case XED_REG_R9W:
				 return PIN_GetContextReg(ctxt,REG_R9);

		case XED_REG_R10:
		case XED_REG_R10D:
		case XED_REG_R10W:
				 return PIN_GetContextReg(ctxt,REG_R10);

		case XED_REG_R11:
		case XED_REG_R11D:
		case XED_REG_R11W:
				 return PIN_GetContextReg(ctxt,REG_R11);

		case XED_REG_R12:
		case XED_REG_R12D:
		case XED_REG_R12W:
				 return PIN_GetContextReg(ctxt,REG_R12);

		case XED_REG_R13:
		case XED_REG_R13D:
		case XED_REG_R13W:
				 return PIN_GetContextReg(ctxt,REG_R13);

		case XED_REG_R14:
		case XED_REG_R14D:
		case XED_REG_R14W:
				 return PIN_GetContextReg(ctxt,REG_R14);

		case XED_REG_R15:
		case XED_REG_R15D:
		case XED_REG_R15W:
				 return PIN_GetContextReg(ctxt,REG_R15);

		case XED_REG_EFLAGS:
				 return PIN_GetContextReg(ctxt,REG_EFLAGS);

		case XED_REG_RIP:
		case XED_REG_EIP:
		case XED_REG_IP:
				 return PIN_GetContextReg(ctxt,REG_RIP);

		case XED_REG_DS: *error=1; assert(0 && "NYI"); break;
		case XED_REG_ES: *error=1; assert(0 && "NYI"); break;
		case XED_REG_SS: *error=1; assert(0 && "NYI"); break;

		case XED_REG_CS:
				 /* Linux stores CS, GS, FS, PAD into one 64b word. */
				 return (uint32_t) PIN_GetContextReg(ctxt,REG_SEG_CS);
		case XED_REG_FS:
				 return (uint32_t) PIN_GetContextReg(ctxt, REG_SEG_FS);
		case XED_REG_GS:
				 return (uint32_t) PIN_GetContextReg(ctxt, REG_SEG_GS);
		default:
				 *error=1;
				 assert(0 && "NYI");
	}
	return 0;
}
#include<unordered_set>

std::unordered_set<ADDRINT> hm;

VOID Checker(ADDRINT addr, ADDRINT ip, const CONTEXT *ctxt, UINT32 idx) {	
	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd, &xedState);

	if(XED_ERROR_NONE != xed_decode(&xedd, (const xed_uint8_t*)(ip), 15 /* max bytes to decode*/)) {
		//printf("get_mem_access_length_and_type failed to disassemble instruction\n");
		return ;
	}
	ADDRINT  address = 0;
	if (XED_ERROR_NONE != xed_agen (&xedd, idx /* memop idx*/, (void *) ctxt, (xed_uint64_t *) (&address)))  {
		return;
	}
	if (addr != (ADDRINT) (address)){
		if(hm.find(addr)  == hm.end()){
			char buf[200];
			if(0 == xed_format_context(XED_SYNTAX_ATT, &xedd, buf , 200,  ip, 0, 0))
				strcpy(buf, "xed_decoded_inst_dump_att_format failed");
			printf("\n %s, %p, %p", buf, (void*)addr, (void *)address);
			hm.insert(addr);
		} else {

		}

	}   
} 

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v) {
	if(INS_IsBranchOrCall(ins) || INS_IsRet(ins)) {
		return;
	}

	// How may memory operations?
	UINT32 memOperands = INS_MemoryOperandCount(ins);
	for(UINT32 i = 0 ; i < memOperands; i++) {
		INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) Checker, IARG_MEMORYOP_EA, i, IARG_INST_PTR,  IARG_CONST_CONTEXT, IARG_UINT32, i, IARG_END);
	}	
}

VOID Fini(INT32 code, VOID *v) {}

int main(int argc, char* argv[]) {
	// Initialize PIN
	if(PIN_Init(argc, argv))
		return Usage2();

	// Initialize Symbols, we need them to report functions and lines
	PIN_InitSymbols();
	// Init Client
	ClientInit(argc, argv);

	// Register Instruction to be called to instrument instructions
	INS_AddInstrumentFunction(Instruction, 0);

	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	// Launch program now
	PIN_StartProgram();
	return 0;
}


