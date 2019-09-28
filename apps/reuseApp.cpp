#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include <string.h>
#include<sys/mman.h>
#include<assert.h>
#define RET 0xC3
#define NOP 0x90
#define MAX_SZ (15)
#define REUSE_ITER (4000)

typedef void (*FTR)();


void LittleEndianWrite(uint32_t num, char * loc) {
	for(int i = 0; i<4; i++)
		loc[i] = ((char*)&num)[i];
}

FTR CreateNOPProc(uint64_t sz, uint32_t tripCnt) {
	assert(sz > 0);
	// Alloc exec page
	char * mem =  (char *) mmap(0, sz, PROT_WRITE | PROT_READ | PROT_EXEC, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	// fill with 
	memset(mem, NOP, sz-1);
	// Ok, now set up a loop similar to this one
	//    0:	b8 ff ff ff 00       	mov    $0xffffff,%eax // ffffffff will be replaced by tripCnt
        //    5:	90                   	nop // MANY NOPS here
        //    6:	2d 01 00 00 00          sub    $0x1,%eax
        //    9:	75 fa                	jne    5 <foo+0x5> // substituted with 0F 85 cd	offset
        //    b:	c3                	retq
	mem[0] = 0xb8;
	LittleEndianWrite(tripCnt, mem+1);

	const int loopBack = 5;
	//83 e8 01                sub    $0x1,%eax
	const int retSlot = sz-1;
	const int jneSlot = retSlot-6;
	const int subSlot = jneSlot-5;
	mem[subSlot] = 0x2d;
	LittleEndianWrite(1, &mem[subSlot+1]);
	mem[jneSlot] = 0x0F;
	mem[jneSlot+1] = 0x85;
	LittleEndianWrite(5-retSlot, &mem[jneSlot+2]);
	// 75 fa                   jne    back
	// retq
	mem[retSlot] = RET;
	fprintf(stdout, "\n page %lu at %p", sz, mem);

	return (FTR)(mem);
}

#define SLT (13)
int main(){
	FTR f[MAX_SZ];
        for(int i = 5; i < MAX_SZ; i++){
		f[i] = CreateNOPProc(1L<<i, REUSE_ITER);
	}
		//f[SLT] = CreateNOPProc(1L<<SLT, REUSE_ITER);
        for(int i = 5; i < MAX_SZ; i++){
		f[i]();
	}
	return 0;
}




