// Reuse-distance test harness: deterministic ASM sequences with known
// expected instruction reuse distances.  Run under Pin with
// ins_reuse_client.so and verify the histogram output.
//
// Usage: reuse_test <test_number>
//   1 = tight_loop_8   (8-ins self-loop,   100K iters, expect dist 7)
//   2 = tight_loop_4   (4-ins self-loop,   100K iters, expect dist 3)
//   3 = tight_loop_2   (2-ins self-loop,   100K iters, expect dist 1)
//   4 = two_blocks     (3+5 alternating,   100K iters, expect dist 7)
//   5 = two_blocks_32  (16+16 alternating, 100K iters, expect dist 31)
//   6 = single_ins     (1-ins LOOP-self,   100K iters, expect dist 0)

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define NOP 0x90
#define RET 0xC3

typedef void (*FTR)();

static void WriteLE32(uint32_t num, char* loc) {
    for (int i = 0; i < 4; i++)
        loc[i] = ((char*)&num)[i];
}

// Create a tight loop:
//   mov eax, tripCount     ; 5 bytes  (BBL of initial trace only)
//   loop:
//     nop x numNops         ; numNops bytes
//     sub eax, 1            ; 5 bytes
//     jnz loop              ; 6 bytes  (0F 85 rel32)
//   ret                     ; 1 byte
//
// The self-looping BBL (iterations 2..tripCount) has (numNops + 2) instructions:
//   numNops NOPs + sub + jnz
static FTR CreateTightLoop(int numNops, uint32_t tripCount) {
    int sz = 5 + numNops + 5 + 6 + 1;
    char* mem = (char*)mmap(0, sz, PROT_WRITE | PROT_READ | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    // mov eax, tripCount
    mem[0] = 0xB8;
    WriteLE32(tripCount, mem + 1);

    // NOPs
    memset(mem + 5, NOP, numNops);

    // sub eax, 1  (opcode 2D id)
    int subPos = 5 + numNops;
    mem[subPos] = 0x2D;
    WriteLE32(1, mem + subPos + 1);

    // jnz back to first NOP at position 5  (0F 85 cd)
    int jnzPos = subPos + 5;
    mem[jnzPos] = 0x0F;
    mem[jnzPos + 1] = 0x85;
    int32_t offset = 5 - (jnzPos + 6);
    WriteLE32((uint32_t)offset, mem + jnzPos + 2);

    // ret
    mem[jnzPos + 6] = RET;

    return (FTR)mem;
}

// Create two alternating BBLs:
//   mov eax, tripCount         ; 5 bytes (initial trace only)
//   blockA:                     ; ← jnz target
//     nop x nA                  ; nA bytes
//     jmp blockB                ; 5 bytes (E9 cd)
//   blockB:                     ; ← jmp target
//     nop x nB                  ; nB bytes
//     sub eax, 1                ; 5 bytes
//     jnz blockA                ; 6 bytes (0F 85 cd)
//   ret                         ; 1 byte
//
// After the first iteration:
//   BBL_A  = nop×nA + jmp   = (nA + 1) instructions
//   BBL_B  = nop×nB + sub + jnz = (nB + 2) instructions
// Total unique instructions in steady state = (nA + 1) + (nB + 2) = nA + nB + 3
// True reuse distance for every instruction = total - 1 = nA + nB + 2
static FTR CreateTwoBlocks(int nA, int nB, uint32_t tripCount) {
    int sz = 5 + nA + 5 + nB + 5 + 6 + 1;
    char* mem = (char*)mmap(0, sz, PROT_WRITE | PROT_READ | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    // mov eax, tripCount
    mem[0] = 0xB8;
    WriteLE32(tripCount, mem + 1);

    // Block A starts at position 5 (loop-back target)
    int aStart = 5;
    memset(mem + aStart, NOP, nA);

    // jmp to blockB  (E9 cd, offset relative to end of jmp)
    int jmpPos = aStart + nA;
    int bStart = jmpPos + 5;
    mem[jmpPos] = 0xE9;
    int32_t jmpOff = bStart - (jmpPos + 5); // = 0: falls through to next byte
    WriteLE32((uint32_t)jmpOff, mem + jmpPos + 1);

    // Block B NOPs
    memset(mem + bStart, NOP, nB);

    // sub eax, 1
    int subPos = bStart + nB;
    mem[subPos] = 0x2D;
    WriteLE32(1, mem + subPos + 1);

    // jnz blockA  (target = aStart = 5)
    int jnzPos = subPos + 5;
    mem[jnzPos] = 0x0F;
    mem[jnzPos + 1] = 0x85;
    int32_t jnzOff = aStart - (jnzPos + 6);
    WriteLE32((uint32_t)jnzOff, mem + jnzPos + 2);

    // ret
    mem[jnzPos + 6] = RET;

    fprintf(stdout, "  blockA at %p: %d ins (nA=%d NOPs + jmp)\n",
            mem + aStart, nA + 1, nA);
    fprintf(stdout, "  blockB at %p: %d ins (nB=%d NOPs + sub + jnz)\n",
            mem + bStart, nB + 2, nB);

    return (FTR)mem;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <test_number>\n", argv[0]);
        fprintf(stderr, "  1: tight_loop_8   (8-ins self-loop)\n");
        fprintf(stderr, "  2: tight_loop_4   (4-ins self-loop)\n");
        fprintf(stderr, "  3: tight_loop_2   (2-ins self-loop)\n");
        fprintf(stderr, "  4: two_blocks     (3+5 alternating)\n");
        fprintf(stderr, "  5: two_blocks_32  (16+16 alternating)\n");
        fprintf(stderr, "  6: single_ins     (1-ins LOOP-self)\n");
        return 1;
    }

    int test = atoi(argv[1]);
    const uint32_t ITERS = 100000;

    switch (test) {
    case 1: {
        // 8-ins self-looping BBL: 6 NOPs + sub + jnz
        // True reuse distance = 8 - 1 = 7 → bin 3 [4,8)
        fprintf(stdout, "Test 1: tight_loop_8\n");
        fprintf(stdout, "  Self-looping BBL: 8 instructions\n");
        fprintf(stdout, "  Expected reuse distance: 7 (bin 3 [4,8))\n");
        fprintf(stdout, "  Expected histogram entries: ~%u at bin 3\n",
                8 * (ITERS - 1));
        FTR f = CreateTightLoop(6, ITERS);
        f();
        break;
    }
    case 2: {
        // 4-ins self-looping BBL: 2 NOPs + sub + jnz
        // True reuse distance = 4 - 1 = 3 → bin 2 [2,4)
        fprintf(stdout, "Test 2: tight_loop_4\n");
        fprintf(stdout, "  Self-looping BBL: 4 instructions\n");
        fprintf(stdout, "  Expected reuse distance: 3 (bin 2 [2,4))\n");
        fprintf(stdout, "  Expected histogram entries: ~%u at bin 2\n",
                4 * (ITERS - 1));
        FTR f = CreateTightLoop(2, ITERS);
        f();
        break;
    }
    case 3: {
        // 2-ins self-looping BBL: sub + jnz (no NOPs)
        // True reuse distance = 2 - 1 = 1 → bin 1 [1,2)
        fprintf(stdout, "Test 3: tight_loop_2\n");
        fprintf(stdout, "  Self-looping BBL: 2 instructions\n");
        fprintf(stdout, "  Expected reuse distance: 1 (bin 1 [1,2))\n");
        fprintf(stdout, "  Expected histogram entries: ~%u at bin 1\n",
                2 * (ITERS - 1));
        FTR f = CreateTightLoop(0, ITERS);
        f();
        break;
    }
    case 4: {
        // Two alternating BBLs: A(3 ins) + B(5 ins) = 8 unique
        // nA=2 → BBL_A = 3 ins (2 NOPs + jmp)
        // nB=3 → BBL_B = 5 ins (3 NOPs + sub + jnz)
        // True reuse distance = 8 - 1 = 7 → bin 3 [4,8)
        fprintf(stdout, "Test 4: two_blocks (A=3, B=5, total=8)\n");
        fprintf(stdout, "  Expected reuse distance: 7 (bin 3 [4,8))\n");
        fprintf(stdout, "  Expected histogram entries: ~%u at bin 3\n",
                8 * (ITERS - 1));
        FTR f = CreateTwoBlocks(2, 3, ITERS);
        f();
        break;
    }
    case 5: {
        // Two alternating BBLs: A(16 ins) + B(16 ins) = 32 unique
        // nA=15 → BBL_A = 16 ins (15 NOPs + jmp)
        // nB=14 → BBL_B = 16 ins (14 NOPs + sub + jnz)
        // True reuse distance = 32 - 1 = 31 → bin 5 [16,32)
        fprintf(stdout, "Test 5: two_blocks_32 (A=16, B=16, total=32)\n");
        fprintf(stdout, "  Expected reuse distance: 31 (bin 5 [16,32))\n");
        fprintf(stdout, "  Expected histogram entries: ~%u at bin 5\n",
                32 * (ITERS - 1));
        FTR f = CreateTwoBlocks(15, 14, ITERS);
        f();
        break;
    }
    case 6: {
        // 1-instruction self-looping BBL: LOOP self (E2 FE)
        // mov ecx, ITERS  sets RCX (zero-extended in 64-bit mode)
        // LOOP decrements RCX, jumps to self while RCX != 0
        // Pin sees: initial BBL [mov ecx + LOOP] (2 ins), then
        //           self-loop BBL [LOOP] (1 ins) for remaining iters
        // True reuse distance for the 1-ins BBL = 0 (bin 0)
        // Bug: FindSumGreaterEqual reports distance 1 (bin 1)
        fprintf(stdout, "Test 6: single_ins\n");
        fprintf(stdout, "  Self-looping BBL: 1 instruction (LOOP self)\n");
        fprintf(stdout, "  Expected reuse distance: 0 (bin 0)\n");
        fprintf(stdout, "  Expected histogram entries: ~%u at bin 0\n",
                ITERS - 2);
        fflush(stdout);

        int sz = 5 + 2 + 1; // mov ecx + loop + ret
        char* mem = (char*)mmap(0, sz, PROT_WRITE | PROT_READ | PROT_EXEC,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) {
            perror("mmap");
            exit(1);
        }

        // mov ecx, ITERS  (B9 + imm32, zero-extends to RCX)
        mem[0] = 0xB9;
        WriteLE32(ITERS, mem + 1);

        // loop self (E2 FE = loop -2, back to this instruction)
        mem[5] = 0xE2;
        mem[6] = 0xFE;

        // ret (fall-through when RCX reaches 0)
        mem[7] = RET;

        ((FTR)mem)();
        break;
    }
    default:
        fprintf(stderr, "Unknown test: %d\n", test);
        return 1;
    }

    return 0;
}
