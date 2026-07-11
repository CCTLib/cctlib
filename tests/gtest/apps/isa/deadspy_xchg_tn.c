// Deadspy ISA edge case: LOCK XCHG.
//
// This is a TRUE-NEGATIVE test. XCHG r, m is a read-modify-write per
// Intel SDM: the memory operand is read into the register while the
// register is stored to memory (atomically -- xchg with memory always
// implies LOCK).
//
// Pin classifies XCHG's memory operand as BOTH read and written.
// Deadspy inserts the read callback before the write callback at
// IPOINT_BEFORE, so on each XCHG the read side sets the shadow to
// READ_ACTION before the write side checks it. Two consecutive XCHGs
// to the same address therefore produce NO dead write reports:
//   xchg #1 read  -> shadow cleared to READ (kills any prior "written")
//   xchg #1 write -> shadow was READ, so nothing reported; -> WRITE
//   xchg #2 read  -> shadow cleared to READ (kills xchg #1's "written")
//   xchg #2 write -> shadow was READ, so nothing reported; -> WRITE
//
// If deadspy ever loses the read-before-write ordering, or a Pin change
// reclassifies XCHG's memory operand as write-only, we'd start seeing
// ~8B * WORK_COUNT extra dead bytes here -- the point of the assertion
// in DeadspyIsa.XchgIsNotFalselyDead.
//
// Contrast: a plain MOV pair does NOT read memory before writing, so
// two consecutive MOVs to the same address DO produce dead writes.
// See deadspy_tp_simple / the sse16/avx32/etc _tp victims for that.
//
// History: this file was previously deadspy_xchg_tp.c with an inverted
// (true-positive) assertion. That assertion passed only because -O0
// compilation produced ~320K bytes of dead stack writes to unused local
// slots that dominated over the actual (zero) XCHG contribution. At
// -O2, GrandTotalDead was baseline (~12K), proving XCHG produces no
// dead writes -- exactly what x86 semantics say. Reclassified as _tn.
//
// Design notes: victim builds at -O0 (ISA_CFLAGS default). To keep the
// per-iteration stack traffic from unused locals out of the dead-count
// signal, all XCHG operands are file-scope static globals -- no per-
// iteration locals are declared in the loop body -- and the loop body
// is entirely inline asm with explicit register clobbers.
#include <stdint.h>
#define WORK_COUNT 20000
static volatile uint64_t sink;
static uint64_t buf[WORK_COUNT];
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    // Two register variables that live for the whole loop; no per-iter
    // stack slot chatter for the compiler to leak into deadspy's count.
    register uint64_t v1 __asm__("r14") = 0x1111;
    register uint64_t v2 __asm__("r15") = 0x2222;
    for (int i = 0; i < WORK_COUNT; ++i) {
        __asm__ __volatile__(
            "xchgq %[v1], (%[p])\n\t"  // atomic 8B RMW -- read-then-write
            "xchgq %[v2], (%[p])\n\t"  // atomic 8B RMW -- second read clears
                                       // first write's shadow marker
            : [v1] "+r"(v1), [v2] "+r"(v2)
            : [p]  "r"(&buf[i])
            : "memory");
    }
    sink = buf[0] ^ v1 ^ v2;
    return 0;
}
