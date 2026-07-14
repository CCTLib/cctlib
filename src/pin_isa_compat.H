// @COPYRIGHT@
// Licensed under MIT license.
// See LICENSE.TXT file in the project root for more information.
// ==============================================================
//
// pin_isa_compat.H
// -----------------
// Shims for a handful of Pin-2.x/3.x APIs that were removed or renamed in
// Pin 4.x. Included by CCTLib client tools so that the source can keep
// using the pre-Pin-4 names without runtime cost.
//
// All shims are inline / #define; they cost nothing at analysis time.
// The two helpers that must scan operands (MemoryReadSize/MemoryWriteSize)
// are only ever invoked from instrumentation callbacks (BBL_/TRACE_ once
// per instruction), NOT from per-access analysis routines, so a small
// loop over operands is fine.
//
// Reference: Pin 4.x README "Breaking Changes Between Pin 3 and Pin 4"
// and "Recent Changes" sections list the removed APIs.
//
#ifndef CCTLIB_PIN_ISA_COMPAT_H
#define CCTLIB_PIN_ISA_COMPAT_H

#include "pin.H"
// PINTOOL_REGISTER is a wide union (up to 1024B) that fills the same role
// as the old PIN_REGISTER union. Same field names (byte/word/dword/qword/
// s_byte/s_word/s_dword/s_qword/flt/dbl), so source code that read fields
// off a PIN_REGISTER* keeps compiling unchanged after the typedef below.
#include "regvalue_utils.h"

// -----------------------------------------------------------------------
// Type / register renames
// -----------------------------------------------------------------------
// Pin 4.x replaced the PIN_REGISTER union with the wider PINTOOL_REGISTER
// (see $PIN_ROOT/source/tools/Utils/regvalue_utils.h). The union has the
// same field names, so a plain typedef is safe and callback signatures
// keep matching IARG_REG_REFERENCE / IARG_REG_CONST_REFERENCE.
using PIN_REGISTER = PINTOOL_REGISTER;

// REG_is_in_X87(reg) -> REG_is_st(reg). Same semantics: true iff `reg` is
// one of the x87 stack registers ST0..ST7 (REG_CLASS_ST).
static inline BOOL REG_is_in_X87(REG reg) {
    return REG_is_st(reg);
}

// -----------------------------------------------------------------------
// Instruction predicates
// -----------------------------------------------------------------------
// INS_IsIndirectBranchOrCall(ins) -> INS_IsIndirectControlFlow(ins).
// The new name is broader (also matches indirect JMP FAR), but for the
// filtering these clients do it is a strict superset with the same intent.
static inline BOOL INS_IsIndirectBranchOrCall(INS ins) {
    return INS_IsIndirectControlFlow(ins);
}

// INS_IsMaskedJump(ins) was removed in Pin 4. In older Pin releases it
// returned true for the "predicated" jumps that always execute but whose
// target is determined by a register/state test: JECXZ, JCXZ, JRCXZ, and
// the LOOP family. CCTLib clients call it (together with INS_IsFarJump/
// INS_IsDirectFarJump) purely to *skip* these edge-case control-flow
// instructions from redundancy analysis. Reproducing the same set is
// therefore safe and matches the historical semantics.
static inline BOOL INS_IsMaskedJump(INS ins) {
    switch (INS_Opcode(ins)) {
    case XED_ICLASS_JECXZ:
    case XED_ICLASS_JCXZ:
    case XED_ICLASS_JRCXZ:
    case XED_ICLASS_LOOP:
    case XED_ICLASS_LOOPE:
    case XED_ICLASS_LOOPNE:
        return TRUE;
    default:
        return FALSE;
    }
}

// -----------------------------------------------------------------------
// Memory operand sizes
// -----------------------------------------------------------------------
// INS_MemoryReadSize(ins)  == sum over read  operands of INS_MemoryOperandSize
// INS_MemoryWriteSize(ins) == sum over write operands of INS_MemoryOperandSize
//
// The vast majority of x86 instructions have exactly one memory operand,
// so this reduces to a single conditional load. We keep the loop generic
// so vector gathers/scatters, XCHG-with-memory, MOVS, etc. are handled
// correctly. Only used at instrumentation time; not on the analysis hot
// path.
static inline USIZE INS_MemoryReadSize(INS ins) {
    USIZE total = 0;
    const UINT32 n = INS_MemoryOperandCount(ins);
    for (UINT32 i = 0; i < n; ++i) {
        if (INS_MemoryOperandIsRead(ins, i))
            total += INS_MemoryOperandSize(ins, i);
    }
    return total;
}

static inline USIZE INS_MemoryWriteSize(INS ins) {
    USIZE total = 0;
    const UINT32 n = INS_MemoryOperandCount(ins);
    for (UINT32 i = 0; i < n; ++i) {
        if (INS_MemoryOperandIsWritten(ins, i))
            total += INS_MemoryOperandSize(ins, i);
    }
    return total;
}

#endif // CCTLIB_PIN_ISA_COMPAT_H
