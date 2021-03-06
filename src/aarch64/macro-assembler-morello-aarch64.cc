// Copyright 2020, VIXL authors
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//   * Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//   * Neither the name of ARM Limited nor the names of its contributors may be
//     used to endorse or promote products derived from this software without
//     specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "macro-assembler-aarch64.h"

namespace vixl {
namespace aarch64 {

void MacroAssembler::Add(CRegister cd, CRegister cn, const Operand& operand) {
  VIXL_ASSERT(allow_macro_instructions_);

  if (operand.IsImmediate()) {
    int64_t imm = operand.GetImmediate();
    if (IsImmAddSub(imm)) {
      // Directly encodable immediates.
      SingleEmissionCheckScope guard(this);
      add(cd, cn, imm);
      return;
    }

    int64_t nimm = (imm == INT64_MIN) ? INT64_MIN : -imm;
    if (IsImmAddSub(nimm)) {
      // Turn `add ..., -<n>` into `sub ..., <n>`.
      SingleEmissionCheckScope guard(this);
      sub(cd, cn, nimm);
      return;
    }
  }

  if (operand.IsExtendedRegister() && !operand.GetRegister().IsSP()) {
    // Directly encodable extended registers.
    // Operand does not allow extended registers with shift amounts over four.
    VIXL_ASSERT(operand.GetShiftAmount() <= 4);
    SingleEmissionCheckScope guard(this);
    add(cd, cn, operand);
    return;
  }

  // Turn `xm, LSL #<n>` into `xm, UXTX #<n>`, like the base ISA `add`.
  // Also turn `xm` into `xm, UXTX #0`, for convenience.
  if (operand.IsPlainRegister() ||
      (operand.IsShiftedRegister() && (operand.GetShift() == LSL))) {
    unsigned shift_amount = operand.GetShiftAmount();
    Register xm = operand.GetRegister();
    if (xm.IsX() && !xm.IsSP() && (shift_amount <= 4)) {
      SingleEmissionCheckScope guard(this);
      add(cd, cn, Operand(xm, UXTX, shift_amount));
      return;
    }
  }

  // Materialise the operand and use the register form.
  UseScratchRegisterScope temps(this);
  temps.Include(cd);
  temps.Exclude(cn);
  Register xm = temps.AcquireX();
  Mov(xm, operand);
  SingleEmissionCheckScope guard(this);
  add(cd, cn, Operand(xm, UXTX));
}

void MacroAssembler::Scbnds(CRegister cd,
                            CRegister cn,
                            const Operand& operand) {
  VIXL_ASSERT(allow_macro_instructions_);

  if (operand.IsImmediate()) {
    uint64_t imm = operand.GetImmediate();
    int shift = 0;
    if (!IsUint6(imm) && ((imm % 4) == 0)) {
      shift = 4;
      imm >>= shift;
    }
    if (IsUint6(imm)) {
      SingleEmissionCheckScope guard(this);
      scbnds(cd, cn, imm, shift);
      return;
    }
  }

  if (operand.IsPlainRegister()) {
    Register xm = operand.GetRegister();
    if (xm.IsX() && !xm.IsSP()) {
      SingleEmissionCheckScope guard(this);
      scbnds(cd, cn, xm);
      return;
    }
  }

  // Materialise the operand and use the register form.
  UseScratchRegisterScope temps(this);
  Register xm = temps.AcquireX();
  Mov(xm, operand);
  SingleEmissionCheckScope guard(this);
  scbnds(cd, cn, xm);
}

void MacroAssembler::Sub(CRegister cd, CRegister cn, const Operand& operand) {
  VIXL_ASSERT(allow_macro_instructions_);

  if (operand.IsImmediate()) {
    int64_t imm = operand.GetImmediate();
    if (IsImmAddSub(imm)) {
      // Encodable cases.
      SingleEmissionCheckScope guard(this);
      sub(cd, cn, imm);
      return;
    }

    int64_t nimm = (imm == INT64_MIN) ? INT64_MIN : -imm;
    if (IsImmAddSub(nimm)) {
      // Turn `sub ..., -<n>` into `add ..., <n>`.
      SingleEmissionCheckScope guard(this);
      add(cd, cn, nimm);
      return;
    }
  }

  // There is no register form of `sub`, so if we can't encode the operand,
  // negate it and pass it to `add`.
  UseScratchRegisterScope temps(this);
  temps.Include(cd);
  temps.Exclude(cn);
  Register xm = temps.AcquireX();
  Neg(xm, operand);
  SingleEmissionCheckScope guard(this);
  add(cd, cn, Operand(xm, UXTX));
}

void MacroAssembler::MorelloBranchSealedIndirect(
    const MemOperand& addr, void (Assembler::*asm_fn)(const MemOperand&)) {
  VIXL_ASSERT(allow_macro_instructions_);
  if (!addr.GetBaseCRegister().IsZero() && addr.IsImmediateOffset()) {
    int64_t offset = addr.GetOffset();
    if (IsScaledInt<7>(offset, kCRegSizeInBytes)) {
      SingleEmissionCheckScope guard(this);
      (this->*asm_fn)(addr);
      return;
    }
  }

  UseScratchRegisterScope temps(this);
  CRegister cn = temps.AcquireC();
  ComputeAddress(cn, addr);
  SingleEmissionCheckScope guard(this);
  (this->*asm_fn)(MemOperand(cn));
}

void MacroAssembler::LoadStoreMacro(CPURegister rt,
                                    const MemOperand& addr,
                                    LoadStoreOpSet op_set) {
  if (op_set.CanEncode(rt, addr)) {
    // Directly encodable cases.
    SingleEmissionCheckScope guard(this);
    LoadStore(rt, addr, op_set, PreferScaledOffset);
    return;
  }

  // TODO: If this is a load, we can include `rt` in the scratch register list
  // (if we also exclude `rn`).

  CPURegister base = addr.GetBase();
  int64_t offset = addr.GetOffset();
  if (addr.IsPreIndex()) {
    // TODO: If we have a register-offset mode, we could save an instruction
    // with immediates that we can pass to `movz` but not `add`. This is simple
    // in principle, but we'd need a variant of ComputeAddress that only
    // performs part of the calculation.
    ComputeAddress(base, MemOperand(base, offset));
    SingleEmissionCheckScope guard(this);
    LoadStore(rt, MemOperand(base), op_set, PreferScaledOffset);
  } else if (addr.IsPostIndex()) {
    {
      SingleEmissionCheckScope guard(this);
      LoadStore(rt, MemOperand(base), op_set, PreferScaledOffset);
    }
    ComputeAddress(base, MemOperand(base, offset));
  } else {
    UseScratchRegisterScope temps(this);
    CPURegister rn = temps.AcquireRRegisterSameSizeAs(base);
    ComputeAddress(rn, addr);
    SingleEmissionCheckScope guard(this);
    LoadStore(rt, MemOperand(rn), op_set, PreferScaledOffset);
  }
}

void MacroAssembler::LoadStorePairMacro(CRegister rt,
                                        CRegister rt2,
                                        const MemOperand& addr,
                                        LoadStorePairOpSet op_set) {
  if (op_set.CanEncode(rt, rt2, addr)) {
    // Directly encodable cases.
    SingleEmissionCheckScope guard(this);
    LoadStorePair(rt, rt2, addr, op_set);
    return;
  }

  // TODO: If this is a load, we can include `rt` and `rt2` in the scratch
  // register list (if we also exclude `rn`).

  CPURegister base = addr.GetBase();
  int64_t offset = addr.GetOffset();
  if (addr.IsPreIndex()) {
    ComputeAddress(base, MemOperand(base, offset));
    SingleEmissionCheckScope guard(this);
    LoadStorePair(rt, rt2, MemOperand(base), op_set);
  } else if (addr.IsPostIndex()) {
    {
      SingleEmissionCheckScope guard(this);
      LoadStorePair(rt, rt2, MemOperand(base), op_set);
    }
    ComputeAddress(base, MemOperand(base, offset));
  } else {
    UseScratchRegisterScope temps(this);
    CPURegister rn = temps.AcquireRRegisterSameSizeAs(base);
    ComputeAddress(rn, addr);
    SingleEmissionCheckScope guard(this);
    LoadStorePair(rt, rt2, MemOperand(rn), op_set);
  }
}

}  // namespace aarch64
}  // namespace vixl
