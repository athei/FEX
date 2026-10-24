// SPDX-License-Identifier: MIT
#include "FEXCore/Utils/LogManager.h"
#include "Interface/Core/Interpreter/Fallbacks/FallbackOpHandler.h"
#include "Interface/IR/IR.h"
#include "Interface/IR/IREmitter.h"
#include "Interface/IR/Passes.h"
#include "Interface/IR/PassManager.h"
#include "FEXCore/IR/IR.h"
#include "FEXCore/Utils/Profiler.h"
#include "FEXCore/Core/HostFeatures.h"
#include "Interface/Core/Addressing.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdint.h>

// This file adds a pass to process X87 stack instructions.
// These instructions are marked in IR.json with `X87: true` and are generated
// by X87 guest instructions.
// The way is works is that there's a virtual stack `StackData`, where we load and store
// and apply the operations in a block of code. Once the block finishes, we emit the necessary operations
// that we recorded onto the virtual stack. This allows us to save a lot of code movement
// to and from stack registers, top management and valid flags. It also allows us to
// perform memcpy optimizations like the one performed in STORESTACKMEM.
//
// By default we run on the fast path - i.e. we assume all values are in the stack and we have a complete
// stack overview. However, if we encounter a value that's not in the virtual stack - maybe it was added
// to the stack in a previous block, we move onto the slow path which loads and stores values to the stack
// registers.
// Once in a slow path, we won't return to the fast pass until the beginning of the following block.

namespace FEXCore::IR {

// FIXME(pmatos): copy from OpcodeDispatcher.h
static uint32_t MMBaseOffset() {
  return static_cast<uint32_t>(offsetof(Core::CPUState, mm[0][0]));
}

// Similar helper to the one in OpcodeDispatcher.h except we do not
// need to handle flags, etc.
template<typename T>
static void DeriveOp(Ref& RefV, IROps NewOp, IREmitter::IRPair<T> Expr) {
  Expr.first->Header.Op = NewOp;
  RefV = Expr;
}

enum class StackSlot { UNUSED, INVALID, VALID };
// FixedSizeStack is a model of the x87 Stack where each element in this
// fixed size stack lives at an offset from top. The top of the stack is at
// index 0.
template<typename T>
class FixedSizeStack {
public:
  struct StackSlotEntry final {
    StackSlot Type = StackSlot::UNUSED;
    T Value = T::Invalid;
  };

  static constexpr uint8_t size = 8;

  // Real top as an offset from stored top value (or the one at the beginning of the block)
  // For example, if we start and push a value to our simulated stack, because we don't
  // update top straight away the TopOffset is 1.
  // If SlowPath is true, then TopOffset is always zero.
  int8_t TopOffset = 0;

  FixedSizeStack() = default;

  void push(const T& Value) {
    rotate();
    buffer.front() = {StackSlot::VALID, Value};
  }

  // Rotate the elements with the direction controlled by Right
  void rotate(bool Right = true) {
    if (Right) {
      std::rotate(buffer.begin(), buffer.end() - 1, buffer.end());
      TopOffset++;
    } else {
      std::rotate(buffer.begin(), buffer.begin() + 1, buffer.end());
      TopOffset--;
    }
  }

  void pop() {
    buffer.front() = {StackSlot::INVALID, T::Invalid};
    rotate(false);
  }

  const StackSlotEntry& top(size_t Offset = 0) const {
    return buffer[Offset];
  }

  void setTop(const T& Value, size_t Offset = 0) {
    buffer[Offset] = {StackSlot::VALID, Value};
  }

  bool isValid(size_t Offset) const {
    return buffer[Offset].Type == StackSlot::VALID;
  }

  void clear() {
    buffer.fill({StackSlot::UNUSED, T::Invalid});
    TopOffset = 0;
  }

  void dump() const {
    LogMan::Msg::DFmt("-- Stack");

    for (size_t i = 0; i < buffer.size(); i++) {
      const auto& [Valid, Element] = buffer[i];
      if (Valid == StackSlot::VALID) {
        LogMan::Msg::DFmt("| ST{}: 0x{:x}", i, (uintptr_t)(Element.StackDataNode));
      } else if (Valid == StackSlot::INVALID) {
        LogMan::Msg::DFmt("| ST{}: INVALID", i);
      }
    }
    LogMan::Msg::DFmt("--");
  }

  void setTagInvalid(size_t Index) {
    buffer[Index].Type = StackSlot::INVALID;
  }

  // Returns a mask to set in AbridgedTagWord
  uint8_t getValidMask() const {
    uint8_t Mask = 0;
    for (size_t i = 0; i < buffer.size(); i++) {
      if (buffer[i].Type == StackSlot::VALID) {
        Mask |= 1U << i;
      }
    }
    return Mask;
  }

  // Returns a mask to set in AbridgedTagWord
  uint8_t getInvalidMask() const {
    uint8_t Mask = 0;
    for (size_t i = 0; i < buffer.size(); i++) {
      if (buffer[i].Type == StackSlot::INVALID) {
        Mask |= 1U << i;
      }
    }
    return Mask;
  }

private:
  std::array<StackSlotEntry, size> buffer {};
};

class X87StackOptimization final : public Pass {
public:
  X87StackOptimization(const FEXCore::HostFeatures& Features, OpSize GPROpSize)
    : Features(Features)
    , GPROpSize(GPROpSize) {
    FEX_CONFIG_OPT(ReducedPrecision, X87REDUCEDPRECISION);
    ReducedPrecisionMode = ReducedPrecision;
  }
  void Run(IREmitter* Emit) override;

private:
  const FEXCore::HostFeatures& Features;
  const OpSize GPROpSize;
  bool ReducedPrecisionMode;
  FEX_CONFIG_OPT(DisableVixlIndirectCalls, DISABLE_VIXL_INDIRECT_RUNTIME_CALLS);

  // Helpers
  Ref RotateRight8(uint32_t V, Ref Amount);

  void F80SplitStore_Helper(const IROp_StoreStackMem* Op, Ref StackNode, Ref AddrNode, Ref Offset, OpSize Align, MemOffsetType OffsetType,
                            uint8_t OffsetScale) {
    IREmit->_StoreMemFPR(OpSize::i64Bit, StackNode, AddrNode, Offset, Align, OffsetType, OffsetScale);
    auto Upper = IREmit->_VExtractToGPR(OpSize::i128Bit, OpSize::i64Bit, StackNode, 1);

    // Store the Upper part of the register (the remaining 2 bytes) into memory.
    AddressMode A {.Base = AddrNode,
                   .Index = Op->Offset.IsInvalid() ? nullptr : Offset,
                   .Offset = 8,
                   .IndexType = MemOffsetType::SXTX,
                   .IndexScale = OffsetScale,
                   .AddrSize = OpSize::i64Bit};
    A = SelectAddressMode(IREmit, A, GPROpSize, Features.SupportsTSOImm9, false, false, OpSize::i16Bit);
    IREmit->_StoreMemGPR(OpSize::i16Bit, Upper, A.Base, A.Index, OpSize::i64Bit, MemOffsetType::SXTX, A.IndexScale);
  }

  void Store80BitToMem(const IROp_StoreStackMem* Op, Ref StackNode, Ref AddrNode, Ref Offset, OpSize Align, MemOffsetType OffsetType,
                       uint8_t OffsetScale) {
    if (Features.SupportsSVE()) {
      AddressMode A {.Base = AddrNode,
                     .Index = Op->Offset.IsInvalid() ? nullptr : Offset,
                     .IndexType = MemOffsetType::SXTX,
                     .IndexScale = OffsetScale,
                     .AddrSize = OpSize::i64Bit};
      AddrNode = LoadEffectiveAddress(IREmit, A, GPROpSize, false);
      IREmit->_StoreMemX87SVEOptPredicate(OpSize::i128Bit, OpSize::i16Bit, StackNode, AddrNode);
    } else {
      F80SplitStore_Helper(Op, StackNode, AddrNode, Offset, Align, OffsetType, OffsetScale);
    }
  }

  void StoreStackMem_Helper(const IRListView& IR, const IROp_StoreStackMem* Op, Ref StackNode) {
    LOGMAN_THROW_A_FMT(!ReducedPrecisionMode, "Full precision mode expected.");

    Ref AddrNode = IR.GetNode(Op->Addr);
    Ref Offset = IR.GetNode(Op->Offset);
    OpSize Align = Op->Align;
    MemOffsetType OffsetType = Op->OffsetType;
    uint8_t OffsetScale = Op->OffsetScale;

    // Normal Precision Mode
    switch (Op->StoreSize) {
    case OpSize::i32Bit:
    case OpSize::i64Bit: {
      StackNode = IREmit->_F80CVT(Op->StoreSize, StackNode);
      IREmit->_StoreMemFPR(Op->StoreSize, StackNode, AddrNode, Offset, Align, OffsetType, OffsetScale);
      break;
    }

    case OpSize::f80Bit: {
      Store80BitToMem(Op, StackNode, AddrNode, Offset, Align, OffsetType, OffsetScale);
      break;
    }
    default: ERROR_AND_DIE_FMT("Unsupported x87 size");
    }
  }

  // Performs a store to memory from a value the stack passed in as StackNode.
  // This is the version dealing with the reduced precision case.
  // Single says that StackNode is a dual value, see X87PCBinop.
  void StoreStackMem_Reduced_Helper(const IRListView& IR, const IROp_StoreStackMem* Op, Ref StackNode, bool Single) {
    LOGMAN_THROW_A_FMT(ReducedPrecisionMode, "Reduced precision mode expected.");

    Ref AddrNode = IR.GetNode(Op->Addr);
    Ref Offset = IR.GetNode(Op->Offset);
    OpSize Align = Op->Align;
    MemOffsetType OffsetType = Op->OffsetType;
    uint8_t OffsetScale = Op->OffsetScale;

    switch (Op->StoreSize) {
    case OpSize::i32Bit: {
      if (Single) {
        StackNode = IREmit->_X87PCToSingle(StackNode);
      } else {
        StackNode = IREmit->_Float_FToF(OpSize::i32Bit, OpSize::i64Bit, StackNode);
      }
      IREmit->_StoreMemFPR(Op->StoreSize, StackNode, AddrNode, Offset, Align, OffsetType, OffsetScale);
      break;
    }
    case OpSize::i64Bit: {
      IREmit->_StoreMemFPR(Op->StoreSize, ToDouble(StackNode, Single), AddrNode, Offset, Align, OffsetType, OffsetScale);
      break;
    }

    case OpSize::f80Bit: {
      StackNode = IREmit->_F80CVTTo(ToDouble(StackNode, Single), OpSize::i64Bit);
      Store80BitToMem(Op, StackNode, AddrNode, Offset, Align, OffsetType, OffsetScale);
      break;
    }
    default: ERROR_AND_DIE_FMT("Unsupported x87 size");
    }
  }

  // Handles a Unary operation.
  // Takes the op we are handling, the Node for the reduced precision case and the node for the normal case.
  // Depending on the type of Op64, we might need to pass a couple of extra constant arguments, this happens
  // when VFOp64 is true.
  void HandleUnop(IROps Op64, bool VFOp64, IROps Op80);
  // Reduced precision x87 with precision control.
  //
  // With 24-bit precision, FADD, FSUB, FMUL, FDIV and FSQRT round their
  // results to 24 bits; nothing else is affected. A block with one of them
  // uses the X87PC ops, which the JIT emits twice: a copy for 53-bit and
  // 64-bit precision that does what the 64-bit ops did before, and a copy for
  // 24-bit precision that works on 32-bit floats. The block picks the copy
  // for the FCW when it is entered, so the same code serves threads that run
  // with different precisions, such as a Direct3D 9 render thread with 24-bit
  // precision and its 53-bit workers.
  //
  // In such a block, values that are exact 32-bit floats in the 24-bit copy
  // are dual: results of the X87PC operations, values loaded from 32-bit
  // memory operands, and checked live-in values, see ScanLiveIns. They stay
  // 32-bit floats in that copy, and are only converted, exactly, where
  // something needs a 64-bit float: the x87 registers in the context at the
  // end of the block, 64-bit and 80-bit stores, transcendentals and the like.
  // An operation with an operand that may have more bits, such as a value
  // from a 64-bit load, uses the 32-bit operation if the JIT finds that
  // operand to be an exact 32-bit float, and otherwise computes in 64 bits
  // and rounds the result. The 24-bit copy has the exponent range of 32-bit
  // floats, see X87PCBinop.
  bool DualMode = false;

  struct StackValue {
    Ref Node;
    // Node is dual, see DualMode.
    bool Single;
  };

  Ref ToDouble(Ref Node, bool Single) {
    return Single ? IREmit->_X87PCToDouble(Node) : Node;
  }
  Ref ToDouble(StackValue Value) {
    return ToDouble(Value.Node, Value.Single);
  }

  // An X87PC operation with a dual operand and a 64-bit one uses
  // X87PCBinopSpec: the JIT converts the 64-bit operand to 32 bits once per
  // block with X87PCSingleCandidate and X87PCSingleExact, and every
  // operation with that operand reuses the result. Every guest load is still
  // performed: for a later 64-bit load from the same address, as for the
  // constants that MSVC uses with FMUL m64 and the like, X87PCSingleSame
  // compares its bits with the earlier load, and the 32-bit float of that
  // one is reused only if they are the same. Otherwise the operation takes
  // its 64-bit path, so memory that changed in between is seen.
  struct SpeculatedDouble {
    Ref Double;
    Ref Candidate;
    Ref Exact;
  };
  std::array<SpeculatedDouble, 16> SpeculatedDoubles {};
  size_t SpeculatedDoubleCount {};
  SpeculatedDouble Speculate(Ref Double);
  // Whether A and B are 64-bit FPR loads from the same address.
  bool SameAddressLoads(Ref A, Ref B);

  // The operand of an F80*Value op. A 32-bit memory operand, which
  // OpcodeDispatcher converts with Float_FToF, becomes a dual value, and so
  // does a dual stack value that OpcodeDispatcher read with ReadStackValue.
  StackValue DualOperand(Ref Node);

  // Whether the block has an operation that the precision control affects.
  static bool BlockHasPrecisionControlOps(const IRListView& IR, Ref BlockNode);

  // Values the block reads from the x87 registers in the context, the ones
  // live in from an earlier block, are 64-bit floats. When a dual block of
  // 24-bit precision writes a dual value there, X87PCStoreLiveOut also writes
  // its 32-bit float to bits 64-95 of the register slot, which reduced
  // precision otherwise only uses for the integer from FILD m64. A later dual
  // block reads its live-in values as dual values if X87PCCheckLiveIns at its
  // start finds the two in agreement for all of them, and in its 24-bit copy
  // loads the 32-bit float, so a value carried around a loop is converted
  // only once per iteration, off the path of the loop. Otherwise the block
  // runs its Precision24Wide copy.
  //
  // The registers are identified by their position relative to TOP at the
  // start of the block, a key from 0 to 7. LiveInMask has the keys the block
  // reads before writing them, found by ScanLiveIns, and WrittenMask the ones
  // it has written so far. Delta is the number of pushes minus pops on the
  // slow path, plus those of the fast path folded into TOP before.
  // SingleOutMask has the keys whose last write stored a dual value with
  // X87PCStoreLiveOut, for LoopSafe of X87PCCheckLiveIns.
  static uint8_t ScanLiveIns(const IRListView& IR, Ref BlockNode);
  uint8_t LiveInMask {};
  uint8_t WrittenMask {};
  uint8_t SingleOutMask {};
  int32_t BaseDelta {};
  int32_t SlowDelta {};
  uint8_t SlotKey(uint8_t Offset) const {
    return (Offset - BaseDelta - SlowDelta) & 7;
  }

  void HandleBinopValue(IROps Op64, bool VFOp64, IROps Op80, uint8_t DestStackOffset, bool MarkDestValid, uint8_t StackOffset,
                        StackValue Value, bool Reverse = false);
  void HandleBinopStack(IROps Op64, bool VFOp64, IROps Op80, uint8_t DestStackOffset, uint8_t StackOffset1, uint8_t StackOffset2,
                        bool Reverse = false);

  // Top Management Helpers
  /// Set the valid tag for Value as valid (if Valid is true), or invalid (if Valid is false).
  void SetX87ValidTag(uint8_t Offset, bool Valid);
  // Generates slow code to load/store a value from an offset from the top of the stack
  Ref LoadStackValueAtOffset_Slow(uint8_t Offset = 0);
  // IntValue is the integer from PushStackInt64 that Value was converted from, if any.
  // Single says that Value is dual, see DualMode.
  void StoreStackValueAtOffset_Slow(Ref Value, uint8_t Offset = 0, bool SetValid = true, Ref IntValue = nullptr, bool Single = false);
  // Reads the top of the stack as a 64-bit integer on the slow path.
  Ref LoadStackValueInt64_Slow(bool Truncate);
  // Update Top value in slow path for a pop
  void UpdateTopForPop_Slow(bool InvalidateTag = true);
  void UpdateTopForPush_Slow();
  // Synchronizes the current simulated stack with the actual values.
  // Returns a new value for Top, that's synchronized between the simulated stack
  // and the actual FPU stack.
  Ref SynchronizeStackValues();
  // Moves us from the fast to the slow path if ShouldMigrate is true.
  void MigrateToSlowPathIf(bool ShouldMigrate);
  // Top Cache Management
  Ref GetTopWithCache_Slow();
  Ref GetOffsetTopWithCache_Slow(uint8_t Offset, bool Reverse = false);
  Ref GetOffsetTopAddressWithCache_Slow(uint8_t Offset);
  void SetTopWithCache_Slow(Ref Value);
  Ref GetX87ValidTag_Slow(uint8_t Offset);
  // Resets fields to initial values
  void Reset();

  struct StackMemberInfo {
    constexpr StackMemberInfo() = default;
    constexpr StackMemberInfo(Ref Data, bool Single = false)
      : StackDataNode(Data)
      , Single(Single) {}
    constexpr StackMemberInfo(Ref Data, Ref Source, OpSize Size, bool Integer = false, bool Single = false)
      : StackDataNode(Data)
      , Single(Single)
      , Source({Size, Source, Integer}) {}
    Ref StackDataNode {}; // Reference to the data in the Stack.
                          // This is the source data node in the stack format, possibly converted to 64/80 bits.
    // StackDataNode is dual, see DualMode.
    bool Single {};
    struct StackMemberData final {
      OpSize Size;
      Ref Node;
      // Node is a signed integer, from PushStackInt64, rather than a float.
      bool Integer;
    };

    static const StackMemberInfo Invalid;

    // Tuple is only valid if we have information about the Source of the Stack Data Node.
    // In it's valid then OpSize is the original source size and Ref is the original source node.
    std::optional<StackMemberData> Source {};
  };

  // StackData, TopCache need to be always properly set to ensure
  // they reflect the current state of the FPU. This sync only makes sense while
  // taking the fast path. Once in the slow path, these don't make sense anymore
  // and we are syncing everything.

  // Index on vector is offset to top value at start of block
  // If slow path is true, then StackData is always empty.
  FixedSizeStack<StackMemberInfo> StackData;

  void InvalidateCaches();
  void InvalidateCachedRegs();

  // Path Migration helper management
  std::optional<StackMemberInfo> MigrateToSlowPath_IfInvalid(uint8_t Offset = 0);
  // Returns the value as a 64-bit float.
  Ref LoadStackValue(uint8_t Offset = 0);
  // Returns the value as it is, dual or not.
  StackValue LoadStackValueDual(uint8_t Offset = 0);
  void StoreStackValue(Ref Value, uint8_t Offset = 0, bool SetValid = false, bool Single = false);
  void StackPop();

  // Cache for Constants
  // ConstantPoll[i] has IREmit->_Constant(i);
  std::array<Ref, 8> ConstantPool {};
  Ref GetConstant(ssize_t Offset);

  // Cached value for Top
  // If slowpath is false, then TopCache is nullptr.
  bool FlushTopPending = false;
  std::array<bool, 8> FlushValuesPending {};
  bool FlushValidPending = false;
  void FlushCachedRegs();

  Ref GetFTW();

  Ref FTWCached {};
  std::array<Ref, 8> TopOffsetCache {};
  std::array<Ref, 8> TopOffsetAddressCache {};
  std::array<Ref, 8> TopValueCache {};
  // For a pending value in TopValueCache, the integer it was converted from by
  // PushStackInt64, or null.
  //
  // In reduced precision, FlushCachedRegs writes that integer to the upper
  // half of the value's 16-byte register slot, which x87 code doesn't use
  // otherwise in that mode, or zero if there is none. A later block's FISTP
  // m64 then stores the integer instead of converting the float back if the
  // float is still the conversion of the integer. A zero passes that check
  // only for 0.0 and -0.0, which convert to 0 anyway, so writing zero for
  // every other value keeps a stale integer from coming back. FRSTOR and
  // FXRSTOR write zero as well, and MMX writes 0xFFFF, which passes only for
  // 65535.0.
  std::array<Ref, 8> TopIntCache {};
  // Whether the value in TopValueCache is dual, see DualMode. FlushCachedRegs
  // converts it to a 64-bit float.
  std::array<bool, 8> TopSingleCache {};
  std::array<StackSlot, 8> TopValidCache {};

  // Are we on the slow path?
  // Once we enter the slow path, we never come out.
  // This just simplifies the code atm. If there's a need to return to the fast path in the future
  // we can implement that but I would expect that there would be very few cases where that's necessary.
  // On the slow path TopCache is always the last obtained version of top.
  // TopOffset is ignored
  bool SlowPath = false;

  // Keeping IREmitter not to pass arguments around
  IREmitter* IREmit = nullptr;
};

inline const X87StackOptimization::StackMemberInfo X87StackOptimization::StackMemberInfo::Invalid {nullptr};

inline void X87StackOptimization::InvalidateCaches() {
  InvalidateCachedRegs();
  ConstantPool.fill(nullptr);
}

inline void X87StackOptimization::InvalidateCachedRegs() {
  FlushCachedRegs();
  FTWCached = {};
  TopOffsetCache.fill(nullptr);
  TopOffsetAddressCache.fill(nullptr);
  TopValueCache.fill(nullptr);
  TopIntCache.fill(nullptr);
  TopSingleCache.fill(false);
  TopValidCache.fill(StackSlot::UNUSED);
}

inline void X87StackOptimization::Reset() {
  SlowPath = false;
  StackData.clear();
  InvalidateCaches();
  LiveInMask = 0;
  WrittenMask = 0;
  SingleOutMask = 0;
  SpeculatedDoubleCount = 0;
  BaseDelta = 0;
  SlowDelta = 0;
}

inline Ref X87StackOptimization::GetConstant(ssize_t Offset) {
  if (Offset < 0 || Offset >= X87StackOptimization::ConstantPool.size()) {
    // not dealt by pool
    return IREmit->_Constant(Offset);
  }
  if (ConstantPool[Offset] == nullptr) {

    ConstantPool[Offset] = IREmit->_Constant(Offset);
  }
  return ConstantPool[Offset];
}

inline void X87StackOptimization::MigrateToSlowPathIf(bool ShouldMigrate) {
  if (ShouldMigrate && !SlowPath) {
    SynchronizeStackValues();
    StackData.clear();
    SlowPath = true;
  }
}

inline Ref X87StackOptimization::GetTopWithCache_Slow() {
  if (!TopOffsetCache[0]) {
    TopOffsetCache[0] = IREmit->_LoadContextGPR(OpSize::i8Bit, offsetof(FEXCore::Core::CPUState, flags) + FEXCore::X86State::X87FLAG_TOP_LOC);
  }
  return TopOffsetCache[0];
}

inline Ref X87StackOptimization::GetOffsetTopWithCache_Slow(uint8_t Offset, bool Reverse) {
  if (Reverse) {
    Offset = 8 - Offset;
  }

  Offset &= 7;

  if (TopOffsetCache[Offset]) {
    return TopOffsetCache[Offset];
  }

  auto* OffsetTop = GetTopWithCache_Slow();
  if (Offset != 0) {
    OffsetTop = IREmit->_And(OpSize::i32Bit, IREmit->Add(OpSize::i32Bit, OffsetTop, Offset), GetConstant(7));
    // GetTopWithCache_Slow already sets the cache so we don't need to set it here for offset == 0
    TopOffsetCache[Offset] = OffsetTop;
  }

  return OffsetTop;
}

inline Ref X87StackOptimization::GetOffsetTopAddressWithCache_Slow(uint8_t Offset) {
  if (TopOffsetAddressCache[Offset]) {
    return TopOffsetAddressCache[Offset];
  }

  Ref OffsetRef = GetOffsetTopWithCache_Slow(Offset);
  TopOffsetAddressCache[Offset] = IREmit->_FormContextAddress(OpSize::i64Bit, OffsetRef, 16);

  return TopOffsetAddressCache[Offset];
}

inline void X87StackOptimization::SetTopWithCache_Slow(Ref Value) {
  InvalidateCachedRegs();
  TopOffsetCache[0] = Value;
  FlushTopPending = true;
}

inline Ref X87StackOptimization::GetFTW() {
  if (!FTWCached) {
    FTWCached = IREmit->_LoadContextGPR(OpSize::i8Bit, offsetof(FEXCore::Core::CPUState, AbridgedFTW));
  }
  return FTWCached;
}

inline void X87StackOptimization::SetX87ValidTag(uint8_t Offset, bool Valid) {
  TopValidCache[Offset] = Valid ? StackSlot::VALID : StackSlot::INVALID;
  FlushValidPending = true;
}

inline Ref X87StackOptimization::GetX87ValidTag_Slow(uint8_t Offset) {
  switch (TopValidCache[Offset]) {
  case StackSlot::UNUSED:
    return IREmit->_And(OpSize::i32Bit, IREmit->_Lshr(OpSize::i32Bit, GetFTW(), GetOffsetTopWithCache_Slow(Offset)), GetConstant(1));
  case StackSlot::INVALID: return GetConstant(0);
  case StackSlot::VALID: return GetConstant(1);
  }
}

inline Ref X87StackOptimization::LoadStackValueAtOffset_Slow(uint8_t Offset) {
  OrderedNode* TopOffsetAddress = GetOffsetTopAddressWithCache_Slow(Offset);
  auto Size = ReducedPrecisionMode ? OpSize::i64Bit : OpSize::i128Bit;
  if (!TopValueCache[Offset]) {
    const uint8_t Key = 1U << SlotKey(Offset);
    if (DualMode && (LiveInMask & Key) && !(WrittenMask & Key)) {
      // A live-in value that X87PCCheckLiveIns checked, see ScanLiveIns.
      TopValueCache[Offset] = IREmit->_X87PCLoadLiveIn(TopOffsetAddress);
      TopSingleCache[Offset] = true;
    } else {
      TopValueCache[Offset] = IREmit->_LoadMemFPR(Size, TopOffsetAddress, IREmit->_InlineConstant(MMBaseOffset()), Size, MemOffsetType::SXTX, 1);
      TopSingleCache[Offset] = false;
    }
  }
  return TopValueCache[Offset];
}

inline void X87StackOptimization::StoreStackValueAtOffset_Slow(Ref Value, uint8_t Offset, bool SetValid, Ref IntValue, bool Single) {
  TopValueCache[Offset] = Value;
  TopIntCache[Offset] = IntValue;
  TopSingleCache[Offset] = Single;
  WrittenMask |= 1U << SlotKey(Offset);
  FlushValuesPending[Offset] = true;
  // mark it valid
  // In some cases we might already know it has been previously set as valid so we don't need to do it again
  if (SetValid) {
    SetX87ValidTag(Offset, true);
  }
}

Ref X87StackOptimization::LoadStackValueInt64_Slow(bool Truncate) {
  const auto Convert = [&](Ref Value) -> Ref {
    if (Truncate) {
      return IREmit->_Vector_FToZS(OpSize::i128Bit, OpSize::i64Bit, Value);
    }
    return IREmit->_Vector_FToS(OpSize::i128Bit, OpSize::i64Bit, Value);
  };

  Ref Value = LoadStackValueAtOffset_Slow();
  Value = ToDouble(Value, TopSingleCache[0]);
  if (FlushValuesPending[0]) {
    // Written in this block: the slot in memory is stale.
    return TopIntCache[0] ? TopIntCache[0] : Convert(Value);
  }

  // The value is the one in memory, so the integer next to it describes it if
  // the value is still that integer's conversion. If it is, the integer is
  // what a real x87 register holds.
  Ref Int = IREmit->_LoadMemFPR(OpSize::i64Bit, GetOffsetTopAddressWithCache_Slow(0), IREmit->_InlineConstant(MMBaseOffset() + 8),
                                OpSize::i64Bit, MemOffsetType::SXTX, 1);
  Ref Same = IREmit->_VFCMPEQ(OpSize::i64Bit, OpSize::i64Bit, Value, IREmit->_Vector_SToF(OpSize::i64Bit, OpSize::i64Bit, Int));
  return IREmit->_VBSL(OpSize::i64Bit, Same, Int, Convert(Value));
}

inline Ref X87StackOptimization::RotateRight8(uint32_t V, Ref Amount) {
  return IREmit->_Lshr(OpSize::i32Bit, GetConstant(V | (V << 8)), Amount);
}

inline std::optional<X87StackOptimization::StackMemberInfo> X87StackOptimization::MigrateToSlowPath_IfInvalid(uint8_t Offset) {
  const auto& [Valid, StackMember] = StackData.top(Offset);
  MigrateToSlowPathIf(Valid != StackSlot::VALID);
  if (Valid == StackSlot::VALID) {
    return StackMember;
  }
  return {};
}

inline X87StackOptimization::StackValue X87StackOptimization::LoadStackValueDual(uint8_t Offset) {
  const auto& Member = MigrateToSlowPath_IfInvalid(Offset);
  if (SlowPath) {
    Ref Value = LoadStackValueAtOffset_Slow(Offset);
    return {Value, TopSingleCache[Offset]};
  }
  return {Member->StackDataNode, Member->Single};
}

inline Ref X87StackOptimization::LoadStackValue(uint8_t Offset) {
  return ToDouble(LoadStackValueDual(Offset));
}

inline void X87StackOptimization::StoreStackValue(Ref Value, uint8_t Offset, bool SetValid, bool Single) {
  if (SlowPath) {
    StoreStackValueAtOffset_Slow(Value, Offset, SetValid, nullptr, Single);
  } else {
    StackData.setTop(StackMemberInfo {Value, Single}, Offset);
  }
}

X87StackOptimization::StackValue X87StackOptimization::DualOperand(Ref Node) {
  if (DualMode && Node->GetUses() == 1) {
    const auto* IROp = IREmit->GetOpHeader(IREmit->WrapNode(Node));
    if (IROp->Op == OP_X87PCTODOUBLE) {
      // A stack value that OpcodeDispatcher read with ReadStackValue, as FCOMI
      // does. The conversion is dead afterwards and removed.
      return {IREmit->UnwrapNode(IROp->C<IROp_X87PCToDouble>()->Value), true};
    }
    if (IROp->Op == OP_FLOAT_FTOF && IROp->ElementSize == OpSize::i64Bit) {
      const auto* Op = IROp->C<IROp_Float_FToF>();
      if (Op->SrcElementSize == OpSize::i32Bit) {
        // The Float_FToF is dead afterwards and removed.
        return {IREmit->_X87PCFromSingle(IREmit->UnwrapNode(Op->Scalar)), true};
      }
    }
  }
  return {Node, false};
}

bool X87StackOptimization::SameAddressLoads(Ref A, Ref B) {
  const auto IsLoad64 = [&](Ref N) -> const IROp_LoadMem* {
    const auto* Header = IREmit->GetOpHeader(IREmit->WrapNode(N));
    if (Header->Op != OP_LOADMEM) {
      return nullptr;
    }
    const auto* Op = Header->C<IROp_LoadMem>();
    return Op->Class == RegClass::FPR && Header->Size == OpSize::i64Bit ? Op : nullptr;
  };
  // The same SSA node, or constants of the same value.
  const auto SameValue = [&](OrderedNodeWrapper A, OrderedNodeWrapper B) {
    if (A == B) {
      return true;
    }
    if (A.IsInvalid() || B.IsInvalid() || A.IsImmediate() || B.IsImmediate()) {
      return false;
    }
    const auto* OpA = IREmit->GetOpHeader(A);
    const auto* OpB = IREmit->GetOpHeader(B);
    if (OpA->Op == OP_CONSTANT && OpB->Op == OP_CONSTANT) {
      return OpA->C<IROp_Constant>()->Constant == OpB->C<IROp_Constant>()->Constant;
    }
    if (OpA->Op == OP_INLINECONSTANT && OpB->Op == OP_INLINECONSTANT) {
      return OpA->C<IROp_InlineConstant>()->Constant == OpB->C<IROp_InlineConstant>()->Constant;
    }
    return false;
  };

  const auto* LoadA = IsLoad64(A);
  const auto* LoadB = IsLoad64(B);
  return LoadA && LoadB && LoadA->OffsetType == LoadB->OffsetType && LoadA->OffsetScale == LoadB->OffsetScale &&
         SameValue(LoadA->Addr, LoadB->Addr) && SameValue(LoadA->Offset, LoadB->Offset);
}

X87StackOptimization::SpeculatedDouble X87StackOptimization::Speculate(Ref Double) {
  for (size_t i = 0; i < SpeculatedDoubleCount; i++) {
    if (SpeculatedDoubles[i].Double == Double) {
      return SpeculatedDoubles[i];
    }
  }
  SpeculatedDouble Result {Double};
  // The first entry for the address is the one with its own candidate.
  for (size_t i = 0; i < SpeculatedDoubleCount; i++) {
    const auto& Earlier = SpeculatedDoubles[i];
    if (SameAddressLoads(Earlier.Double, Double)) {
      Result.Candidate = Earlier.Candidate;
      Result.Exact = IREmit->_X87PCSingleSame(Double, Earlier.Double, Earlier.Exact);
      break;
    }
  }
  if (!Result.Candidate) {
    Result.Candidate = IREmit->_X87PCSingleCandidate(Double);
    Result.Exact = IREmit->_X87PCSingleExact(Double, Result.Candidate);
  }
  if (SpeculatedDoubleCount < SpeculatedDoubles.size()) {
    SpeculatedDoubles[SpeculatedDoubleCount++] = Result;
  }
  return Result;
}

uint8_t X87StackOptimization::ScanLiveIns(const IRListView& IR, Ref BlockNode) {
  // Follows the stack effects of the x87 ops, as the pass handles them below.
  uint8_t LiveIn {};
  uint8_t Written {};
  int32_t Delta {};
  const auto Key = [&](uint32_t Offset) -> uint8_t {
    return 1U << ((Offset - Delta) & 7);
  };
  const auto Read = [&](uint32_t Offset) {
    if (!(Written & Key(Offset))) {
      LiveIn |= Key(Offset);
    }
  };
  const auto Write = [&](uint32_t Offset) {
    Written |= Key(Offset);
  };
  const auto Push = [&]() {
    ++Delta;
    Write(0);
  };
  const auto Pop = [&]() {
    --Delta;
  };

  for (auto [CodeNode, IROp] : IR.GetCode(BlockNode)) {
    switch (IROp->Op) {
    case OP_F80ADDSTACK: {
      const auto* Op = IROp->C<IROp_F80AddStack>();
      Read(Op->SrcStack1);
      Read(Op->SrcStack2);
      Write(Op->SrcStack1);
      break;
    }
    case OP_F80MULSTACK: {
      const auto* Op = IROp->C<IROp_F80MulStack>();
      Read(Op->SrcStack1);
      Read(Op->SrcStack2);
      Write(Op->SrcStack1);
      break;
    }
    case OP_F80SUBSTACK: {
      const auto* Op = IROp->C<IROp_F80SubStack>();
      Read(Op->SrcStack1);
      Read(Op->SrcStack2);
      Write(Op->DstStack);
      break;
    }
    case OP_F80DIVSTACK: {
      const auto* Op = IROp->C<IROp_F80DivStack>();
      Read(Op->SrcStack1);
      Read(Op->SrcStack2);
      Write(Op->DstStack);
      break;
    }
    case OP_F80FPREMSTACK:
    case OP_F80FPREM1STACK:
    case OP_F80SCALESTACK:
      Read(0);
      Read(1);
      Write(0);
      break;
    case OP_F80FYL2XSTACK:
    case OP_F80FYL2XP1STACK:
    case OP_F80ATANSTACK:
      Read(0);
      Read(1);
      Write(1);
      Pop();
      break;
    case OP_F80ADDVALUE:
    case OP_F80SUBVALUE:
    case OP_F80SUBRVALUE:
    case OP_F80MULVALUE:
    case OP_F80DIVVALUE:
    case OP_F80DIVRVALUE: {
      // All of them have SrcStack where F80AddValue has it.
      const auto* Op = IROp->C<IROp_F80AddValue>();
      Read(Op->SrcStack);
      Write(0);
      break;
    }
    case OP_F80SQRTSTACK:
    case OP_F80SINSTACK:
    case OP_F80COSSTACK:
    case OP_F80F2XM1STACK:
    case OP_F80ROUNDSTACK:
    case OP_F80STACKCHANGESIGN:
    case OP_F80STACKABS:
      Read(0);
      Write(0);
      break;
    case OP_F80PTANSTACK:
    case OP_F80SINCOSSTACK:
      Read(0);
      Write(0);
      Push();
      break;
    case OP_INITSTACK:
      // Everything after this is written by the block.
      Written = 0xff;
      break;
    case OP_PUSHSTACK:
    case OP_PUSHSTACKINT64: Push(); break;
    case OP_COPYPUSHSTACK: {
      const auto* Op = IROp->C<IROp_CopyPushStack>();
      Read(Op->StackLocation);
      Push();
      break;
    }
    case OP_READSTACKVALUE: {
      const auto* Op = IROp->C<IROp_ReadStackValue>();
      Read(Op->StackLocation);
      break;
    }
    case OP_READSTACKVALUEINT64:
    case OP_STORESTACKMEM:
    case OP_F80CMPVALUE: Read(0); break;
    case OP_STORESTACKTOSTACK: {
      const auto* Op = IROp->C<IROp_StoreStackToStack>();
      Read(0);
      Write(Op->StackLocation);
      break;
    }
    case OP_POPSTACKDESTROY:
    case OP_INCSTACKTOP: Pop(); break;
    case OP_DECSTACKTOP: ++Delta; break;
    case OP_F80STACKXCHANGE: {
      const auto* Op = IROp->C<IROp_F80StackXchange>();
      if (Op->SrcStack != 0) {
        Read(0);
        Read(Op->SrcStack);
        Write(0);
        Write(Op->SrcStack);
      }
      break;
    }
    case OP_F80CMPSTACK: {
      const auto* Op = IROp->C<IROp_F80CmpStack>();
      Read(0);
      Read(Op->SrcStack);
      break;
    }
    case OP_F80STACKTEST: {
      const auto* Op = IROp->C<IROp_F80StackTest>();
      Read(Op->SrcStack);
      break;
    }
    case OP_F80VBSLSTACK: {
      const auto* Op = IROp->C<IROp_F80VBSLStack>();
      Read(Op->SrcStack1);
      Read(Op->SrcStack2);
      Write(0);
      break;
    }
    default:
      // The others, such as InvalidateStack, StackValidTag and the
      // synchronisation ops, read no value. Ops that aren't x87 don't touch
      // the stack.
      break;
    }
  }
  return LiveIn;
}

bool X87StackOptimization::BlockHasPrecisionControlOps(const IRListView& IR, Ref BlockNode) {
  for (auto [CodeNode, IROp] : IR.GetCode(BlockNode)) {
    switch (IROp->Op) {
    case OP_F80ADDSTACK:
    case OP_F80SUBSTACK:
    case OP_F80MULSTACK:
    case OP_F80DIVSTACK:
    case OP_F80ADDVALUE:
    case OP_F80SUBVALUE:
    case OP_F80SUBRVALUE:
    case OP_F80MULVALUE:
    case OP_F80DIVVALUE:
    case OP_F80DIVRVALUE:
    case OP_F80SQRTSTACK: return true;
    default: break;
    }
  }
  return false;
}

inline void X87StackOptimization::StackPop() {
  if (SlowPath) {
    UpdateTopForPop_Slow();
  } else {
    StackData.pop();
  }
}


void X87StackOptimization::HandleUnop(IROps Op64, bool VFOp64, IROps Op80) {
  if (ReducedPrecisionMode && VFOp64) {
    // FSQRT
    LOGMAN_THROW_A_FMT(DualMode, "Precision control op outside of a dual block");
    const auto St0 = LoadStackValueDual();
    StoreStackValue(IREmit->_X87PCUnop(X87PC_SQRT, St0.Node, St0.Single), 0, false, true);
    return;
  }

  Ref St0 = LoadStackValue();
  Ref Value {};

  if (ReducedPrecisionMode) {
    DeriveOp(Value, Op64, IREmit->_F64SIN(St0));
  } else {
    DeriveOp(Value, Op80, IREmit->_F80SQRT(St0));
  }

  StoreStackValue(Value);
}


void X87StackOptimization::HandleBinopValue(IROps Op64, bool VFOp64, IROps Op80, uint8_t DestStackOffset, bool MarkDestValid,
                                            uint8_t StackOffset, StackValue Value, bool Reverse) {
  LOGMAN_THROW_A_FMT(!Reverse || VFOp64, "There are no reverse operations using non VFOp64 ops");

  if (ReducedPrecisionMode && VFOp64) {
    // FADD, FSUB, FMUL and FDIV, which the precision control affects.
    LOGMAN_THROW_A_FMT(DualMode, "Precision control op outside of a dual block");
    const auto Stack = LoadStackValueDual(StackOffset);
    const auto& Src1 = Reverse ? Value : Stack;
    const auto& Src2 = Reverse ? Stack : Value;

    uint8_t PCOp {};
    switch (Op64) {
    case OP_VFADD: PCOp = X87PC_ADD; break;
    case OP_VFSUB: PCOp = X87PC_SUB; break;
    case OP_VFMUL: PCOp = X87PC_MUL; break;
    case OP_VFDIV: PCOp = X87PC_DIV; break;
    default: LOGMAN_MSG_A_FMT("Unexpected x87 binop"); FEX_UNREACHABLE;
    }

    const uint8_t SingleMask = (Src1.Single ? 1 : 0) | (Src2.Single ? 2 : 0);
    Ref Node {};
    if (SingleMask == 1 || SingleMask == 2) {
      // One 64-bit operand, see SpeculatedDouble.
      const bool DoubleIsSrc1 = SingleMask == 2;
      const auto Spec = Speculate(DoubleIsSrc1 ? Src1.Node : Src2.Node);
      Node = IREmit->_X87PCBinopSpec(PCOp, DoubleIsSrc1 ? Spec.Double : Src1.Node, DoubleIsSrc1 ? Src2.Node : Spec.Double, SingleMask,
                                     Spec.Candidate, Spec.Exact);
    } else {
      Node = IREmit->_X87PCBinop(PCOp, Src1.Node, Src2.Node, SingleMask);
    }
    StoreStackValue(Node, DestStackOffset, MarkDestValid && StackOffset != DestStackOffset, true);
    return;
  }

  Ref ValueNode = ToDouble(Value);
  auto StackNode = LoadStackValue(StackOffset);

  Ref Node = {};
  if (ReducedPrecisionMode) {
    DeriveOp(Node, Op64, IREmit->_F64FPREM(StackNode, ValueNode));
  } else {
    if (Reverse) {
      DeriveOp(Node, Op80, IREmit->_F80Add(ValueNode, StackNode));
    } else {
      DeriveOp(Node, Op80, IREmit->_F80Add(StackNode, ValueNode));
    }
  }

  StoreStackValue(Node, DestStackOffset, MarkDestValid && StackOffset != DestStackOffset);
}

void X87StackOptimization::HandleBinopStack(IROps Op64, bool VFOp64, IROps Op80, uint8_t DestStackOffset, uint8_t StackOffset1,
                                            uint8_t StackOffset2, bool Reverse) {
  auto Value = LoadStackValueDual(StackOffset2);
  HandleBinopValue(Op64, VFOp64, Op80, DestStackOffset, StackOffset2 != DestStackOffset, StackOffset1, Value, Reverse);
}

inline void X87StackOptimization::UpdateTopForPop_Slow(bool InvalidateTag) {
  const auto PopContainer = [](auto& container) {
    const auto begin = std::begin(container);
    std::rotate(begin, std::next(begin), std::end(container));
  };

  if (InvalidateTag) {
    SetX87ValidTag(0, false);
  }

  // Pop the top of the x87 stack
  --SlowDelta;
  GetOffsetTopWithCache_Slow(1);
  PopContainer(TopOffsetCache);
  PopContainer(TopOffsetAddressCache);
  PopContainer(TopValueCache);
  PopContainer(TopIntCache);
  PopContainer(TopSingleCache);
  PopContainer(FlushValuesPending);
  PopContainer(TopValidCache);
  FlushTopPending = true;
}

inline void X87StackOptimization::UpdateTopForPush_Slow() {
  const auto PushContainer = [](auto& container) {
    const auto end = std::end(container);
    std::rotate(std::begin(container), std::prev(end), end);
  };

  // Push the top of the x87 stack
  ++SlowDelta;
  GetOffsetTopWithCache_Slow(1, true);
  PushContainer(TopOffsetCache);
  PushContainer(TopOffsetAddressCache);
  PushContainer(TopValueCache);
  PushContainer(TopIntCache);
  PushContainer(TopSingleCache);
  PushContainer(FlushValuesPending);
  PushContainer(TopValidCache);
  FlushTopPending = true;
}

void X87StackOptimization::FlushCachedRegs() {
  if (FlushTopPending) {
    IREmit->_StoreContextGPR(OpSize::i8Bit, TopOffsetCache[0], offsetof(FEXCore::Core::CPUState, flags) + FEXCore::X86State::X87FLAG_TOP_LOC);
    FlushTopPending = false;
  }

  auto Size = ReducedPrecisionMode ? OpSize::i64Bit : OpSize::i128Bit;
  for (size_t i = 0; i < FlushValuesPending.size(); i++) {
    if (FlushValuesPending[i]) {
      OrderedNode* TopOffsetAddress = GetOffsetTopAddressWithCache_Slow(i);
      const uint8_t Key = 1U << SlotKey(i);
      if (TopSingleCache[i]) {
        // A dual value, which has no integer, see ScanLiveIns.
        // A slot that the block reads as a live-in is likely read again by
        // the block itself, as a loop does.
        IREmit->_X87PCStoreLiveOut(TopValueCache[i], TopOffsetAddress, (LiveInMask & Key) != 0);
        SingleOutMask |= Key;
        FlushValuesPending[i] = false;
        continue;
      }
      SingleOutMask &= ~Key;
      IREmit->_StoreMemFPR(Size, TopValueCache[i], TopOffsetAddress, IREmit->_InlineConstant(MMBaseOffset()), Size, MemOffsetType::SXTX, 1);
      if (ReducedPrecisionMode) {
        // The integer behind the value, or zero, see TopIntCache.
        auto IntOffset = IREmit->_InlineConstant(MMBaseOffset() + 8);
        if (TopIntCache[i]) {
          IREmit->_StoreMemFPR(OpSize::i64Bit, TopIntCache[i], TopOffsetAddress, IntOffset, OpSize::i64Bit, MemOffsetType::SXTX, 1);
        } else {
          IREmit->_StoreMemGPR(OpSize::i64Bit, GetConstant(0), TopOffsetAddress, IntOffset, OpSize::i64Bit, MemOffsetType::SXTX, 1);
        }
      }
      // store
      FlushValuesPending[i] = false;
    }
  }

  if (FlushValidPending) {
    uint8_t ValidMask = 0;
    uint8_t InvalidMask = 0;
    for (auto It = TopValidCache.rbegin(); It != TopValidCache.rend(); It++) {
      ValidMask <<= 1;
      InvalidMask <<= 1;
      if (*It == StackSlot::VALID) {
        ValidMask |= 1;
      } else if (*It == StackSlot::INVALID) {
        InvalidMask |= 1;
      }
    }

    if (ValidMask || InvalidMask) {
      Ref NewFTW = [&]() {
        if (ValidMask == 0xff || InvalidMask == 0xff) {
          // If InvalidMask == 0xff then ValidMask = 0
          return GetConstant(ValidMask);
        } else {
          Ref NewFTW = GetFTW();
          Ref RotAmount {};
          if (std::popcount(ValidMask) == 1) {
            uint8_t BitIdx = std::countr_zero(ValidMask);
            Ref RegMask = IREmit->_Lshl(OpSize::i32Bit, GetConstant(1), GetOffsetTopWithCache_Slow(BitIdx));
            NewFTW = IREmit->_Or(OpSize::i32Bit, NewFTW, RegMask);
          } else if (ValidMask) {
            RotAmount = IREmit->_Sub(OpSize::i32Bit, GetConstant(8), GetTopWithCache_Slow());
            // perform a rotate right on mask by top
            NewFTW = IREmit->_Or(OpSize::i32Bit, NewFTW, RotateRight8(ValidMask, RotAmount));
          }

          if (std::popcount(InvalidMask) == 1) {
            uint8_t BitIdx = std::countr_zero(InvalidMask);
            Ref RegMask = IREmit->_Lshl(OpSize::i32Bit, GetConstant(1), GetOffsetTopWithCache_Slow(BitIdx));
            NewFTW = IREmit->_Andn(OpSize::i32Bit, NewFTW, RegMask);
          } else if (InvalidMask) {
            if (!RotAmount) {
              RotAmount = IREmit->_Sub(OpSize::i32Bit, GetConstant(8), GetTopWithCache_Slow());
            }
            NewFTW = IREmit->_Andn(OpSize::i32Bit, NewFTW, RotateRight8(InvalidMask, RotAmount));
          }
          return NewFTW;
        }
      }();

      IREmit->_StoreContextGPR(OpSize::i8Bit, NewFTW, offsetof(FEXCore::Core::CPUState, AbridgedFTW));
      FTWCached = NewFTW;
    }

    FlushValidPending = false;
  }
}

// We synchronize stack values in a few occasions but one of the most important of those,
// is when we move from fast to a slow path and need to make sure that the context is properly
// written.
Ref X87StackOptimization::SynchronizeStackValues() {
  if (SlowPath) {
    return GetTopWithCache_Slow();
  }

  // Store new top which is now the original top minus recorded top offset
  // Careful with underflow wraparound.
  const auto TopOffset = StackData.TopOffset;

  if (TopOffset != 0) {
    Ref NewTop = GetOffsetTopWithCache_Slow(TopOffset, true);
    SetTopWithCache_Slow(NewTop);
  }
  StackData.TopOffset = 0;
  BaseDelta += TopOffset;

  // Before leaving we need to write the current values in the stack to
  // context so that the values are correct. Copy SourceDataNode in the
  // stack to the respective mmX register.
  Ref TopValue = GetTopWithCache_Slow();
  for (size_t i = 0; i < StackData.size; ++i) {
    const auto& [Valid, StackMember] = StackData.top(i);

    if (Valid == StackSlot::VALID) {
      Ref IntValue = StackMember.Source && StackMember.Source->Integer ? StackMember.Source->Node : nullptr;
      StoreStackValueAtOffset_Slow(StackMember.StackDataNode, i, false, IntValue, StackMember.Single);
    }
  }
  { // Set valid tags
    uint8_t ValidMask = StackData.getValidMask();
    uint8_t InvalidMask = StackData.getInvalidMask();
    for (auto& Elem : TopValidCache) {
      Elem = (ValidMask & 1) ? StackSlot::VALID : ((InvalidMask & 1) ? StackSlot::INVALID : StackSlot::UNUSED);

      ValidMask >>= 1;
      InvalidMask >>= 1;
    }
    FlushValidPending = true;
  }

  return TopValue;
}

void X87StackOptimization::Run(IREmitter* Emit) {
  FEXCORE_PROFILE_SCOPED("PassManager::x87StackOpt");

  auto CurrentIR = Emit->ViewIR();
  auto* HeaderOp = CurrentIR.GetHeader();
  LOGMAN_THROW_A_FMT(HeaderOp->Header.Op == OP_IRHEADER, "First op wasn't IRHeader");

  if (!HeaderOp->HasX87) {
    // If there is no x87 in this, just early exit.
    return;
  }

  // Initialize IREmit member
  IREmit = Emit;

  // Run optimization proper
  for (auto [BlockNode, BlockHeader] : CurrentIR.GetBlocks()) {
    auto BlockIROp = BlockHeader->CW<FEXCore::IR::IROp_CodeBlock>();
    // Each time we deal with a new block we need to start over.
    // The optimization should run per-block
    Reset();
    DualMode = ReducedPrecisionMode && BlockHasPrecisionControlOps(CurrentIR, BlockNode);

    IREmit->SetCurrentCodeBlock(BlockNode);
    Ref CheckNode {};
    if (DualMode) {
      LiveInMask = ScanLiveIns(CurrentIR, BlockNode);
      if (LiveInMask) {
        // Before anything else, so the 24-bit copy can still give way to
        // the wide copy. LoopSafe is set at the end of the block.
        auto [FirstNode, FirstOp] = *CurrentIR.GetCode(BlockNode).begin();
        LOGMAN_THROW_A_FMT(FirstOp->Op == OP_BEGINBLOCK, "Block doesn't start with BeginBlock");
        IREmit->SetWriteCursor(FirstNode);
        CheckNode = IREmit->_X87PCCheckLiveIns(LiveInMask, false);
      }
    }
    for (auto [CodeNode, IROp] : CurrentIR.GetCode(BlockNode)) {
      if (!LoweredX87(IROp->Op)) {
        continue;
      }
      IREmit->SetWriteCursor(CodeNode);
      switch (IROp->Op) {
      case OP_F80ADDSTACK: {
        const auto* Op = IROp->C<IROp_F80AddStack>();
        HandleBinopStack(OP_VFADD, true, OP_F80ADD, Op->SrcStack1, Op->SrcStack1, Op->SrcStack2);
        break;
      }

      case OP_F80SUBSTACK: {
        const auto* Op = IROp->C<IROp_F80SubStack>();
        HandleBinopStack(OP_VFSUB, true, OP_F80SUB, Op->DstStack, Op->SrcStack1, Op->SrcStack2);
        break;
      }

      case OP_F80MULSTACK: {
        const auto* Op = IROp->C<IROp_F80MulStack>();
        HandleBinopStack(OP_VFMUL, true, OP_F80MUL, Op->SrcStack1, Op->SrcStack1, Op->SrcStack2);
        break;
      }

      case OP_F80DIVSTACK: {
        const auto* Op = IROp->C<IROp_F80DivStack>();
        HandleBinopStack(OP_VFDIV, true, OP_F80DIV, Op->DstStack, Op->SrcStack1, Op->SrcStack2);
        break;
      }

      case OP_F80FPREMSTACK: {
        HandleBinopStack(OP_F64FPREM, false, OP_F80FPREM, 0, 0, 1);
        break;
      }

      case OP_F80FPREM1STACK: {
        HandleBinopStack(OP_F64FPREM1, false, OP_F80FPREM1, 0, 0, 1);
        break;
      }

      case OP_F80SCALESTACK: {
        HandleBinopStack(OP_F64SCALE, false, OP_F80SCALE, 0, 0, 1);
        break;
      }

      case OP_F80FYL2XSTACK: {
        HandleBinopStack(OP_F64FYL2X, false, OP_F80FYL2X, 1, 0, 1);
        StackPop();
        break;
      }

      case OP_F80FYL2XP1STACK: {
        HandleBinopStack(OP_F64FYL2XP1, false, OP_F80FYL2XP1, 1, 0, 1);
        StackPop();
        break;
      }

      case OP_F80ATANSTACK: {
        HandleBinopStack(OP_F64ATAN, false, OP_F80ATAN, 1, 1, 0);
        StackPop();
        break;
      }

      case OP_F80ADDVALUE: {
        const auto* Op = IROp->C<IROp_F80AddValue>();
        HandleBinopValue(OP_VFADD, true, OP_F80ADD, 0, true, Op->SrcStack, DualOperand(CurrentIR.GetNode(Op->X80Src)));
        break;
      }

      case OP_F80SUBRVALUE:
      case OP_F80SUBVALUE: {
        const auto* Op = IROp->C<IROp_F80SubValue>();
        HandleBinopValue(OP_VFSUB, true, OP_F80SUB, 0, true, Op->SrcStack, DualOperand(CurrentIR.GetNode(Op->X80Src)), IROp->Op == OP_F80SUBRVALUE);
        break;
      }

      case OP_F80DIVRVALUE:
      case OP_F80DIVVALUE: {
        const auto* Op = IROp->C<IROp_F80DivValue>();
        HandleBinopValue(OP_VFDIV, true, OP_F80DIV, 0, true, Op->SrcStack, DualOperand(CurrentIR.GetNode(Op->X80Src)), IROp->Op == OP_F80DIVRVALUE);
        break;
      }

      case OP_F80MULVALUE: {
        const auto* Op = IROp->C<IROp_F80MulValue>();
        HandleBinopValue(OP_VFMUL, true, OP_F80MUL, 0, true, Op->SrcStack, DualOperand(CurrentIR.GetNode(Op->X80Src)));
        break;
      }

      case OP_F80SQRTSTACK: {
        HandleUnop(OP_VFSQRT, true, OP_F80SQRT);
        break;
      }

      case OP_F80SINSTACK: {
        HandleUnop(OP_F64SIN, false, OP_F80SIN);
        break;
      }

      case OP_F80COSSTACK: {
        HandleUnop(OP_F64COS, false, OP_F80COS);
        break;
      }

      case OP_F80F2XM1STACK: {
        HandleUnop(OP_F64F2XM1, false, OP_F80F2XM1);
        break;
      }


      case OP_F80PTANSTACK: {
        HandleUnop(OP_F64TAN, false, OP_F80TAN);
        Ref OneConst {};
        if (ReducedPrecisionMode) {
          OneConst = IREmit->_VCastFromGPR(OpSize::i64Bit, OpSize::i64Bit, GetConstant(0x3FF0000000000000));
        } else {
          OneConst = IREmit->_LoadNamedVectorConstant(OpSize::i128Bit, NamedVectorConstant::NAMED_VECTOR_X87_ONE);
        }

        if (SlowPath) {
          UpdateTopForPush_Slow();
          StoreStackValueAtOffset_Slow(OneConst);
        } else {
          StackData.push(StackMemberInfo {OneConst});
        }
        break;
      }

      case OP_F80SINCOSSTACK: {
        Ref St0 = LoadStackValue();

        Ref SinValue {};
        Ref CosValue {};

        if (ReducedPrecisionMode) {
          SinValue = IREmit->_F64SIN(St0);
          CosValue = IREmit->_F64COS(St0);
        }
#ifdef VIXL_SIMULATOR
        else if (DisableVixlIndirectCalls() == 0) {
          SinValue = IREmit->_F80SIN(St0);
          CosValue = IREmit->_F80COS(St0);
        }
#endif
        else {
          SinValue = IREmit->_AllocateFPR(OpSize::i128Bit, OpSize::i128Bit);
          CosValue = IREmit->_AllocateFPR(OpSize::i128Bit, OpSize::i128Bit);
          IREmit->_F80SINCOS(St0, SinValue, CosValue);
        }

        // Push values
        if (SlowPath) {
          StoreStackValueAtOffset_Slow(SinValue, 0, false);
          UpdateTopForPush_Slow();
          StoreStackValueAtOffset_Slow(CosValue, 0, true);
        } else {
          StackData.setTop(StackMemberInfo {SinValue});
          StackData.push(StackMemberInfo {CosValue});
        }
        break;
      }

      case OP_INITSTACK: {
        StackData.clear();
        InvalidateCachedRegs();
        // Nothing is live in from earlier blocks any more.
        WrittenMask = 0xff;
        break;
      }

      case OP_INVALIDATESTACK: {
        const auto* Op = IROp->C<IROp_ReadStackValue>();
        auto Offset = Op->StackLocation;

        if (Offset != 0xff) { // invalidate single offset
          if (SlowPath) {
            SetX87ValidTag(Offset, false);
          } else {
            StackData.setTagInvalid(Offset);
          }
        } else { // invalidate all
          if (SlowPath) {
            TopValidCache.fill(StackSlot::INVALID);
            FlushValidPending = true;
          } else {
            for (size_t i = 0; i < StackData.size; i++) {
              StackData.setTagInvalid(i);
            }
          }
        }
        break;
      }

      case OP_PUSHSTACK: {
        const auto* Op = IROp->C<IROp_PushStack>();
        auto* SourceNode = CurrentIR.GetNode(Op->X80Src);

        // FLD m32 in a dual block: the value is the 32-bit float as loaded. The
        // Float_FToF that converted it is dead afterwards and removed.
        bool Single = false;
        if (DualMode && Op->LoadSize == OpSize::i32Bit && !Op->OriginalValue.IsInvalid() && SourceNode->GetUses() == 1) {
          SourceNode = IREmit->_X87PCFromSingle(CurrentIR.GetNode(Op->OriginalValue));
          Single = true;
        }

        if (SlowPath) {
          UpdateTopForPush_Slow();
          StoreStackValueAtOffset_Slow(SourceNode, 0, true, nullptr, Single);
        } else {
          if (Op->OriginalValue.IsInvalid()) {
            // No original value to track - just push the converted data
            StackData.push(StackMemberInfo {SourceNode});
          } else {
            auto* OriginalNode = CurrentIR.GetNode(Op->OriginalValue);
            StackData.push(StackMemberInfo {SourceNode, OriginalNode, Op->LoadSize, false, Single});
          }
        }
        break;
      }

      case OP_PUSHSTACKINT64: {
        // Like PushStack, but the original value is an integer that only
        // ReadStackValueInt64 may use, as its bits aren't the float's.
        LOGMAN_THROW_A_FMT(ReducedPrecisionMode, "Reduced precision mode expected.");
        const auto* Op = IROp->C<IROp_PushStackInt64>();
        auto* SourceNode = CurrentIR.GetNode(Op->X80Src);
        auto* IntNode = CurrentIR.GetNode(Op->IntValue);

        if (SlowPath) {
          UpdateTopForPush_Slow();
          StoreStackValueAtOffset_Slow(SourceNode, 0, true, IntNode);
        } else {
          StackData.push(StackMemberInfo {SourceNode, IntNode, OpSize::i64Bit, true});
        }
        break;
      }

      case OP_COPYPUSHSTACK: {
        const auto* Op = IROp->C<IROp_CopyPushStack>();
        auto Offset = Op->StackLocation;
        auto Value = MigrateToSlowPath_IfInvalid(Offset);

        if (SlowPath) {
          Ref St0 = LoadStackValueAtOffset_Slow(Offset);
          const bool Single = TopSingleCache[Offset];
          UpdateTopForPush_Slow();
          StoreStackValueAtOffset_Slow(St0, 0, true, nullptr, Single);
        } else {
          StackData.push(*Value);
        }
        break;
      }

      case OP_READSTACKVALUE: {
        const auto* Op = IROp->C<IROp_ReadStackValue>();
        auto Offset = Op->StackLocation;
        Ref NewValue = LoadStackValue(Offset);

        IREmit->ReplaceUsesWithAfter(CodeNode, NewValue, CodeNode);
        break;
      }

      case OP_READSTACKVALUEINT64: {
        // FISTP m64. A 64-bit float rounds integers of 2^53 and above, so if
        // the value is still the integer FILD m64 loaded, store that integer
        // instead of converting the float back. A real x87 register holds any
        // 64-bit integer, so the result is the one hardware gives. Arithmetic
        // and other changes to the slot drop the integer. Values from earlier
        // blocks are checked against the integer kept next to them in the
        // register slot, see TopIntCache.
        LOGMAN_THROW_A_FMT(ReducedPrecisionMode, "Reduced precision mode expected.");
        const auto* Op = IROp->C<IROp_ReadStackValueInt64>();
        const auto& Value = MigrateToSlowPath_IfInvalid();

        Ref Result {};
        if (SlowPath) {
          Result = LoadStackValueInt64_Slow(Op->Truncate);
        } else if (Value->Source && Value->Source->Integer) {
          Result = Value->Source->Node;
        } else if (Op->Truncate) {
          Result = IREmit->_Vector_FToZS(OpSize::i128Bit, OpSize::i64Bit, ToDouble(Value->StackDataNode, Value->Single));
        } else {
          Result = IREmit->_Vector_FToS(OpSize::i128Bit, OpSize::i64Bit, ToDouble(Value->StackDataNode, Value->Single));
        }

        IREmit->ReplaceUsesWithAfter(CodeNode, Result, CodeNode);
        break;
      }

      case OP_STACKVALIDTAG: {
        // Returns 0 if value is valid and 1 otherwise.
        const auto* Op = IROp->C<IROp_StackValidTag>();
        auto Offset = Op->StackLocation;
        auto Value = MigrateToSlowPath_IfInvalid(Offset);

        Ref Tag {};
        if (SlowPath) {
          Tag = GetX87ValidTag_Slow(Offset);
        } else {
          Tag = Value ? GetConstant(1) : GetConstant(0);
        }

        IREmit->ReplaceUsesWithAfter(CodeNode, Tag, CodeNode);
        break;
      }

      case OP_STORESTACKMEM: {
        const auto* Op = IROp->C<IROp_StoreStackMem>();
        const auto& Value = MigrateToSlowPath_IfInvalid();
        Ref StackNode = SlowPath ? LoadStackValueAtOffset_Slow() : Value->StackDataNode;
        const bool Single = SlowPath ? TopSingleCache[0] : Value->Single;
        Ref AddrNode = CurrentIR.GetNode(Op->Addr);
        Ref Offset = CurrentIR.GetNode(Op->Offset);
        OpSize Align = Op->Align;
        MemOffsetType OffsetType = Op->OffsetType;
        uint8_t OffsetScale = Op->OffsetScale;

        // On the fast path we can optimize memory copies.
        // If we are doing:
        // fld dword [rax]
        // fst dword [rbx]
        // We can optimize this to:
        // ldr w2, [x0]
        // str w2, [x1]
        // or similar. As long as the source size and dest size are one and the same.
        // This will avoid any conversions between source and stack element size and conversion back.
        OpSize StoreSize = Op->StoreSize;
        LOGMAN_THROW_A_FMT(Op->StoreSize == OpSize::i32Bit || Op->StoreSize == OpSize::i64Bit || Op->StoreSize == OpSize::f80Bit,
                           "Invalid store size in x87 store stack mem");
        // An integer from FILD m64 has the size of a 64-bit float but not its
        // bits, so it has to be converted.
        if (!SlowPath && Value->Source && !Value->Source->Integer && Value->Source->Size == StoreSize) {
          Ref SourceValue = Value->Source->Node;
          if (Op->StoreSize == OpSize::f80Bit) {
            Store80BitToMem(Op, SourceValue, AddrNode, Offset, Align, OffsetType, OffsetScale);
          } else {
            IREmit->_StoreMemFPR(StoreSize, SourceValue, AddrNode, Offset, Align, OffsetType, OffsetScale);
          }
          break;
        }

        if (ReducedPrecisionMode) {
          StoreStackMem_Reduced_Helper(CurrentIR, Op, StackNode, Single);
          break;
        }

        StoreStackMem_Helper(CurrentIR, Op, StackNode);
        break;
      }

      case OP_STORESTACKTOSTACK: { // stores top of stack in another place in stack.
        const auto* Op = IROp->C<IROp_StoreStackToStack>();
        auto Offset = Op->StackLocation;

        auto Value = MigrateToSlowPath_IfInvalid();

        // Need to store st0 to stack location - basically a copy.
        if (SlowPath) {
          Ref St0 = LoadStackValueAtOffset_Slow();
          StoreStackValueAtOffset_Slow(St0, Offset, true, nullptr, TopSingleCache[0]);
        } else {
          StackData.setTop(*Value, Offset);
        }
        break;
      }
      case OP_POPSTACKDESTROY: {
        StackPop();
        break;
      }

      case OP_F80STACKXCHANGE: {
        const auto* Op = IROp->C<IROp_F80StackXchange>();
        auto Offset = Op->SrcStack;

        if (Offset == 0) {
          // No-op
          break;
        }

        const auto [ValidTop, StackMemberTop] = StackData.top(0);
        const auto [ValidOffset, StackMemberOffset] = StackData.top(Offset);

        if (ValidTop != StackSlot::VALID || ValidOffset != StackSlot::VALID) {
          // Slow path: do actual memory operations
          const auto ValueTop = LoadStackValueDual();
          const auto ValueOffset = LoadStackValueDual(Offset);
          StoreStackValue(ValueOffset.Node, 0, true, ValueOffset.Single);
          StoreStackValue(ValueTop.Node, Offset, true, ValueTop.Single);
        } else {
          // Fast path: swap complete StackMemberInfo preserving Source metadata
          StackData.setTop(StackMemberOffset, 0);
          StackData.setTop(StackMemberTop, Offset);
        }
        break;
      }

      case OP_F80STACKCHANGESIGN: {
        if (const auto Dual = LoadStackValueDual(); Dual.Single) {
          StoreStackValue(IREmit->_X87PCUnop(X87PC_NEG, Dual.Node, true), 0, false, true);
          break;
        }
        Ref Value = LoadStackValue();

        // We need a couple of intermediate instructions to change the sign
        // of a value
        Ref ResultNode {};
        if (ReducedPrecisionMode) {
          ResultNode = IREmit->_VFNeg(OpSize::i64Bit, OpSize::i64Bit, Value);
        } else {
          Ref HelperNode = IREmit->_LoadNamedVectorConstant(OpSize::i128Bit, IR::NamedVectorConstant::NAMED_VECTOR_F80_SIGN_MASK);
          ResultNode = IREmit->_VXor(OpSize::i128Bit, Value, HelperNode);
        }
        StoreStackValue(ResultNode);
        break;
      }

      case OP_F80STACKABS: {
        if (const auto Dual = LoadStackValueDual(); Dual.Single) {
          StoreStackValue(IREmit->_X87PCUnop(X87PC_ABS, Dual.Node, true), 0, false, true);
          break;
        }
        Ref Value = LoadStackValue();

        Ref ResultNode {};
        if (ReducedPrecisionMode) {
          ResultNode = IREmit->_VFAbs(OpSize::i64Bit, OpSize::i64Bit, Value);
        } else {
          // Intermediate insts
          Ref HelperNode = IREmit->_LoadNamedVectorConstant(OpSize::i128Bit, IR::NamedVectorConstant::NAMED_VECTOR_F80_SIGN_MASK);
          ResultNode = IREmit->_VAndn(OpSize::i128Bit, Value, HelperNode);
        }
        StoreStackValue(ResultNode);
        break;
      }

      case OP_F80CMPSTACK: {
        const auto* Op = IROp->C<IROp_F80CmpStack>();
        auto Offset = Op->SrcStack;
        const auto Dual1 = LoadStackValueDual();
        const auto Dual2 = LoadStackValueDual(Offset);
        Ref StackValue1 = Dual1.Node;
        Ref StackValue2 = Dual2.Node;

        Ref CmpNode {};
        if (Dual1.Single || Dual2.Single) {
          CmpNode = IREmit->_X87PCCmp(StackValue1, StackValue2, (Dual1.Single ? 1 : 0) | (Dual2.Single ? 2 : 0));
        } else if (ReducedPrecisionMode) {
          CmpNode = IREmit->_FCmp(OpSize::i64Bit, StackValue1, StackValue2);
        } else {
          CmpNode = IREmit->_F80Cmp(StackValue1, StackValue2);
        }

        IREmit->ReplaceUsesWithAfter(CodeNode, CmpNode, CodeNode);
        break;
      }
      case OP_F80STACKTEST: {
        const auto* Op = IROp->C<IROp_F80StackTest>();
        auto Offset = Op->SrcStack;
        const auto Dual = LoadStackValueDual(Offset);
        auto StackNode = Dual.Node;
        Ref ZeroConst = IREmit->_VCastFromGPR(ReducedPrecisionMode ? OpSize::i64Bit : OpSize::i128Bit, OpSize::i64Bit, GetConstant(0));

        Ref CmpNode {};
        if (Dual.Single) {
          // Zero has the same bits as a 32-bit and a 64-bit float, so it is dual too.
          CmpNode = IREmit->_X87PCCmp(StackNode, ZeroConst, 3);
        } else if (ReducedPrecisionMode) {
          CmpNode = IREmit->_FCmp(OpSize::i64Bit, StackNode, ZeroConst);
        } else {
          CmpNode = IREmit->_F80Cmp(StackNode, ZeroConst);
        }
        IREmit->ReplaceUsesWithAfter(CodeNode, CmpNode, CodeNode);
        break;
      }


      case OP_F80CMPVALUE: {
        const auto* Op = IROp->C<IROp_F80CmpValue>();
        const auto DualValue = DualOperand(CurrentIR.GetNode(Op->X80Src));
        const auto DualStack = LoadStackValueDual();
        Ref Value = DualValue.Node;
        Ref StackNode = DualStack.Node;

        Ref CmpNode {};
        if (DualValue.Single || DualStack.Single) {
          CmpNode = IREmit->_X87PCCmp(StackNode, Value, (DualStack.Single ? 1 : 0) | (DualValue.Single ? 2 : 0));
        } else if (ReducedPrecisionMode) {
          CmpNode = IREmit->_FCmp(OpSize::i64Bit, StackNode, Value);
        } else {
          CmpNode = IREmit->_F80Cmp(StackNode, Value);
        }
        IREmit->ReplaceUsesWithAfter(CodeNode, CmpNode, CodeNode);
        break;
      }

      case OP_SYNCSTACKTOSLOW: {
        // This synchronizes stack values but doesn't necessarily moves us off the FastPath!
        Ref NewTop = SynchronizeStackValues();
        FlushCachedRegs();
        IREmit->ReplaceUsesWithAfter(CodeNode, NewTop, CodeNode);
        break;
      }

      case OP_STACKFORCESLOW: {
        MigrateToSlowPathIf(true);
        InvalidateCachedRegs();
        break;
      }

      case OP_INCSTACKTOP: {
        if (SlowPath) {
          UpdateTopForPop_Slow(false);
        } else {
          StackData.rotate(false);
        }
        break;
      }

      case OP_DECSTACKTOP: {
        if (SlowPath) {
          UpdateTopForPush_Slow();
        } else {
          StackData.rotate(true);
        }
        break;
      }

      case OP_F80ROUNDSTACK: {
        Ref St0 = LoadStackValue();

        Ref Value {};
        if (ReducedPrecisionMode) {
          Value = IREmit->_Vector_FToI(OpSize::i64Bit, OpSize::i64Bit, St0, RoundMode::Host);
        } else {
          Value = IREmit->_F80Round(St0);
        }
        StoreStackValue(Value);
        break;
      }

      case OP_F80VBSLSTACK: {
        const auto* Op = IROp->C<IROp_F80VBSLStack>();

        auto StackOffset1 = Op->SrcStack1;
        auto StackOffset2 = Op->SrcStack2;
        auto Value1 = LoadStackValueDual(StackOffset1);
        auto Value2 = LoadStackValueDual(StackOffset2);

        // A selection between two dual values is dual. Otherwise both are
        // selected as 64-bit floats.
        const bool Single = Value1.Single && Value2.Single;
        if (!Single) {
          Value1 = {ToDouble(Value1), false};
          Value2 = {ToDouble(Value2), false};
        }

        Ref StackNode = IREmit->_VBSL(OpSize::i128Bit, CurrentIR.GetNode(Op->VectorMask), Value1.Node, Value2.Node);
        StoreStackValue(StackNode, 0, StackOffset1 && StackOffset2, Single);
        break;
      }

      default: LOGMAN_THROW_A_FMT(false, "IROp was expected to be lowered");
      }
      IREmit->Remove(CodeNode);
    }

    auto Last = CurrentIR.at(BlockIROp->Last);
    --Last;
    auto [LastCodeNode, LastIROp] = Last();
    LOGMAN_THROW_A_FMT(IsBlockExit(LastIROp->Op), "must be exit");
    IREmit->SetWriteCursorBefore(LastCodeNode);
    SynchronizeStackValues();
    FlushCachedRegs();

    if (CheckNode) {
      // The checked slots are the same ones at the end if TOP is, and the
      // check passes for them if this copy didn't write them, or wrote dual
      // values.
      const bool SameTop = ((BaseDelta + SlowDelta) & 7) == 0;
      const uint8_t Unchecked = LiveInMask & WrittenMask & ~SingleOutMask;
      auto* CheckOp = IREmit->GetOpHeader(IREmit->WrapNode(CheckNode))->CW<IROp_X87PCCheckLiveIns>();
      CheckOp->LoopSafe = SameTop && Unchecked == 0;
    }
  }
}

fextl::unique_ptr<Pass> CreateX87StackOptimizationPass(const HostFeatures& Features, OpSize GPROpSize) {
  return fextl::make_unique<X87StackOptimization>(Features, GPROpSize);
}
} // namespace FEXCore::IR
