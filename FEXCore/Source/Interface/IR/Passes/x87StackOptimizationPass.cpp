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
  void StoreStackMem_Reduced_Helper(const IRListView& IR, const IROp_StoreStackMem* Op, Ref StackNode) {
    LOGMAN_THROW_A_FMT(ReducedPrecisionMode, "Reduced precision mode expected.");

    Ref AddrNode = IR.GetNode(Op->Addr);
    Ref Offset = IR.GetNode(Op->Offset);
    OpSize Align = Op->Align;
    MemOffsetType OffsetType = Op->OffsetType;
    uint8_t OffsetScale = Op->OffsetScale;

    switch (Op->StoreSize) {
    case OpSize::i32Bit: {
      StackNode = IREmit->_Float_FToF(OpSize::i32Bit, OpSize::i64Bit, StackNode);
      [[fallthrough]];
    }
    case OpSize::i64Bit: {
      IREmit->_StoreMemFPR(Op->StoreSize, StackNode, AddrNode, Offset, Align, OffsetType, OffsetScale);
      break;
    }

    case OpSize::f80Bit: {
      StackNode = IREmit->_F80CVTTo(StackNode, OpSize::i64Bit);
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
  void HandleBinopValue(IROps Op64, bool VFOp64, IROps Op80, uint8_t DestStackOffset, bool MarkDestValid, uint8_t StackOffset,
                        Ref ValueNode, bool Reverse = false);
  void HandleBinopStack(IROps Op64, bool VFOp64, IROps Op80, uint8_t DestStackOffset, uint8_t StackOffset1, uint8_t StackOffset2,
                        bool Reverse = false);

  // Top Management Helpers
  /// Set the valid tag for Value as valid (if Valid is true), or invalid (if Valid is false).
  void SetX87ValidTag(uint8_t Offset, bool Valid);
  // Generates slow code to load/store a value from an offset from the top of the stack
  Ref LoadStackValueAtOffset_Slow(uint8_t Offset = 0);
  // IntValue is the integer from PushStackInt64 that Value was converted from, if any.
  void StoreStackValueAtOffset_Slow(Ref Value, uint8_t Offset = 0, bool SetValid = true, Ref IntValue = nullptr);
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
    constexpr StackMemberInfo(Ref Data)
      : StackDataNode(Data) {}
    constexpr StackMemberInfo(Ref Data, Ref Source, OpSize Size, bool Integer = false)
      : StackDataNode(Data)
      , Source({Size, Source, Integer}) {}
    Ref StackDataNode {}; // Reference to the data in the Stack.
                          // This is the source data node in the stack format, possibly converted to 64/80 bits.
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
  Ref LoadStackValue(uint8_t Offset = 0);
  void StoreStackValue(Ref Value, uint8_t Offset = 0, bool SetValid = false);
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
  TopValidCache.fill(StackSlot::UNUSED);
}

inline void X87StackOptimization::Reset() {
  SlowPath = false;
  StackData.clear();
  InvalidateCaches();
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
    TopValueCache[Offset] = IREmit->_LoadMemFPR(Size, TopOffsetAddress, IREmit->_InlineConstant(MMBaseOffset()), Size, MemOffsetType::SXTX, 1);
  }
  return TopValueCache[Offset];
}

inline void X87StackOptimization::StoreStackValueAtOffset_Slow(Ref Value, uint8_t Offset, bool SetValid, Ref IntValue) {
  TopValueCache[Offset] = Value;
  TopIntCache[Offset] = IntValue;
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

inline Ref X87StackOptimization::LoadStackValue(uint8_t Offset) {
  const auto& StackValue = MigrateToSlowPath_IfInvalid(Offset);
  return SlowPath ? LoadStackValueAtOffset_Slow(Offset) : StackValue->StackDataNode;
}

inline void X87StackOptimization::StoreStackValue(Ref Value, uint8_t Offset, bool SetValid) {
  if (SlowPath) {
    StoreStackValueAtOffset_Slow(Value, Offset, SetValid);
  } else {
    StackData.setTop(StackMemberInfo {Value}, Offset);
  }
}

inline void X87StackOptimization::StackPop() {
  if (SlowPath) {
    UpdateTopForPop_Slow();
  } else {
    StackData.pop();
  }
}


void X87StackOptimization::HandleUnop(IROps Op64, bool VFOp64, IROps Op80) {
  Ref St0 = LoadStackValue();
  Ref Value {};

  if (ReducedPrecisionMode) {
    if (VFOp64) {
      DeriveOp(Value, Op64, IREmit->_VFSqrt(OpSize::i64Bit, OpSize::i64Bit, St0));
    } else {
      DeriveOp(Value, Op64, IREmit->_F64SIN(St0));
    }
  } else {
    DeriveOp(Value, Op80, IREmit->_F80SQRT(St0));
  }

  StoreStackValue(Value);
}


void X87StackOptimization::HandleBinopValue(IROps Op64, bool VFOp64, IROps Op80, uint8_t DestStackOffset, bool MarkDestValid,
                                            uint8_t StackOffset, Ref ValueNode, bool Reverse) {
  LOGMAN_THROW_A_FMT(!Reverse || VFOp64, "There are no reverse operations using non VFOp64 ops");
  auto StackNode = LoadStackValue(StackOffset);

  Ref Node = {};
  if (ReducedPrecisionMode) {
    if (Reverse) {
      DeriveOp(Node, Op64, IREmit->_VFAdd(OpSize::i64Bit, OpSize::i64Bit, ValueNode, StackNode));
    } else {
      if (VFOp64) {
        DeriveOp(Node, Op64, IREmit->_VFAdd(OpSize::i64Bit, OpSize::i64Bit, StackNode, ValueNode));
      } else {
        DeriveOp(Node, Op64, IREmit->_F64FPREM(StackNode, ValueNode));
      }
    }
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
  auto StackNode = LoadStackValue(StackOffset2);
  HandleBinopValue(Op64, VFOp64, Op80, DestStackOffset, StackOffset2 != DestStackOffset, StackOffset1, StackNode, Reverse);
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
  GetOffsetTopWithCache_Slow(1);
  PopContainer(TopOffsetCache);
  PopContainer(TopOffsetAddressCache);
  PopContainer(TopValueCache);
  PopContainer(TopIntCache);
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
  GetOffsetTopWithCache_Slow(1, true);
  PushContainer(TopOffsetCache);
  PushContainer(TopOffsetAddressCache);
  PushContainer(TopValueCache);
  PushContainer(TopIntCache);
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

  // Before leaving we need to write the current values in the stack to
  // context so that the values are correct. Copy SourceDataNode in the
  // stack to the respective mmX register.
  Ref TopValue = GetTopWithCache_Slow();
  for (size_t i = 0; i < StackData.size; ++i) {
    const auto& [Valid, StackMember] = StackData.top(i);

    if (Valid == StackSlot::VALID) {
      Ref IntValue = StackMember.Source && StackMember.Source->Integer ? StackMember.Source->Node : nullptr;
      StoreStackValueAtOffset_Slow(StackMember.StackDataNode, i, false, IntValue);
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

    IREmit->SetCurrentCodeBlock(BlockNode);
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
        HandleBinopValue(OP_VFADD, true, OP_F80ADD, 0, true, Op->SrcStack, CurrentIR.GetNode(Op->X80Src));
        break;
      }

      case OP_F80SUBRVALUE:
      case OP_F80SUBVALUE: {
        const auto* Op = IROp->C<IROp_F80SubValue>();
        HandleBinopValue(OP_VFSUB, true, OP_F80SUB, 0, true, Op->SrcStack, CurrentIR.GetNode(Op->X80Src), IROp->Op == OP_F80SUBRVALUE);
        break;
      }

      case OP_F80DIVRVALUE:
      case OP_F80DIVVALUE: {
        const auto* Op = IROp->C<IROp_F80DivValue>();
        HandleBinopValue(OP_VFDIV, true, OP_F80DIV, 0, true, Op->SrcStack, CurrentIR.GetNode(Op->X80Src), IROp->Op == OP_F80DIVRVALUE);
        break;
      }

      case OP_F80MULVALUE: {
        const auto* Op = IROp->C<IROp_F80MulValue>();
        HandleBinopValue(OP_VFMUL, true, OP_F80MUL, 0, true, Op->SrcStack, CurrentIR.GetNode(Op->X80Src));
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

        if (SlowPath) {
          UpdateTopForPush_Slow();
          StoreStackValueAtOffset_Slow(SourceNode);
        } else {
          if (Op->OriginalValue.IsInvalid()) {
            // No original value to track - just push the converted data
            StackData.push(StackMemberInfo {SourceNode});
          } else {
            auto* OriginalNode = CurrentIR.GetNode(Op->OriginalValue);
            StackData.push(StackMemberInfo {SourceNode, OriginalNode, Op->LoadSize});
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
          UpdateTopForPush_Slow();
          StoreStackValueAtOffset_Slow(St0);
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
          Result = IREmit->_Vector_FToZS(OpSize::i128Bit, OpSize::i64Bit, Value->StackDataNode);
        } else {
          Result = IREmit->_Vector_FToS(OpSize::i128Bit, OpSize::i64Bit, Value->StackDataNode);
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
          StoreStackMem_Reduced_Helper(CurrentIR, Op, StackNode);
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
          StoreStackValueAtOffset_Slow(LoadStackValueAtOffset_Slow(), Offset);
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
          Ref ValueTop = LoadStackValue();
          Ref ValueOffset = LoadStackValue(Offset);
          StoreStackValue(ValueOffset, 0, true);
          StoreStackValue(ValueTop, Offset, true);
        } else {
          // Fast path: swap complete StackMemberInfo preserving Source metadata
          StackData.setTop(StackMemberOffset, 0);
          StackData.setTop(StackMemberTop, Offset);
        }
        break;
      }

      case OP_F80STACKCHANGESIGN: {
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
        Ref StackValue1 = LoadStackValue();
        Ref StackValue2 = LoadStackValue(Offset);

        Ref CmpNode {};
        if (ReducedPrecisionMode) {
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
        auto StackNode = LoadStackValue(Offset);
        Ref ZeroConst = IREmit->_VCastFromGPR(ReducedPrecisionMode ? OpSize::i64Bit : OpSize::i128Bit, OpSize::i64Bit, GetConstant(0));

        Ref CmpNode {};
        if (ReducedPrecisionMode) {
          CmpNode = IREmit->_FCmp(OpSize::i64Bit, StackNode, ZeroConst);
        } else {
          CmpNode = IREmit->_F80Cmp(StackNode, ZeroConst);
        }
        IREmit->ReplaceUsesWithAfter(CodeNode, CmpNode, CodeNode);
        break;
      }


      case OP_F80CMPVALUE: {
        const auto* Op = IROp->C<IROp_F80CmpValue>();
        const auto& Value = CurrentIR.GetNode(Op->X80Src);
        auto StackNode = LoadStackValue();

        Ref CmpNode {};
        if (ReducedPrecisionMode) {
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
        Ref Value1 = LoadStackValue(StackOffset1);
        Ref Value2 = LoadStackValue(StackOffset2);

        Ref StackNode = IREmit->_VBSL(OpSize::i128Bit, CurrentIR.GetNode(Op->VectorMask), Value1, Value2);
        StoreStackValue(StackNode, 0, StackOffset1 && StackOffset2);
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
  }
}

fextl::unique_ptr<Pass> CreateX87StackOptimizationPass(const HostFeatures& Features, OpSize GPROpSize) {
  return fextl::make_unique<X87StackOptimization>(Features, GPROpSize);
}
} // namespace FEXCore::IR
