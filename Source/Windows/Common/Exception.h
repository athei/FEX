// SPDX-License-Identifier: MIT
#pragma once

#include <ntstatus.h>
#include <windef.h>
#include <winternl.h>

#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Debug/InternalThreadState.h>

namespace FEX::Windows {
// The opcode of the guest instruction at Rip, past its legacy and (64-bit only) REX prefixes, or nullptr when the
// prefixes take up the 15 bytes an instruction can have.
template<typename TReg>
static inline const uint8_t* SkipPrefixes(TReg Rip) {
  const auto* Code = reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(Rip));
  for (size_t i = 0; i < 15; i++, Code++) {
    switch (*Code) {
    case 0x26:
    case 0x2e:
    case 0x36:
    case 0x3e:
    case 0x64:
    case 0x65:
    case 0x66:
    case 0x67:
    case 0xf2:
    case 0xf3: continue;
    default:
      if (sizeof(TReg) == 8 && (*Code & 0xf0) == 0x40) {
        continue;
      }
      return Code;
    }
  }
  return nullptr;
}

// Whether the guest instruction at Rip loads a segment register and so raises #GP from the segment checks: IRET, MOV to
// a segment register or POP of one.
template<typename TReg>
static inline bool IsSegmentLoad(TReg Rip) {
  const auto* Code = SkipPrefixes(Rip);
  if (!Code) {
    return false;
  }
  switch (Code[0]) {
  case 0xcf: // IRET
  case 0x8e: // MOV Sreg, r/m16
    return true;
  case 0x07: // POP ES
  case 0x17: // POP SS
  case 0x1f: // POP DS
    return sizeof(TReg) == 4;
  case 0x0f: return Code[1] == 0xa1 || Code[1] == 0xa9; // POP FS, POP GS
  default: return false;
  }
}

template<typename TReg>
static inline EXCEPTION_RECORD HandleGuestException(FEXCore::Core::CpuStateFrame::SynchronousFaultDataStruct& Fault,
                                                    const EXCEPTION_RECORD& Src, TReg& Rip, TReg Rax, TReg Cx, BOOL& FirstChance) {
  EXCEPTION_RECORD Dst = Src;
  Dst.ExceptionAddress = reinterpret_cast<void*>(Rip);

  if (!Fault.FaultToTopAndGeneratedException) {
    return Dst;
  }
  Fault.FaultToTopAndGeneratedException = false;

  Dst.ExceptionFlags = 0;
  Dst.NumberParameters = 0;

  switch (Fault.Signal) {
  case FEXCore::Core::FAULT_SIGILL: Dst.ExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION; return Dst;
  case FEXCore::Core::FAULT_SIGTRAP:
    switch (Fault.TrapNo) {
    case FEXCore::X86State::X86_TRAPNO_DB: Dst.ExceptionCode = EXCEPTION_SINGLE_STEP; return Dst;
    case FEXCore::X86State::X86_TRAPNO_BP:
      Dst.ExceptionAddress = reinterpret_cast<void*>(Rip - 1);
      Dst.ExceptionCode = EXCEPTION_BREAKPOINT;
      Dst.NumberParameters = 1;
      Dst.ExceptionInformation[0] = 0;
      return Dst;
    default: LogMan::Msg::EFmt("Unknown SIGTRAP trap: {}", Fault.TrapNo); break;
    }
    break;
  case FEXCore::Core::FAULT_SIGSEGV:
    switch (Fault.TrapNo) {
    case FEXCore::X86State::X86_TRAPNO_GP:
      if ((Fault.err_code & 0b111) == 0b010) {
        switch (Fault.err_code >> 3) {
        case 3:
          Rip += 2;
          Dst.ExceptionAddress = reinterpret_cast<void*>(Rip - 1);
          Dst.ExceptionCode = EXCEPTION_BREAKPOINT;
          Dst.NumberParameters = 1;
          Dst.ExceptionInformation[0] = 0;
          return Dst;
        case 0x29:
          Dst.ExceptionCode = STATUS_STACK_BUFFER_OVERRUN;
          Dst.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
          Dst.ExceptionAddress = reinterpret_cast<void*>(Rip);
          Dst.NumberParameters = 1;
          Dst.ExceptionInformation[0] = Cx;
          FirstChance = FALSE;
          return Dst;
        case 0x2c: Dst.ExceptionCode = STATUS_ASSERTION_FAILURE; return Dst;
        case 0x2d:
          Rip += 3;
          Dst.ExceptionCode = EXCEPTION_BREAKPOINT;
          Dst.ExceptionAddress = reinterpret_cast<void*>(Rip);
          Dst.NumberParameters = 1;
          Dst.ExceptionInformation[0] = Rax;
          // Note that ExceptionAddress doesn't equal the reported context RIP here, this discrepancy expected and not having it can trigger anti-debug logic.
          return Dst;
        default: LogMan::Msg::EFmt("Unknown interrupt: 0x{:X}", Fault.err_code >> 3); break;
        }
      } else if (IsSegmentLoad<TReg>(Rip)) {
        // As on Windows, a #GP that is not from a privileged instruction, here from the segment checks of a segment
        // register load, is an access violation at an unknown address.
        Dst.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
        Dst.NumberParameters = 2;
        Dst.ExceptionInformation[0] = 0;
        Dst.ExceptionInformation[1] = static_cast<TReg>(~TReg {0});
        return Dst;
      } else {
        Dst.ExceptionCode = EXCEPTION_PRIV_INSTRUCTION;
        return Dst;
      }
      break;
    case FEXCore::X86State::X86_TRAPNO_OF: Dst.ExceptionCode = EXCEPTION_INT_OVERFLOW; return Dst;
    case FEXCore::X86State::X86_TRAPNO_PF:
      // A page-fault raised by an explicit break in JIT code is always an execute fault
      Dst.NumberParameters = 2;
      Dst.ExceptionInformation[0] = EXCEPTION_EXECUTE_FAULT;
      Dst.ExceptionInformation[1] = Rip;
      return Dst;
    default: LogMan::Msg::EFmt("Unknown SIGSEGV trap: {}", Fault.TrapNo); break;
    }
    break;
  default: LogMan::Msg::EFmt("Unknown signal type: {}", Fault.Signal); break;
  }

  // Default to SIGILL
  Dst.ExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION;
  return Dst;
}
} // namespace FEX::Windows
