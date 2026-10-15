// SPDX-License-Identifier: MIT
#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/LogManager.h>

#include <windef.h>
#include <winternl.h>

#include "FEXUnixLib.h"
#include "HardwareTSO.h"

extern "C" {
int64_t HardwareTSOTrap {};

[[noreturn]]
void HardwareTSOEnableFailed() {
  LogMan::Msg::EFmt("FEX: Failed to switch a thread to hardware TSO, terminating");
  NtTerminateProcess(NtCurrentProcess(), STATUS_INTERNAL_ERROR);
  __builtin_trap();
}
}

namespace FEX::Windows::HardwareTSO {
namespace {
  // Issues the trap like the libsystem_kernel stub does, but from this module, so that the PC of a thread suspended
  // in it stays inside a PE module (see HardwareTSOTrap). Returns the trap's kern_return_t.
  __attribute__((naked)) int32_t CallTrap(uint32_t /* Enable */) {
    asm(R"(
    adrp x16, %[Trap]
    ldr x16, [x16, #:lo12:%[Trap]]
    svc #0x80
    ret
    )" ::[Trap] "S"(&HardwareTSOTrap)
        : "memory");
  }
} // namespace

bool Init() {
  FEX_CONFIG_OPT(TSOEnabled, TSOENABLED);
  if (!TSOEnabled()) {
    return false;
  }

  FEXUnixLib_ProbeHardwareTSOArgs Args {};
  if (!UnixLib::ProbeHardwareTSO(Args)) {
    // Hosts without the probe can only set hardware TSO for the whole process, at once.
    return UnixLib::TryEnableHardwareTSO();
  }

  switch (Args.Result) {
  case FEXUnixLib_HardwareTSOProbeResult::Available:
    // Check the trap the way the PE side issues it, leaving this thread off like every other.
    HardwareTSOTrap = Args.Trap;
    if (CallTrap(1) != 0 || CallTrap(0) != 0) {
      HardwareTSOTrap = 0;
      return false;
    }
    LogMan::Msg::IFmt("FEX: Using hardware TSO");
    return true;
  case FEXUnixLib_HardwareTSOProbeResult::InvalidValue:
    LogMan::Msg::EFmt("FEX: FEX_HARDWARE_TSO must be 0 or 1, using software TSO");
    return false;
  case FEXUnixLib_HardwareTSOProbeResult::Disabled:
  case FEXUnixLib_HardwareTSOProbeResult::Unavailable: return false;
  }
  return false;
}

bool PerThread() {
  return HardwareTSOTrap != 0;
}

void InitThread(FEXCore::Core::CpuStateFrame* Frame) {
  // A new thread starts off: whether it inherits its creator's state is up to the host, and a thread that is on while
  // its state says off only costs one redundant trap at its first JIT entry.
  Frame->HardwareTSOState = FEXCore::ToUnderlying(PerThread() ? State::Off : State::NotUsed);
}

void EnsureOn(FEXCore::Core::CpuStateFrame* Frame) {
  if (Frame->HardwareTSOState != FEXCore::ToUnderlying(State::Off)) {
    return;
  }

  if (CallTrap(1) != 0) {
    HardwareTSOEnableFailed();
  }
  Frame->HardwareTSOState = FEXCore::ToUnderlying(State::On);
}

void EnsureOff(FEXCore::Core::CpuStateFrame* Frame) {
  if (Frame->HardwareTSOState != FEXCore::ToUnderlying(State::On)) {
    return;
  }

  // Off is stored before the trap, so the state never says On while the thread is off. If the trap fails, the thread
  // stays on with its state Off, which is harmless: the next entry into JIT code issues one redundant trap.
  Frame->HardwareTSOState = FEXCore::ToUnderlying(State::Off);
  CallTrap(0);
}
} // namespace FEX::Windows::HardwareTSO
