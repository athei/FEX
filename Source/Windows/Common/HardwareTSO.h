// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>

namespace FEXCore::Core {
struct CpuStateFrame;
}

// Hardware TSO on hosts that switch it per thread (macOS).
//
// FEX compiles code once for the whole process, so code compiled without TSO barriers is only correct on a thread
// that runs with hardware TSO. Every entry into JIT code therefore switches the thread on (EnsureOn), and the places
// where native code does real work switch it off again (EnsureOff), since native code is slower under TSO. If the
// host cannot switch threads, software TSO stays in use. If switching a thread on fails later, the process is
// terminated, as it cannot run its code safely.
//
// The state of each thread is kept in CpuStateFrame::HardwareTSOState. Only this file and the ARM64EC assembly in
// Module.S change it, so that it is never On while the thread is off: On is stored only after a successful trap that
// switches the thread on, and Off is stored before the trap that switches it off. The reverse mismatch (on, but Off)
// is harmless and only costs a redundant trap at the next entry into JIT code.
namespace FEX::Windows::HardwareTSO {
enum class State : uint32_t {
  // Hardware TSO is in use and the thread is off. It must be switched on before running JIT code.
  Off = 0,
  // Hardware TSO is in use and the thread is on.
  On = 1,
  // Hardware TSO is not switched per thread: software TSO, or a host that sets it once for the process.
  NotUsed = 2,
};

/**
 * @brief Decides on hardware TSO for the process. Must run after UnixLib::Init and before the context is created.
 *
 * @return true if the JIT may rely on hardware TSO (HostFeatures::SupportsHardwareTSO).
 */
bool Init();

// Whether threads are switched individually, which requires the hooks in this file.
bool PerThread();

// Sets the state of a new thread.
void InitThread(FEXCore::Core::CpuStateFrame* Frame);

// Switches the calling thread on if it is off. Terminates the process if that fails.
void EnsureOn(FEXCore::Core::CpuStateFrame* Frame);

// Switches the calling thread off if it is on. Called before native code handles a guest syscall or unix call.
void EnsureOff(FEXCore::Core::CpuStateFrame* Frame);
} // namespace FEX::Windows::HardwareTSO

extern "C" {
// The Mach trap number of thread_set_x86_64_compat(uint32_t Enable), which switches the calling thread on macOS.
// FEX issues it with svc #0x80 from its own code rather than calling the libsystem_kernel stub: on ARM64EC, Wine takes
// a suspended thread whose PC is outside every PE module for one running x64 code and resumes it in the JIT.
// Non-zero only when threads are switched individually. Read by Module.S on ARM64EC.
extern int64_t HardwareTSOTrap;

// Called by the ARM64EC assembly when switching a thread on fails.
[[noreturn]]
void HardwareTSOEnableFailed();
}
