// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Utils/CompilerDefs.h>

#include <stddef.h>
#include <stdint.h>
#include <optional>

namespace FEXCore::Core {
struct InternalThreadState;
}

namespace FEXCore::ArchHelpers::Arm64 {
enum class UnalignedHandlerType {
  ///< Backpatch unaligned access to half-barrier based atomic.
  HalfBarrier,
  ///< Backpatch unaligned access to non-atomic.
  NonAtomic,
};

/**
 * @brief On ARM64 handles an unaligned memory access that the JIT has done.
 *
 * This is an OS agnostic handler where the frontend must provide FEXCore with the information necessary to know if this is safe.
 * This does not check if the PC is within a JIT code buffer, the frontend must provide that safety with `CPUBackend::IsAddressInCodeBuffer`.
 *
 * @param HandleType Type of TSO handling to use.
 * @param ProgramCounter The location in memory for the instruction that did the access
 * @param GPRs The array of GPRs from the signal context. This will be modified and the host context needs to be updated on signal return.
 *
 * @return Returns a value if the unaligned access has been handled with how many bytes to modify the host PC
 * by. FEXCore will return a positive or negative offset depending on internal handling.
 */
[[nodiscard]]
FEX_DEFAULT_VISIBILITY std::optional<int32_t> HandleUnalignedAccess(
  FEXCore::Core::InternalThreadState* Thread, UnalignedHandlerType HandleType, uintptr_t ProgramCounter, uint64_t* GPRs, bool IsJIT = true);

/**
 * @brief Copies Size bytes from Src to Dst, for reads of memory that can go away at any moment, such as guest code.
 *
 * A fault in a read of Src ends the copy when the frontend's fault handler resumes it at `FaultSafeCopyResumePC`. On
 * Windows that is the handler's first step, which takes only the InvalidationTracker's IntervalsLock, so a caller must
 * not hold that one. Without that the fault is raised as from any other read.
 *
 * @return The number of bytes copied. The reads are 8 bytes wide while 8 remain, so where one straddles two pages and the
 * second faults, the readable bytes it covers on the first are not copied either.
 */
FEX_DEFAULT_VISIBILITY size_t FaultSafeCopy(void* Dst, const void* Src, size_t Size);

/**
 * @brief The host PC to resume a fault at ProgramCounter at, if that is a read of `FaultSafeCopy`, or 0.
 */
FEX_DEFAULT_VISIBILITY uint64_t FaultSafeCopyResumePC(uint64_t ProgramCounter);
} // namespace FEXCore::ArchHelpers::Arm64
