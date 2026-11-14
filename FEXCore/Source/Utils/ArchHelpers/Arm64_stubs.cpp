// SPDX-License-Identifier: MIT
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/ArchHelpers/Arm64.h>
#include <stdint.h>
#include <string.h>

namespace FEXCore::ArchHelpers::Arm64 {

#ifndef ARCHITECTURE_arm64
// These are stub implementations that exist only to allow instantiating the arm64 jit
// on non arm platforms.

// Obvously such a configuration can't do the actual arm64-specific stuff

std::optional<int32_t>
HandleUnalignedAccess(FEXCore::Core::InternalThreadState* Thread, UnalignedHandlerType HandleType, uintptr_t ProgramCounter, uint64_t* GPRs) {
  ERROR_AND_DIE_FMT("HandleAtomicMemOp Not Implemented");
}

size_t FaultSafeCopy(void* Dst, const void* Src, size_t Size) {
  memcpy(Dst, Src, Size);
  return Size;
}

uint64_t FaultSafeCopyResumePC(uint64_t ProgramCounter) {
  return 0;
}

#endif

} // namespace FEXCore::ArchHelpers::Arm64
