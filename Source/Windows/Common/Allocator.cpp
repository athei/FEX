// SPDX-License-Identifier: MIT
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/Utils/TypeDefines.h>
#include "Windows/Common/FEXUnixLib.h"

#include <array>
#include <chrono>
#include <libloaderapi.h>
#include <sysinfoapi.h>
#include <synchapi.h>
#include <windef.h>
#include <winternl.h>
#include <winnt.h>
#include <wine/debug.h>

namespace FEX::Windows::Allocator {
void SetupHooks(HMODULE ntdll) {
  FEXCore::Allocator::HookPtrs Ptrs {};

  Ptrs = {
    .VirtualName = UnixLib::VirtualName,
    .VirtualTHPControl = UnixLib::VirtualTHPControl,
  };

  SYSTEM_INFO system_info {};
  GetSystemInfo(&system_info);
  FEXCore::Allocator::SetupHooks(system_info.dwPageSize, Ptrs);
}

// Wine extension to MemExtendedParameterAttributeFlags (see Wine's winternl.h): on hosts that refuse
// RWX mappings, back the allocation with per-thread W^X JIT memory (MAP_JIT on macOS) instead of
// flipping page protections on faults. Every write must be inside a FEXCore::Allocator::ScopedJITWrite.
constexpr ULONG MEM_EXTENDED_PARAMETER_WINE_UNIX_JIT = 0x80000000;

static void* AllocateJIT(size_t Size) {
  MEM_EXTENDED_PARAMETER Parameter {};
  Parameter.Type = MemExtendedParameterAttributeFlags;
  Parameter.ULong64 = MEM_EXTENDED_PARAMETER_WINE_UNIX_JIT;
#ifdef ARCHITECTURE_arm64ec
  Parameter.ULong64 |= MEM_EXTENDED_PARAMETER_EC_CODE;
#endif
  return ::VirtualAlloc2(nullptr, nullptr, Size, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE, &Parameter, 1);
}

void EnableJITWriteProtect() {
  FEXCore::Allocator::SetJITHooks(UnixLib::JITWriteProtect, AllocateJIT);
}
} // namespace FEX::Windows::Allocator
