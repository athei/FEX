// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
#include <winternl.h>

namespace FEX::Windows::Allocator {
#ifdef _M_ARM64EC
// Wine serves allocations without a fixed address from its reserved areas first: top-down ones from a small area near
// the top of the address space and, once that is full, from the low area. On macOS that is the low 4GB and the area
// from 4GB up to the loader, which the kernel places a random distance above 4GB, and it stays reserved for the whole
// process. x64 code needs the low 4GB for ZeroBits and other address-limited allocations and for DLLs that can't be
// relocated, and 4GB to 8GB holds the default image bases (0x140000000, 0x180000000) with the 2GB that hooks near them
// can reach, while macOS already places the loader and its own mappings just above 4GB. FEX's own memory starts above
// both.
inline constexpr uintptr_t LowestFEXAddress = 0x2'0000'0000;
#else
// FEX's own memory stays out of the 32-bit guest's address space. VirtualAlloc uses the emulated
// HighestUserAddress instead, this covers the file and host mappings.
inline constexpr uintptr_t LowestFEXAddress = 0x1'0000'0000;
#endif

// Wine keeps the area from 0x7ffff0000000 to the top of the host address space (208MB on macOS) for its own top-down
// allocations, among them the blocks of every new thread (reserve_area() in mmap_init(), dlls/ntdll/unix/virtual.c).
// Nothing reports reserved areas, so the start is a constant here. FEX's memory ends below it, as when FEX fills the
// area Wine's thread blocks spill to lower addresses. Inclusive, as MEM_ADDRESS_REQUIREMENTS::HighestEndingAddress.
inline constexpr uintptr_t HighestFEXAddress = 0x7fff'efff'ffff;

void SetupHooks(HMODULE ntdll);

// Backs JIT code buffers with per-thread W^X memory; the host must support it (see UnixLib).
void EnableJITWriteProtect();
}
