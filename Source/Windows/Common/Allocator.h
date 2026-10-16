// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
#include <winternl.h>

namespace FEX::Windows::Allocator {
#ifdef _M_ARM64EC
// Wine serves allocations without a fixed address from its reserved areas first: top-down ones from an area near the
// top of the address space and, once that is full, from the low area. On macOS that is the low 4GB and the area
// from 4GB up to the loader, which the kernel places a random distance above 4GB, and it stays reserved for the whole
// process. x64 code needs the low 4GB for ZeroBits and other address-limited allocations and for DLLs that can't be
// relocated, and 4GB to 8GB holds the default image bases (0x140000000, 0x180000000) with the 2GB that hooks near them
// can reach, while macOS already places the loader and its own mappings just above 4GB. FEX's own memory starts above
// both.
inline constexpr uintptr_t LowestFEXAddress = 0x2'0000'0000;
#else
// FEX's own memory stays out of the whole 32-bit address space. In a process that isn't large address aware, accesses
// from 2GB to 4GB must fault, as on Windows, which programs and ntdll:info rely on, and a large address aware program
// allocates from that range itself.
inline constexpr uintptr_t LowestFEXAddress = 0x1'0000'0000;
#endif

// Wine reserves 0x7ff000000000 to 0x7ff600000000 for the 64-bit top-down allocations of a process, such as the
// MEM_TOP_DOWN ones of an x64 program (dlls/ntdll/unix/virtual.c). Wine serves allocations from reserved areas before
// free ones, top-down ones from the highest area down. Nothing reports reserved areas, so the start is a constant here.
// FEX's memory ends below it: once FEX filled the area, top-down allocations went to the low reserved area that x64 code
// needs. Inclusive, as MEM_ADDRESS_REQUIREMENTS::HighestEndingAddress.
inline constexpr uintptr_t HighestFEXAddress = 0x7fef'ffff'ffff;

void SetupHooks(HMODULE ntdll);

// Backs JIT code buffers with per-thread W^X memory; the host must support it (see UnixLib).
void EnableJITWriteProtect();
}
