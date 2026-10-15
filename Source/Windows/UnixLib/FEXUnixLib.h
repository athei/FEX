// SPDX-License-Identifier: MIT
#pragma once
#include <cstddef>
#include <cstdint>

enum class FEXUnixLibFunctions : uint32_t {
  SetHardwareTSOControl,
  SetKernelUnalignedAtomicControl,
  Madvise,
  SetVMAName,
  GetSHMStatsVMA,
  DeleteSHMStatsFile,
  MapFile,
  GetPID,
  JITWriteProtectSupported,
  JITWriteProtect,
  ProbeHardwareTSO,
  MAX,
};

// Structures for passing arguments to unix library handlers.
// This must match between wow64, arm64ec, and Linux.
struct FEXUnixLib_SetHardwareTSOControlArgs {
  bool Enable;
};
static_assert(sizeof(FEXUnixLib_SetHardwareTSOControlArgs) == 1);

// These match the prctl flag values for PR_ARM64_SET_UNALIGN_ATOMIC
static constexpr uint64_t FEX_UNALIGN_ATOMIC_EMULATE = 1ULL << 0;
static constexpr uint64_t FEX_UNALIGN_ATOMIC_BACKPATCH = 1ULL << 1;
static constexpr uint64_t FEX_UNALIGN_ATOMIC_STRICT_SPLIT_LOCKS = 1ULL << 2;

struct FEXUnixLib_SetKernelUnalignedAtomicControl {
  uint64_t Flags;
};
static_assert(sizeof(FEXUnixLib_SetKernelUnalignedAtomicControl) == 8);

struct FEXUnixLib_Madvise {
  const void* Addr;
  size_t Size;
  int32_t Advise;
  uint32_t pad;
};
static_assert(sizeof(FEXUnixLib_Madvise) == 24);

struct FEXUnixLib_SetVMAName {
  const void* Addr;
  size_t Size;
  const char* Name;
};
static_assert(sizeof(FEXUnixLib_SetVMAName) == 24);

struct FEXUnixLib_GetSHMStatsVMA {
  void* SHMBase;
  uint32_t MapSize;
  uint32_t MaxSize;
  // The reservation must start at or above this address
  uint64_t MinAddress;
};
static_assert(sizeof(FEXUnixLib_GetSHMStatsVMA) == 24);

struct FEXUnixLib_MapFile {
  int32_t FD;
  uint64_t MapSize;
  // The mapping must start at or above this address
  uint64_t MinAddress;
  void* Result;
};
static_assert(sizeof(FEXUnixLib_MapFile) == 32);

struct FEXUnixLib_GetPID {
  uint32_t Result;
};
static_assert(sizeof(FEXUnixLib_GetPID) == 4);

struct FEXUnixLib_JITWriteProtect {
  bool Protect;
};
static_assert(sizeof(FEXUnixLib_JITWriteProtect) == 1);

enum class FEXUnixLib_HardwareTSOProbeResult : uint32_t {
  // The trap works on this thread, Trap holds its number.
  Available,
  // FEX_HARDWARE_TSO is 0.
  Disabled,
  // FEX_HARDWARE_TSO has a value other than 0 or 1.
  InvalidValue,
  // The host has no thread_set_x86_64_compat, its stub has an unknown form, or the trap failed (usually because the
  // cross-architecture entitlement is missing).
  Unavailable,
};

struct FEXUnixLib_ProbeHardwareTSOArgs {
  // Out: the Mach trap number of thread_set_x86_64_compat, which PE code issues directly with svc #0x80 to switch
  // the calling thread.
  int64_t Trap;
  FEXUnixLib_HardwareTSOProbeResult Result;
  uint32_t pad;
};
static_assert(sizeof(FEXUnixLib_ProbeHardwareTSOArgs) == 16, "Must match between the PE and unix sides");
