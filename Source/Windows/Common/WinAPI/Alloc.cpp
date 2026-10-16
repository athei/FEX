// SPDX-License-Identifier: MIT
#define NTDDI_VERSION 0x0A000005
#define WINAPI
#define WINBASEAPI

#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cerrno>
#include <winternl.h>
#include <windows.h>
#include <processenv.h>
#include "../Allocator.h"
#include "../Priv.h"

namespace {
#ifdef _M_ARM64EC
MEM_ADDRESS_REQUIREMENTS MakeAddressReqs() {
  MEM_ADDRESS_REQUIREMENTS Reqs {};
  Reqs.LowestStartingAddress = reinterpret_cast<void*>(FEX::Windows::Allocator::LowestFEXAddress);
  Reqs.HighestEndingAddress = reinterpret_cast<void*>(FEX::Windows::Allocator::HighestFEXAddress);
  return Reqs;
}
#else
SYSTEM_BASIC_INFORMATION BasicInfo;

// Limits allocations to outside the 32-bit user address space
MEM_ADDRESS_REQUIREMENTS MakeAddressReqs() {
  // Queried on first use rather than from a CRT initializer, as rpmalloc maps its first spans before those run.
  // The first call happens during single-threaded process init.
  if (!BasicInfo.HighestUserAddress) {
    NtQuerySystemInformation(SystemEmulationBasicInformation, &BasicInfo, sizeof(BasicInfo), nullptr);
  }
  MEM_ADDRESS_REQUIREMENTS Reqs {};
  Reqs.LowestStartingAddress = reinterpret_cast<void*>(BasicInfo.HighestUserAddress & ~(BasicInfo.AllocationGranularity - 1));
  Reqs.HighestEndingAddress = reinterpret_cast<void*>(FEX::Windows::Allocator::HighestFEXAddress);
  return Reqs;
}
#endif
} // namespace

DLLEXPORT_FUNC(void*, VirtualAlloc, (void* lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)) {
  NTSTATUS Status;
  if (!lpAddress) {
    // Add address requirements to keep FEX's allocations out of the address space the guest relies on
    MEM_EXTENDED_PARAMETER ExtParam {};
    MEM_ADDRESS_REQUIREMENTS AddrReq = MakeAddressReqs();

    ExtParam.Type = MemExtendedParameterAddressRequirements;
    ExtParam.Pointer = &AddrReq;

    Status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &lpAddress, &dwSize, flAllocationType, flProtect, &ExtParam, 1);
  } else {
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &lpAddress, 0, &dwSize, flAllocationType, flProtect);
  }
  if (Status) {
    SetLastError(RtlNtStatusToDosError(Status));
    return nullptr;
  }
  return lpAddress;
}

DLLEXPORT_FUNC(SIZE_T, VirtualQuery, (LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)) {
  SIZE_T WrittenSize;
  NTSTATUS Status =
    NtQueryVirtualMemory(NtCurrentProcess(), lpAddress, MemoryBasicInformation, reinterpret_cast<void*>(lpBuffer), dwLength, &WrittenSize);
  if (Status) {
    SetLastError(RtlNtStatusToDosError(Status));
    return 0;
  }
  return WrittenSize;
}

DLLEXPORT_FUNC(WINBOOL, VirtualProtect, (void* lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)) {
  return WinAPIReturn(NtProtectVirtualMemory(NtCurrentProcess(), &lpAddress, &dwSize, flNewProtect, lpflOldProtect));
}

DLLEXPORT_FUNC(void*, VirtualAlloc2,
               (HANDLE Process, void* BaseAddress, SIZE_T Size, ULONG AllocationType, ULONG PageProtection,
                MEM_EXTENDED_PARAMETER* ExtendedParameters, ULONG ParameterCount)) {
  NTSTATUS Status;
  // A parameter array that is missing although the count says otherwise is passed on unchanged for ntdll to reject
  if (!BaseAddress && (ExtendedParameters || !ParameterCount)) {
    // Add address requirements to keep FEX's allocations out of the address space the guest relies on
    auto* NewExtParams = reinterpret_cast<MEM_EXTENDED_PARAMETER*>(alloca((ParameterCount + 1) * sizeof(MEM_EXTENDED_PARAMETER)));
    if (ExtendedParameters && ParameterCount > 0) {
      memcpy(NewExtParams, ExtendedParameters, ParameterCount * sizeof(MEM_EXTENDED_PARAMETER));
    }

    MEM_ADDRESS_REQUIREMENTS AddrReq = MakeAddressReqs();
    ULONG NewParameterCount = ParameterCount;
    MEM_EXTENDED_PARAMETER* AddrReqParam = nullptr;
    for (ULONG i = 0; i < ParameterCount; i++) {
      if (NewExtParams[i].Type == MemExtendedParameterAddressRequirements) {
        AddrReqParam = &NewExtParams[i];
      }
    }

    // A parameter type may only be passed once, so merge with the caller's requirements: the narrower range of the two
    // (a null HighestEndingAddress means no limit), and the caller's alignment
    if (AddrReqParam) {
      const auto* CallerReq = static_cast<const MEM_ADDRESS_REQUIREMENTS*>(AddrReqParam->Pointer);
      AddrReq.Alignment = CallerReq->Alignment;
      if (CallerReq->HighestEndingAddress && CallerReq->HighestEndingAddress < AddrReq.HighestEndingAddress) {
        AddrReq.HighestEndingAddress = CallerReq->HighestEndingAddress;
      }
      if (CallerReq->LowestStartingAddress > AddrReq.LowestStartingAddress) {
        AddrReq.LowestStartingAddress = CallerReq->LowestStartingAddress;
      }
    } else {
      AddrReqParam = &NewExtParams[NewParameterCount++];
      *AddrReqParam = {};
      AddrReqParam->Type = MemExtendedParameterAddressRequirements;
    }
    AddrReqParam->Pointer = &AddrReq;

    Status = NtAllocateVirtualMemoryEx(Process ? Process : NtCurrentProcess(), &BaseAddress, &Size, AllocationType, PageProtection,
                                       NewExtParams, NewParameterCount);
  } else {
    Status = NtAllocateVirtualMemoryEx(Process ? Process : NtCurrentProcess(), &BaseAddress, &Size, AllocationType, PageProtection,
                                       ExtendedParameters, ParameterCount);
  }
  if (Status) {
    SetLastError(RtlNtStatusToDosError(Status));
    return nullptr;
  }
  return BaseAddress;
}

DLLEXPORT_FUNC(WINBOOL, VirtualFree, (void* lpAddress, SIZE_T dwSize, DWORD dwFreeType)) {
  return WinAPIReturn(NtFreeVirtualMemory(NtCurrentProcess(), &lpAddress, &dwSize, dwFreeType));
}

DLLEXPORT_FUNC(WINBOOL, FlushInstructionCache, (HANDLE hProcess, const void* lpBaseAddress, SIZE_T dwSize)) {
  return WinAPIReturn(NtFlushInstructionCache(hProcess, const_cast<void*>(lpBaseAddress), dwSize));
}

DLLEXPORT_FUNC(DWORD, FlsAlloc, (PFLS_CALLBACK_FUNCTION lpCallback)) {
  UNIMPLEMENTED();
}

DLLEXPORT_FUNC(void*, FlsGetValue, (DWORD dwFlsIndex)) {
  UNIMPLEMENTED();
}

DLLEXPORT_FUNC(WINBOOL, FlsSetValue, (DWORD dwFlsIndex, void* lpFlsData)) {
  UNIMPLEMENTED();
}

DLLEXPORT_FUNC(WINBOOL, FlsFree, (DWORD dwFlsIndex)) {
  UNIMPLEMENTED();
}

DLLEXPORT_FUNC(HLOCAL, LocalFree, (HLOCAL hMem)) {
  UNIMPLEMENTED();
}

DLLEXPORT_FUNC(DWORD, TlsAlloc, ()) {
  RtlAcquirePebLock();

  // Cannot use expansion slots or FLS here, as they would be freed before FEX can cleanup.
  DWORD Slot = RtlFindClearBitsAndSet(GetCurrentPEB()->TlsBitmap, 1, 1);
  if (Slot != -1) {
    GetCurrentTEB()->TlsSlots[Slot] = nullptr;
  }
  RtlReleasePebLock();
  return Slot;
}

DLLEXPORT_FUNC(void*, TlsGetValue, (DWORD dwTlsIndex)) {
  return GetCurrentTEB()->TlsSlots[dwTlsIndex];
}

DLLEXPORT_FUNC(WINBOOL, TlsSetValue, (DWORD dwTlsIndex, void* lpTlsValue)) {
  GetCurrentTEB()->TlsSlots[dwTlsIndex] = lpTlsValue;
  return true;
}

DLLEXPORT_FUNC(WINBOOL, TlsFree, (DWORD dwTlsIndex)) {
  RtlAcquirePebLock();

  RtlClearBits(GetCurrentPEB()->TlsBitmap, dwTlsIndex, 1);
  NTSTATUS Status = NtSetInformationThread(NtCurrentThread(), ThreadZeroTlsCell, &dwTlsIndex, sizeof(dwTlsIndex));
  RtlReleasePebLock();
  return WinAPIReturn(Status);
}
