// SPDX-License-Identifier: MIT
#define NTDDI_VERSION 0x0A000005
#define _SECIMP
#define _CRTIMP
#include <cstdint>
#include <cstdlib>
#include "../Priv.h"
#include "CRT.h"
#include <memoryapi.h>
#include <rpmalloc/rpmalloc.h>

// rpmalloc's OS hooks, see rpmalloc.c
extern "C" void* (*rp_mmap_hook)(size_t size, size_t alignment, size_t* offset, size_t* mapped_size);
extern "C" void (*rp_name_hook)(const char* name, const void* address, size_t size);

namespace FEX::Windows {
namespace {
  // rpmalloc's own Windows mapping reserves the alignment on top of the size and skips to the first aligned address,
  // which doubles the address space taken by every span. Ask for an aligned reservation instead.
  void* MapAligned(size_t Size, size_t Alignment, size_t* Offset, size_t* MappedSize) {
    MEM_ADDRESS_REQUIREMENTS Reqs {};
    MEM_EXTENDED_PARAMETER Parameter {};
    // Reservations are always aligned to the 64K allocation granularity, which is also the smallest alignment that can be requested.
    if (Alignment > 64 * 1024) {
      Reqs.Alignment = Alignment;
      Parameter.Type = MemExtendedParameterAddressRequirements;
      Parameter.Pointer = &Reqs;
    }

    // Memory is committed on demand by rpmalloc.
    void* Ptr = ::VirtualAlloc2(nullptr, nullptr, Size, MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE, Reqs.Alignment ? &Parameter : nullptr,
                                Reqs.Alignment ? 1 : 0);
    if (!Ptr) {
      return nullptr;
    }

    rp_name_hook(rpmalloc_config()->page_name, Ptr, Size);
    *Offset = 0;
    *MappedSize = Size;
    return Ptr;
  }
} // namespace

void SetupRpmallocMapHook() {
  rp_mmap_hook = MapAligned;
}
} // namespace FEX::Windows

void* calloc(size_t NumOfElements, size_t SizeOfElements) {
  return ::rpcalloc(NumOfElements, SizeOfElements);
}

void free(void* Memory) {
  ::rpfree(Memory);
}

void* malloc(size_t Size) {
  return ::rpmalloc(Size);
}

void* realloc(void* Memory, size_t NewSize) {
  return ::rprealloc(Memory, NewSize);
}

DLLEXPORT_FUNC(void*, _aligned_malloc, (size_t Size, size_t Alignment)) {
  return ::rpaligned_alloc(Alignment, Size);
}

DLLEXPORT_FUNC(void, _aligned_free, (void* Memory)) {
  ::rpfree(Memory);
}
