// SPDX-License-Identifier: MIT
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <type_traits>
#include <errno.h>
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#ifdef __APPLE__
#include <mach/kern_return.h>
#include <pthread.h>
#endif
#include <unistd.h>

#include "FEXUnixLib.h"

// Equivalent to C++23's std::to_underlying.
template<typename Enum>
[[nodiscard]]
constexpr std::underlying_type_t<Enum> ToUnderlying(Enum e) noexcept {
  return static_cast<std::underlying_type_t<Enum>>(e);
}

using NTSTATUS = int32_t;
using unixlib_entry_t = NTSTATUS (*)(void*);

constexpr NTSTATUS STATUS_SUCCESS = 0;
constexpr NTSTATUS STATUS_NOT_SUPPORTED = 0xC00000BB;
constexpr NTSTATUS STATUS_INTERNAL_ERROR = 0xC00000E5;

#ifndef PR_GET_MEM_MODEL
#define PR_GET_MEM_MODEL 0x6d4d444c
#endif
#ifndef PR_SET_MEM_MODEL
#define PR_SET_MEM_MODEL 0x4d4d444c
#endif
#ifndef PR_SET_MEM_MODEL_DEFAULT
#define PR_SET_MEM_MODEL_DEFAULT 0
#endif
#ifndef PR_SET_MEM_MODEL_TSO
#define PR_SET_MEM_MODEL_TSO 1
#endif
#ifndef PR_ARM64_SET_UNALIGN_ATOMIC
#define PR_ARM64_SET_UNALIGN_ATOMIC 0x46455849
#endif
#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif

#ifdef __APPLE__
// macOS has no prctl. Every call fails, so kernel unaligned-atomic control reports as
// unsupported and FEX falls back to its software implementation, and VMA naming does nothing.
static int prctl(int, ...) {
  errno = ENOSYS;
  return -1;
}
#endif

#ifdef __APPLE__
// Apple silicon provides x86 memory ordering (TSO) per thread through the x86_64 compat mode,
// which requires the cross-architecture entitlement. The trap only switches the calling thread,
// so the PE side switches every thread itself around JIT code and issues the trap directly
// instead of through a unix call. This only checks that the trap works and returns its number.
extern "C" kern_return_t thread_set_x86_64_compat(uint32_t enable) __attribute__((weak_import));

// Returns the Mach trap number that the libsystem_kernel stub passes in x16, or 0 if the stub is
// not the expected `movn x16, #imm; svc #0x80; ret`. The PE side issues the trap from its own
// code instead of calling the stub, because Wine takes a suspended ARM64EC thread whose PC is
// outside any PE module for one running x64 code.
static int64_t GetHardwareTSOTrapNumber() {
  const auto Code = reinterpret_cast<const uint32_t*>(&thread_set_x86_64_compat);
  if ((Code[0] & 0xffe0001f) != 0x92800010 || Code[1] != 0xd4001001 || Code[2] != 0xd65f03c0) {
    return 0;
  }
  return ~static_cast<int64_t>((Code[0] >> 5) & 0xffff);
}

static FEXUnixLib_HardwareTSOProbeResult ProbeHardwareTSO() {
  // On by default: FEX_HARDWARE_TSO=0 keeps software TSO, unset or 1 uses hardware TSO.
  const char* Env = getenv("FEX_HARDWARE_TSO");
  if (Env && !strcmp(Env, "0")) {
    return FEXUnixLib_HardwareTSOProbeResult::Disabled;
  }
  if (Env && strcmp(Env, "1")) {
    return FEXUnixLib_HardwareTSOProbeResult::InvalidValue;
  }
  if (!thread_set_x86_64_compat || !GetHardwareTSOTrapNumber()) {
    return FEXUnixLib_HardwareTSOProbeResult::Unavailable;
  }
  // Leave this thread off like every other thread. If switching off fails it stays on, which is
  // still correct, but the process then keeps software TSO.
  if (thread_set_x86_64_compat(1) != KERN_SUCCESS || thread_set_x86_64_compat(0) != KERN_SUCCESS) {
    return FEXUnixLib_HardwareTSOProbeResult::Unavailable;
  }
  return FEXUnixLib_HardwareTSOProbeResult::Available;
}

static NTSTATUS FEXUnixLib_ProbeHardwareTSOHandler(void* _Args) {
  auto Args = reinterpret_cast<FEXUnixLib_ProbeHardwareTSOArgs*>(_Args);
  Args->Result = ProbeHardwareTSO();
  Args->Trap = Args->Result == FEXUnixLib_HardwareTSOProbeResult::Available ? GetHardwareTSOTrapNumber() : 0;
  return STATUS_SUCCESS;
}
#else
static NTSTATUS FEXUnixLib_ProbeHardwareTSOHandler(void* _Args) {
  return STATUS_NOT_SUPPORTED;
}
#endif

static NTSTATUS FEXUnixLib_SetHardwareTSOControlHandler(void* _Args) {
  auto Args = reinterpret_cast<const FEXUnixLib_SetHardwareTSOControlArgs*>(_Args);
  if (Args->Enable) {
    int ret = prctl(PR_GET_MEM_MODEL, 0, 0, 0, 0);
    if (ret == PR_SET_MEM_MODEL_DEFAULT) {
      return prctl(PR_SET_MEM_MODEL, PR_SET_MEM_MODEL_TSO, 0, 0, 0) ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
    }
    return ret == PR_SET_MEM_MODEL_TSO ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
  }

  prctl(PR_SET_MEM_MODEL, PR_SET_MEM_MODEL_DEFAULT, 0, 0, 0);
  return STATUS_SUCCESS;
}

static NTSTATUS FEXUnixLib_SetKernelUnalignedAtomicControlHandler(void* _Args) {
  auto Args = reinterpret_cast<const FEXUnixLib_SetKernelUnalignedAtomicControl*>(_Args);
  return prctl(PR_ARM64_SET_UNALIGN_ATOMIC, Args->Flags, 0, 0, 0) == 0 ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
}

static NTSTATUS FEXUnixLib_MadviseHandler(void* _Args) {
  auto Args = reinterpret_cast<const FEXUnixLib_Madvise*>(_Args);
  return madvise(const_cast<void*>(Args->Addr), Args->Size, Args->Advise) == 0 ? STATUS_SUCCESS : STATUS_INTERNAL_ERROR;
}

static NTSTATUS FEXUnixLib_SetVMANameHandler(void* _Args) {
  auto Args = reinterpret_cast<const FEXUnixLib_SetVMAName*>(_Args);
  return prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, reinterpret_cast<unsigned long>(Args->Addr), Args->Size, Args->Name) == 0 ?
           STATUS_SUCCESS :
           STATUS_INTERNAL_ERROR;
}

constexpr static int USER_PERMS = S_IRWXU | S_IRWXG | S_IRWXO;
static inline void* InitializeSHM(uint32_t MapSize, uint32_t MaxSize, uint64_t MinAddress) {
  void* Base {};
  const std::string Name = "fex-" + std::to_string(getpid()) + "-stats";
  int fd = shm_open(Name.c_str(), O_CREAT | O_TRUNC | O_RDWR, USER_PERMS);

  if (fd == -1) {
    return nullptr;
  }

  if (ftruncate(fd, MapSize) == -1) {
    goto err;
  }

  // Reserve a region of MAX_STATS_SIZE so we can grow the allocation buffer.
  // Number of thread slots when ThreadStatsHeader == 64bytes and ThreadStats == 40bytes:
  // 1 page: 99 slots
  // 1 MB: 26211 slots
  // 128 MB: 3355440 slots
  // MinAddress is only a hint, see FEXUnixLib_MapFileHandler. Without a mapping profiling stays off.
  Base = mmap(reinterpret_cast<void*>(MinAddress), MaxSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (Base == MAP_FAILED) {
    Base = nullptr;
    goto err;
  }
  if (reinterpret_cast<uint64_t>(Base) < MinAddress) {
    ::munmap(Base, MaxSize);
    Base = nullptr;
    goto err;
  }

  prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, reinterpret_cast<void*>(Base), MaxSize, "FEXMem_Misc");

  // Allocate a small working shared space for now, grow as necessary.
  {
    auto SharedBase = mmap(Base, MapSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
    if (SharedBase == MAP_FAILED) {
      ::munmap(Base, MaxSize);
      Base = nullptr;
      goto err;
    }
  }

err:
  close(fd);
  if (!Base) {
    shm_unlink(Name.c_str());
  }

  return Base;
}

static inline bool AllocateMoreSlots(void* SHMBase, uint32_t NewSize) {
  bool Result {};
  const std::string Name = "fex-" + std::to_string(getpid()) + "-stats";

  // When allocating more slots, open the fd without O_TRUNC | O_CREAT.
  int fd = shm_open(Name.c_str(), O_RDWR, USER_PERMS);
  if (fd == -1) {
    return false;
  }

  if (ftruncate(fd, NewSize) == -1) {
    goto err;
  }

  {
    auto SharedBase = mmap(SHMBase, NewSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
    if (SharedBase == MAP_FAILED) {
      goto err;
    }
  }

  Result = true;

err:
  close(fd);
  return Result;
}

static NTSTATUS FEXUnixLib_GetSHMStatsVMAHandler(void* _Args) {
  auto Args = reinterpret_cast<FEXUnixLib_GetSHMStatsVMA*>(_Args);
  if (Args->SHMBase == nullptr) {
    Args->SHMBase = InitializeSHM(Args->MapSize, Args->MaxSize, Args->MinAddress);
    return Args->SHMBase ? STATUS_SUCCESS : STATUS_INTERNAL_ERROR;
  }

  return AllocateMoreSlots(Args->SHMBase, Args->MapSize) ? STATUS_SUCCESS : STATUS_INTERNAL_ERROR;
}

static NTSTATUS FEXUnixLib_DeleteSHMStatsFileHandler(void* _Args) {
  const std::string Name = "fex-" + std::to_string(getpid()) + "-stats";
  shm_unlink(Name.c_str());
  return STATUS_SUCCESS;
}

static NTSTATUS FEXUnixLib_MapFileHandler(void* _Args) {
  auto Args = reinterpret_cast<FEXUnixLib_MapFile*>(_Args);
  // could find a way to dedupe with DiskCacheFilemapper in FEXInterpreter but it's barely any code
  // fd was already duped by Wine handle translation
  // Wine doesn't track host mappings, so one placed in the address space the guest relies on would block it there.
  // MinAddress is passed as a hint only, as MAP_FIXED would replace whatever is mapped there. The kernel may place the
  // mapping elsewhere, so a mapping below MinAddress is undone and the cache reads the file instead.
  Args->Result = mmap(reinterpret_cast<void*>(Args->MinAddress), Args->MapSize, PROT_READ, MAP_SHARED | MAP_NORESERVE, Args->FD, 0);
  close(Args->FD);
  if (Args->Result == (void*)-1) {
    Args->Result = nullptr;
    return STATUS_INTERNAL_ERROR;
  }
  if (reinterpret_cast<uint64_t>(Args->Result) < Args->MinAddress) {
    munmap(Args->Result, Args->MapSize);
    Args->Result = nullptr;
    return STATUS_INTERNAL_ERROR;
  }
  return STATUS_SUCCESS;
}

static NTSTATUS FEXUnixLib_GetPIDHandler(void* _Args) {
  auto Args = reinterpret_cast<FEXUnixLib_GetPID*>(_Args);
  Args->Result = ::getpid();
  return STATUS_SUCCESS;
}

#ifdef __APPLE__
// Wine backs FEX's code buffers with MAP_JIT memory on macOS (MEM_EXTENDED_PARAMETER_WINE_UNIX_JIT),
// which is writable or executable per thread. FEX switches the calling thread around code writes.
static NTSTATUS FEXUnixLib_JITWriteProtectSupportedHandler(void* _Args) {
  return pthread_jit_write_protect_supported_np() ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
}

static NTSTATUS FEXUnixLib_JITWriteProtectHandler(void* _Args) {
  pthread_jit_write_protect_np(reinterpret_cast<const FEXUnixLib_JITWriteProtect*>(_Args)->Protect);
  return STATUS_SUCCESS;
}
#else
static NTSTATUS FEXUnixLib_JITWriteProtectSupportedHandler(void* _Args) {
  return STATUS_NOT_SUPPORTED;
}

static NTSTATUS FEXUnixLib_JITWriteProtectHandler(void* _Args) {
  return STATUS_NOT_SUPPORTED;
}
#endif

extern "C" const unixlib_entry_t __wine_unix_call_funcs[] = {
  FEXUnixLib_SetHardwareTSOControlHandler,
  FEXUnixLib_SetKernelUnalignedAtomicControlHandler,
  FEXUnixLib_MadviseHandler,
  FEXUnixLib_SetVMANameHandler,
  FEXUnixLib_GetSHMStatsVMAHandler,
  FEXUnixLib_DeleteSHMStatsFileHandler,
  FEXUnixLib_MapFileHandler,
  FEXUnixLib_GetPIDHandler,
  FEXUnixLib_JITWriteProtectSupportedHandler,
  FEXUnixLib_JITWriteProtectHandler,
  FEXUnixLib_ProbeHardwareTSOHandler,
};

static_assert(sizeof(__wine_unix_call_funcs) / sizeof(__wine_unix_call_funcs[0]) == ToUnderlying(FEXUnixLibFunctions::MAX));
