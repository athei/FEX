// SPDX-License-Identifier: MIT
/*
$info$
tags: Bin|WOW64
desc: Implements the WOW64 BT module API using FEXCore
$end_info$
*/

// Thanks to André Zwing, whose ideas from https://github.com/AndreRH/hangover this code is based upon

#include <FEXCore/fextl/fmt.h>
#include <FEXCore/fextl/vector.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/DiskCacheFileMapper.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/Threads.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/SHMStats.h>
#include <FEXCore/Utils/EnumOperators.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/FPState.h>
#include <FEXCore/Utils/ArchHelpers/Arm64.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/Utils/SignalScopeGuards.h>

#include "Windows/Common/Allocator.h"
#include "Windows/Common/EnvironmentVariablesHandling.h"
#include "Windows/Common/FEXUnixLib.h"
#include "Windows/Common/HardwareTSO.h"
#include "Common/CallRetStack.h"
#include "Common/JITGuardPage.h"
#include "Common/Config.h"
#include "Common/Exception.h"
#include "Common/TSOHandlerConfig.h"
#include "Common/ImageTracker.h"
#include "Common/InvalidationTracker.h"
#include "Common/Threads.h"
#include "Common/OvercommitTracker.h"
#include "Common/CPUFeatures.h"
#include "Common/Logging.h"
#include "Common/Module.h"
#include "Common/CRT/CRT.h"
#include "Common/PortabilityInfo.h"
#include "Common/Handle.h"
#include "DummyHandlers.h"
#include "BTInterface.h"
#include "Windows/Common/SHMStats.h"

#include <algorithm>
#include <cstdint>
#include <type_traits>
#include <atomic>
#include <mutex>
#include <utility>
#include <unordered_map>
#include <ntstatus.h>
#include <windef.h>
#include <winternl.h>
#include <wine/debug.h>
#include <wine/unixlib.h>

struct TLS {
  enum class Slot : size_t {
    ENTRY_CONTEXT = WOW64_TLS_MAX_NUMBER - 1,
    CONTROL_WORD = WOW64_TLS_MAX_NUMBER - 2,
    THREAD_STATE = WOW64_TLS_MAX_NUMBER - 3,
    CACHED_CALLRET_SP = WOW64_TLS_MAX_NUMBER - 4,
  };

  _TEB* TEB;

  explicit TLS(_TEB* TEB)
    : TEB(TEB) {}

  WOW64INFO& Wow64Info() const {
    return *reinterpret_cast<WOW64INFO*>(TEB->TlsSlots[WOW64_TLS_WOW64INFO]);
  }

  std::atomic<uint32_t>& ControlWord() const {
    // TODO: Change this when libc++ gains std::atomic_ref support
    return reinterpret_cast<std::atomic<uint32_t>&>(TEB->TlsSlots[FEXCore::ToUnderlying(Slot::CONTROL_WORD)]);
  }

  uint32_t* ControlWordAddress() const {
    return reinterpret_cast<uint32_t*>(&TEB->TlsSlots[FEXCore::ToUnderlying(Slot::CONTROL_WORD)]);
  }

  CONTEXT*& EntryContext() const {
    return reinterpret_cast<CONTEXT*&>(TEB->TlsSlots[FEXCore::ToUnderlying(Slot::ENTRY_CONTEXT)]);
  }

  FEXCore::Core::InternalThreadState*& ThreadState() const {
    return reinterpret_cast<FEXCore::Core::InternalThreadState*&>(TEB->TlsSlots[FEXCore::ToUnderlying(Slot::THREAD_STATE)]);
  }

  // This is used to work around user callback handling (see Wow64KiUserCallbackDispatcher in wine) unbalancing the
  // call-ret stace since user callbacks are returned from using a syscall that we can't really intercept.
  uint64_t& CachedCallRetSp() const {
    return reinterpret_cast<uint64_t&>(TEB->TlsSlots[FEXCore::ToUnderlying(Slot::CACHED_CALLRET_SP)]);
  }

  CHPE_V2_CPU_AREA_INFO*& CpuArea() const {
    return reinterpret_cast<__TEB*>(TEB)->ChpeV2CpuAreaInfo;
  }
};

WOW64_CONTEXT* GetWow64Context() {
  WOW64_CONTEXT* WowContext;
  RtlWow64GetCurrentCpuArea(nullptr, reinterpret_cast<void**>(&WowContext), nullptr);
  return WowContext;
}

struct FrontendThreadData {
  bool InLockedRWXRead {};
  // Set while the thread processes the cross-process work, see ProcessCrossProcessWork
  bool InCrossProcessWork {};
  // Set from the first to the second notification around a syscall when the first one entered the syscall callback state
  bool NotifyEnteredSyscallCallback {};
  CHPE_V2_CPU_AREA_INFO CpuArea {};

  // Takes over from the CPU area that BTCpuThreadInit set up for the thread: its syscall callback state, and a suspend
  // that Wine requested through its doorbell. The doorbell is read again once Wine sees only the new area.
  FrontendThreadData(const TLS& TLS) {
    CpuArea.SuspendDoorbell = reinterpret_cast<ULONG*>(&TLS.ThreadState()->CurrentFrame->SuspendDoorbell);
    const auto* InitCpuArea = TLS.CpuArea();
    if (InitCpuArea) {
      CpuArea.InSyscallCallback = InitCpuArea->InSyscallCallback;
    }
    std::atomic_signal_fence(std::memory_order_seq_cst);
    TLS.CpuArea() = &CpuArea;
    std::atomic_signal_fence(std::memory_order_seq_cst);
    if (InitCpuArea && *static_cast<volatile ULONG*>(InitCpuArea->SuspendDoorbell)) {
      *CpuArea.SuspendDoorbell = *InitCpuArea->SuspendDoorbell;
    }
  }
};

class WowSyscallHandler;

namespace {
namespace BridgeInstrs {
  // These directly jumped to by the guest to make system calls
  void* Syscall {};
  void* UnixCall {};
} // namespace BridgeInstrs

fextl::unique_ptr<FEXCore::Context::Context> CTX;
fextl::unique_ptr<FEX::DummyHandlers::DummySignalDelegator> SignalDelegator;
fextl::unique_ptr<WowSyscallHandler> SyscallHandler;
fextl::unique_ptr<FEX::Windows::StatAlloc> StatAllocHandler;

std::optional<FEX::Windows::InvalidationTracker> InvalidationTracker;
std::optional<FEX::Windows::CPUFeatures> CPUFeatures;
std::optional<FEX::Windows::OvercommitTracker> OvercommitTracker;
std::optional<FEX::Windows::ImageTracker> ImageTracker;

// The thread terminating the process, see BTCpuProcessTerm. Claimed with acquire-release, and cleared with release once
// TerminationSuspendedThreads is empty again.
std::atomic<DWORD> TerminatingThread {};
// Threads that BTCpuProcessTerm suspended, resumed again if the termination fails. Only the terminating thread uses it.
fextl::vector<HANDLE> TerminationSuspendedThreads;

// Waits until the thread is killed by the thread terminating the process, or until that termination fails. The wait is
// a syscall, in which Wine suspends the thread at once.
void WaitForTermination() {
  LARGE_INTEGER Timeout {.QuadPart = -100'000}; // 10ms
  while (TerminatingThread.load(std::memory_order_acquire)) {
    NtDelayExecution(FALSE, &Timeout);
  }
}

// Wine suspends a thread that is in the JIT (InSimulation) or a syscall callback cooperatively, where it holds no FEX
// locks, and any other thread immediately, wherever it is. The hooks that take FEX locks outside of the JIT enter the
// syscall callback state when they can, see EnterSyscallCallback.
bool IsSuspendCooperative() {
  const auto* CpuArea = TLS {NtCurrentTeb()}.CpuArea();
  return CpuArea && (CpuArea->InSimulation || CpuArea->InSyscallCallback);
}

// Outside of the JIT, FEX takes its locks with this mutex held, so once a thread has started terminating the process,
// any other thread outside of the JIT that takes the mutex waits for its end instead, holding no FEX locks. Recursive,
// since a fault on overcommitted memory takes it again in a thread that holds it. A nested lock never waits: the thread
// already holds the mutex, and waiting would keep it held.
class ThreadCreationMutexType final {
public:
  void lock() {
    const auto Self = GetCurrentThreadId();
    if (Owner.load(std::memory_order_relaxed) == Self) {
      Mutex.lock();
      ++Depth;
      return;
    }

    while (true) {
      Mutex.lock();
      const auto Terminating = TerminatingThread.load(std::memory_order_acquire);
      if (!Terminating || Terminating == Self || IsSuspendCooperative()) {
        Owner.store(Self, std::memory_order_relaxed);
        Depth = 1;
        return;
      }
      Mutex.unlock();
      WaitForTermination();
    }
  }

  void unlock() {
    if (--Depth == 0) {
      Owner.store(0, std::memory_order_relaxed);
    }
    Mutex.unlock();
  }

private:
  std::recursive_mutex Mutex;
  // The thread holding the mutex and how often, only changed by that thread
  std::atomic<DWORD> Owner {};
  uint32_t Depth {};
};

ThreadCreationMutexType ThreadCreationMutex;
// Map of TIDs to their FEX thread state, `ThreadCreationMutex` must be locked when accessing
std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*> Threads;

decltype(__wine_unix_call_dispatcher) WineUnixCall;

std::pair<NTSTATUS, TLS> GetThreadTLS(HANDLE Thread) {
  THREAD_BASIC_INFORMATION Info;
  const NTSTATUS Err = NtQueryInformationThread(Thread, ThreadBasicInformation, &Info, sizeof(Info), nullptr);
  return {Err, TLS {reinterpret_cast<_TEB*>(Info.TebBaseAddress)}};
}

TLS GetTLS() {
  return TLS {NtCurrentTeb()};
}

FrontendThreadData* GetFrontendThreadData(FEXCore::Core::InternalThreadState* Thread) {
  return static_cast<FrontendThreadData*>(Thread->FrontendPtr);
}

// The frontend data of the current thread, null until BTCpuThreadInit has set it up and after BTCpuThreadTerm
FrontendThreadData* GetCurrentFrontendThreadData() {
  const auto TLS = GetTLS();
  auto* Thread = TLS.CpuArea() ? TLS.ThreadState() : nullptr;
  return Thread ? GetFrontendThreadData(Thread) : nullptr;
}

// Wine suspends a thread in a syscall callback cooperatively, as one in the JIT, and any other thread at once. Wine runs
// the ARM64EC notification hooks in a syscall callback, but wow64 calls the WOW64 ones outside of one. A thread suspended
// at once in such a hook can hold a FEX lock, such as the code invalidation mutex, that a thread in the JIT needs before
// it reaches the point where it suspends, and whoever waits for both suspends then waits forever. So the hooks that take
// FEX locks outside of the JIT enter the syscall callback state themselves. Returns whether this call entered it.
// No wait in the server may happen in that state: the server marks a thread suspended at once, and holds every wait of a
// suspended thread until it is resumed, so a thread with a deferred suspend that waits there never reaches the point
// where it takes the suspend. FEX's own locks are critical sections and SRW locks, which Wine waits for in the process
// (RtlWaitOnAddress). A wait for a handle goes to the server when msync is off, so code in that state must not wait for
// one, such as BTCpuProcessTerm waiting for its suspends.
bool EnterSyscallCallback() {
  auto* CpuArea = GetTLS().CpuArea();
  if (!CpuArea || CpuArea->InSimulation || CpuArea->InSyscallCallback) {
    return false;
  }
  CpuArea->InSyscallCallback = 1;
  return true;
}

// Leaves the syscall callback state if EnterSyscallCallback entered it, and takes a suspend requested meanwhile, as
// UnlockJITContext does for the JIT.
void LeaveSyscallCallback(bool Entered) {
  if (!Entered) {
    return;
  }
  CHPE_V2_CPU_AREA_INFO* CpuArea = GetTLS().CpuArea();
  CpuArea->InSyscallCallback = 0;
  if (*CpuArea->SuspendDoorbell) {
    CONTEXT ResumeContext;
    RtlCaptureContext(&ResumeContext);
    if (*CpuArea->SuspendDoorbell) {
      NtContinue(&ResumeContext, FALSE);
    }
  }
}

class ScopedSyscallCallback final {
public:
  explicit ScopedSyscallCallback(bool Enter = true)
    : Entered {Enter && EnterSyscallCallback()} {}
  ~ScopedSyscallCallback() {
    LeaveSyscallCallback(Entered);
  }
  ScopedSyscallCallback(const ScopedSyscallCallback&) = delete;
  ScopedSyscallCallback& operator=(const ScopedSyscallCallback&) = delete;

private:
  bool Entered;
};

// Wine's wow64 queues the memory notifications and instruction cache flushes that other processes make for this one,
// and a thread of this one processes them at its next syscall or compile. The two notifications around a syscall become
// two items there, which different threads can process, and the second one is lost when the queue is full. Holding
// ThreadCreationMutex from the first to the second, as around a syscall of this process, could keep it held for long or
// for good, and orders nothing, as the other process makes its syscall without waiting for this one. So for queued
// items the first notification does nothing, and the second one takes the mutex only for its own work.
void ProcessCrossProcessWork() {
  auto* Data = GetFrontendThreadData(GetTLS().ThreadState());
  const bool Prev = Data->InCrossProcessWork;
  Data->InCrossProcessWork = true;
  Wow64ProcessPendingCrossProcessItems();
  Data->InCrossProcessWork = Prev;
}

// Handles a notification of a pair around a syscall, with Work done in the second one (After), see ProcessCrossProcessWork.
// Around a syscall of this process, the thread stays in the syscall callback state from the first to the second.
template<typename Func>
void NotifyAroundSyscall(BOOL After, Func&& Work) {
  auto* Data = GetCurrentFrontendThreadData();
  if (Data && Data->InCrossProcessWork) {
    if (After) {
      std::scoped_lock Lock(ThreadCreationMutex);
      Work();
    }
    return;
  }

  if (!After) {
    if (Data) {
      Data->NotifyEnteredSyscallCallback = EnterSyscallCallback();
    }
    ThreadCreationMutex.lock();
  } else {
    Work();
    ThreadCreationMutex.unlock();
    if (Data) {
      LeaveSyscallCallback(std::exchange(Data->NotifyEnteredSyscallCallback, false));
    }
  }
}

uint64_t GetWowTEB(void* TEB) {
  static constexpr size_t WowTEBOffsetMemberOffset {0x180c};
  return static_cast<uint64_t>(
    *reinterpret_cast<LONG*>(reinterpret_cast<uintptr_t>(TEB) + WowTEBOffsetMemberOffset) + reinterpret_cast<uint64_t>(TEB));
}

bool IsDispatcherAddress(uint64_t Address) {
  const auto& Config = SignalDelegator->GetConfig();
  return Address >= Config.DispatcherBegin && Address < Config.DispatcherEnd;
}

bool IsAddressInJit(uint64_t Address) {
  if (IsDispatcherAddress(Address)) {
    return true;
  }

  auto Thread = GetTLS().ThreadState();
  return Thread->CTX->IsAddressInCodeBuffer(Thread, Address);
}

void HandleImageMap(uint64_t Address, bool MainImage = false) {
  fextl::string ModulePath = FEX::Windows::GetSectionFilePath(Address);
  fextl::string ModuleName = fextl::string {FEX::Windows::BaseName(ModulePath)};
  InvalidationTracker->HandleImageMap(ModuleName, Address);
  ImageTracker->HandleImageMap(ModulePath, Address, MainImage);
}

void HandleImageUnmap(uint64_t Address, uint64_t Size) {
  ImageTracker->HandleImageUnmap(Address, Size);
}
} // namespace

namespace Context {
void LoadStateFromWowContext(FEXCore::Core::InternalThreadState* Thread) {
  auto& State = Thread->CurrentFrame->State;
  WOW64_CONTEXT* Context = GetWow64Context();

  // General register state

  State.gregs[FEXCore::X86State::REG_RAX] = Context->Eax;
  State.gregs[FEXCore::X86State::REG_RBX] = Context->Ebx;
  State.gregs[FEXCore::X86State::REG_RCX] = Context->Ecx;
  State.gregs[FEXCore::X86State::REG_RDX] = Context->Edx;
  State.gregs[FEXCore::X86State::REG_RSI] = Context->Esi;
  State.gregs[FEXCore::X86State::REG_RDI] = Context->Edi;
  State.gregs[FEXCore::X86State::REG_RBP] = Context->Ebp;
  State.gregs[FEXCore::X86State::REG_RSP] = Context->Esp;

  State.rip = Context->Eip;
  CTX->SetFlagsFromCompactedEFLAGS(Thread, Context->EFlags);

  State.es_idx = Context->SegEs & 0xffff;
  State.cs_idx = Context->SegCs & 0xffff;
  State.ss_idx = Context->SegSs & 0xffff;
  State.ds_idx = Context->SegDs & 0xffff;
  State.fs_idx = Context->SegFs & 0xffff;
  State.gs_idx = Context->SegGs & 0xffff;

  // The TEB is the only populated GDT entry by default
  auto GDT = State.GetSegmentFromIndex(State, (Context->SegFs & 0xffff));
  uint64_t WowTEB = GetWowTEB(NtCurrentTeb());
  State.SetGDTBase(GDT, WowTEB);
  State.SetGDTLimit(GDT, 0xF'FFFFU);
  State.fs_cached = WowTEB;
  State.es_cached = 0;
  State.cs_cached = 0;
  State.ss_cached = 0;
  State.ds_cached = 0;

  // Floating-point register state
  const auto* XSave = reinterpret_cast<XSAVE_FORMAT*>(Context->ExtendedRegisters);

  CTX->SetXMMRegistersFromState(Thread, reinterpret_cast<const __uint128_t*>(XSave->XmmRegisters), nullptr);
  memcpy(State.mm, XSave->FloatRegisters, sizeof(State.mm));

  State.FCW = XSave->ControlWord;
  State.flags[FEXCore::X86State::X87FLAG_IE_LOC] = XSave->StatusWord & 1;
  State.flags[FEXCore::X86State::X87FLAG_C0_LOC] = (XSave->StatusWord >> 8) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C1_LOC] = (XSave->StatusWord >> 9) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C2_LOC] = (XSave->StatusWord >> 10) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C3_LOC] = (XSave->StatusWord >> 14) & 1;
  State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] = (XSave->StatusWord >> 11) & 0b111;
  State.AbridgedFTW = XSave->TagWord;
}

void StoreWowContextFromState(WOW64_CONTEXT* Context) {
  auto Thread = GetTLS().ThreadState();
  auto& State = Thread->CurrentFrame->State;

  // General register state

  Context->Eax = State.gregs[FEXCore::X86State::REG_RAX];
  Context->Ebx = State.gregs[FEXCore::X86State::REG_RBX];
  Context->Ecx = State.gregs[FEXCore::X86State::REG_RCX];
  Context->Edx = State.gregs[FEXCore::X86State::REG_RDX];
  Context->Esi = State.gregs[FEXCore::X86State::REG_RSI];
  Context->Edi = State.gregs[FEXCore::X86State::REG_RDI];
  Context->Ebp = State.gregs[FEXCore::X86State::REG_RBP];
  Context->Esp = State.gregs[FEXCore::X86State::REG_RSP];

  Context->Eip = State.rip;
  Context->EFlags = CTX->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);

  Context->SegEs = State.es_idx;
  Context->SegCs = State.cs_idx;
  Context->SegSs = State.ss_idx;
  Context->SegDs = State.ds_idx;
  Context->SegFs = State.fs_idx;
  Context->SegGs = State.gs_idx;

  // Floating-point register state

  auto* XSave = reinterpret_cast<XSAVE_FORMAT*>(Context->ExtendedRegisters);

  CTX->ReconstructXMMRegisters(Thread, reinterpret_cast<__uint128_t*>(XSave->XmmRegisters), nullptr);
  memcpy(XSave->FloatRegisters, State.mm, sizeof(State.mm));

  XSave->ControlWord = State.FCW;
  XSave->StatusWord = (State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] << 11) | (State.flags[FEXCore::X86State::X87FLAG_C0_LOC] << 8) |
                      (State.flags[FEXCore::X86State::X87FLAG_C1_LOC] << 9) | (State.flags[FEXCore::X86State::X87FLAG_C2_LOC] << 10) |
                      (State.flags[FEXCore::X86State::X87FLAG_C3_LOC] << 14) | State.flags[FEXCore::X86State::X87FLAG_IE_LOC];
  XSave->TagWord = State.AbridgedFTW;

  Context->FloatSave.ControlWord = XSave->ControlWord;
  Context->FloatSave.StatusWord = XSave->StatusWord;
  Context->FloatSave.TagWord = FEXCore::FPState::ConvertFromAbridgedFTW(XSave->StatusWord, State.mm, XSave->TagWord);
  Context->FloatSave.ErrorOffset = XSave->ErrorOffset;
  Context->FloatSave.ErrorSelector = XSave->ErrorSelector | (XSave->ErrorOpcode << 16);
  Context->FloatSave.DataOffset = XSave->DataOffset;
  Context->FloatSave.DataSelector = XSave->DataSelector;
  Context->FloatSave.Cr0NpxState = XSave->StatusWord | 0xffff0000;
}

void FlushThreadStateContext() {
  StoreWowContextFromState(GetWow64Context());
}

void ReconstructThreadState(CONTEXT* Context) {
  const auto& Config = SignalDelegator->GetConfig();
  auto* Thread = GetTLS().ThreadState();
  auto& State = Thread->CurrentFrame->State;

  State.rip = CTX->RestoreRIPFromHostPC(Thread, Context->Pc);

  // Spill all SRA GPRs
  for (size_t i = 0; i < Config.SRAGPRCount; i++) {
    State.gregs[i] = Context->X[Config.SRAGPRMapping[i]];
  }

  // Spill all SRA FPRs
  for (size_t i = 0; i < Config.SRAFPRCount; i++) {
    memcpy(State.xmm.sse.data[i], &Context->V[Config.SRAFPRMapping[i]], sizeof(__uint128_t));
  }

  // Spill EFlags
  uint32_t EFlags = CTX->ReconstructCompactedEFLAGS(Thread, true, Context->X, Context->Cpsr);
  CTX->SetFlagsFromCompactedEFLAGS(Thread, EFlags);
}

WOW64_CONTEXT* ReconstructWowContext(CONTEXT* Context) {
  if (!IsDispatcherAddress(Context->Pc)) {
    ReconstructThreadState(Context);
  }

  WOW64_CONTEXT* WowContext = GetWow64Context();
  auto* XSave = reinterpret_cast<XSAVE_FORMAT*>(WowContext->ExtendedRegisters);
  XSave->ControlWord = 0x27f;
  XSave->MxCsr = 0x1f80;

  StoreWowContextFromState(WowContext);
  return WowContext;
}

static std::optional<FEX::Windows::TSOHandlerConfig> HandlerConfig;

bool HandleUnalignedAccess(CONTEXT* Context) {
  auto Thread = GetTLS().ThreadState();
  if (!Thread->CTX->IsAddressInCodeBuffer(Thread, Context->Pc)) {
    return false;
  }

  const auto Result =
    FEXCore::ArchHelpers::Arm64::HandleUnalignedAccess(Thread, HandlerConfig->GetUnalignedHandlerType(), Context->Pc, &Context->X0);
  Context->Pc += Result.value_or(0);
  return Result.has_value();
}

void LockJITContext() {
  TLS TLS = GetTLS();
  FEX::Windows::HardwareTSO::EnsureOn(TLS.ThreadState()->CurrentFrame);
  TLS.CpuArea()->InSimulation = -1;
  LoadStateFromWowContext(TLS.ThreadState());
}

void UnlockJITContext() {
  CHPE_V2_CPU_AREA_INFO* CpuArea = GetTLS().CpuArea();
  CpuArea->InSimulation = 0;
  if (*CpuArea->SuspendDoorbell) {
    CONTEXT ResumeContext;
    RtlCaptureContext(&ResumeContext);
    if (*CpuArea->SuspendDoorbell) {
      NtContinue(&ResumeContext, FALSE);
    }
  }
}

bool HandleSuspendInterrupt(CONTEXT* Context) {
  static constexpr uint32_t SuspendTrapMagic {0xD4395FC0}; // brk #0xCAFE
  if (*reinterpret_cast<uint32_t*>(Context->Pc) != SuspendTrapMagic) {
    return false;
  }

  // Since interrupts only happen at the start of blocks, the reconstructed state should be entirely accurate
  ReconstructThreadState(Context);
  FlushThreadStateContext();

  // Yield to the suspender
  UnlockJITContext();
  LockJITContext();

  // Adjust context to return to the dispatcher, reloading SRA from thread state
  const auto& Config = SignalDelegator->GetConfig();
  Context->Pc = Config.AbsoluteLoopTopAddressFillSRA;
  Context->X1 = 0; // Set ENTRY_FILL_SRA_SINGLE_INST_REG
  return true;
}
} // namespace Context

// Calls a 1-argument function `Func` setting the parent unwind frame information to the given SP and PC
__attribute__((naked)) extern "C" uint64_t SEHFrameTrampoline1Args(void* Arg0, void* Func, uint64_t Sp, uint64_t Pc) {
  asm(".seh_proc SEHFrameTrampoline1Args;"
      "stp x2, x3, [sp, #-0x10]!;"
      ".seh_pushframe;"
      "stp x29, x30, [sp, #-0x10]!;"
      ".seh_save_fplr_x 16;"
      ".seh_endprologue;"
      "blr x1;"
      "ldp x29, x30, [sp], 0x20;"
      "ret;"
      ".seh_endproc;");
}

// Calls a 2-argument function `Func` setting the parent unwind frame information to the given SP and PC
__attribute__((naked)) extern "C" uint64_t SEHFrameTrampoline2Args(void* Arg0, void* Arg1, void* Func, uint64_t Sp, uint64_t Pc) {
  asm(".seh_proc SEHFrameTrampoline2Args;"
      "stp x3, x4, [sp, #-0x10]!;"
      ".seh_pushframe;"
      "stp x29, x30, [sp, #-0x10]!;"
      ".seh_save_fplr_x 16;"
      ".seh_endprologue;"
      "blr x2;"
      "ldp x29, x30, [sp], 0x20;"
      "ret;"
      ".seh_endproc;");
}

class WowSyscallHandler : public FEXCore::HLE::SyscallHandler, public FEXCore::Allocator::FEXAllocOperators {
public:
  WowSyscallHandler() = default;

  static void HandleSyscallImpl(FEXCore::Core::CpuStateFrame* Frame) {
    const uint64_t ReturnRIP = *(uint32_t*)(Frame->State.gregs[FEXCore::X86State::REG_RSP]); // Return address from the stack
    uint64_t ReturnRSP = Frame->State.gregs[FEXCore::X86State::REG_RSP] + 4;                 // Stack pointer after popping return address
    uint64_t ReturnRAX = 0;

    if (Frame->State.rip == (uint64_t)BridgeInstrs::UnixCall) {
      struct StackLayout {
        unixlib_handle_t Handle;
        UINT32 ID;
        ULONG32 Args;
      }* StackArgs = reinterpret_cast<StackLayout*>(ReturnRSP);

      Frame->State.gregs[FEXCore::X86State::REG_RSP] = ReturnRSP + sizeof(StackLayout);
      Frame->State.rip = ReturnRIP;

      Context::FlushThreadStateContext();
      Context::UnlockJITContext();
      FEX::Windows::HardwareTSO::EnsureOff(Frame);
      ReturnRAX = static_cast<uint64_t>(WineUnixCall(StackArgs->Handle, StackArgs->ID, ULongToPtr(StackArgs->Args)));
      Context::LockJITContext();
      Frame->State.gregs[FEXCore::X86State::REG_RAX] = ReturnRAX;
    } else if (Frame->State.rip == (uint64_t)BridgeInstrs::Syscall) {
      const uint64_t EntryRAX = Frame->State.gregs[FEXCore::X86State::REG_RAX];

      Frame->State.gregs[FEXCore::X86State::REG_RSP] = ReturnRSP;
      Frame->State.rip = ReturnRIP;

      Context::FlushThreadStateContext();
      // The cross-process work takes FEX locks, so process it while InSimulation is still set, as PreCompile does. Wine
      // keeps a single alert per thread, and these locks wait for it too. The guest code may have registered a wait for
      // the alert just before this syscall, as RtlWaitOnAddress does. Our Wine's ntdll hands an alert that a lock wait
      // took on to the thread's next wait outside the emulator only if InSimulation or InSyscallCallback was set during
      // the lock wait. A suspend requested meanwhile is taken in UnlockJITContext, and ThreadCreationMutex is taken even
      // while another thread terminates the process, as in PreCompile.
      ProcessCrossProcessWork();
      Context::UnlockJITContext();
      FEX::Windows::HardwareTSO::EnsureOff(Frame);
      ReturnRAX = static_cast<uint64_t>(Wow64SystemServiceEx(static_cast<UINT>(EntryRAX), reinterpret_cast<UINT*>(ReturnRSP + 4)));
      Context::LockJITContext();
      Frame->State.gregs[FEXCore::X86State::REG_RAX] = ReturnRAX;
    }
  }

  void HandleSyscall(FEXCore::Core::CpuStateFrame* Frame) override {
    const auto TLS = GetTLS();
    // Stash the the context pointer on the stack, as Simulate can be called from this syscall handler which would overwrite it
    CONTEXT* EntryContext = TLS.EntryContext();
    // Call the syscall handler with unwind information pointing to Simulate as its caller
    SEHFrameTrampoline1Args(reinterpret_cast<void*>(Frame), reinterpret_cast<void*>(&HandleSyscallImpl), EntryContext->Sp, EntryContext->Pc);
    TLS.EntryContext() = EntryContext;
  }

  std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(FEXCore::Core::InternalThreadState*, uint64_t Address) override {
    return ImageTracker->LookupExecutableFileSection(Address);
  }

  void MarkGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override {
    InvalidationTracker->ReprotectRWXIntervals(Start, Length);
  }

  void InvalidateGuestCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override {
    InvalidationTracker->InvalidateAlignedInterval(Start, Length, false);
  }

  void MarkOvercommitRange(uint64_t Start, uint64_t Length) override {
    OvercommitTracker->MarkRange(Start, Length);
  }

  void UnmarkOvercommitRange(uint64_t Start, uint64_t Length) override {
    OvercommitTracker->UnmarkRange(Start, Length);
  }

  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) override {
    return InvalidationTracker->QueryExecutableRange(Address);
  }

  void PreCompile() override {
    ProcessCrossProcessWork();
  }
};

void BTCpuProcessInit() {
  FEX::Windows::InitCRTProcess();
  FEX::Windows::SetupThreadHandlers();
  const auto ExecutablePath = FEX::Windows::GetExecutableFilePath();
  const auto ExecutableName = FEX::Windows::BaseName(ExecutablePath);
  FEX::Config::LoadConfig(fextl::string {ExecutableName}, _environ, FEX::ReadPortabilityInformation());
  FEXCore::Config::ReloadMetaLayer();
  FEX::Windows::Logging::Init();

  FEXCore::Config::Set(FEXCore::Config::CONFIG_INTERPRETER_INSTALLED, "0");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "0");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_APP_FILENAME, ExecutablePath);
  FEXCore::Config::Set(FEXCore::Config::CONFIG_APP_CONFIG_NAME, ExecutableName);

  FEXCore::Profiler::Init("", "");

  SignalDelegator = fextl::make_unique<FEX::DummyHandlers::DummySignalDelegator>();
  SyscallHandler = fextl::make_unique<WowSyscallHandler>();
  const auto NtDll = GetModuleHandleW(L"ntdll.dll");
  const bool IsWine = !!GetProcAddress(NtDll, "wine_get_version");
  OvercommitTracker.emplace(IsWine);

  FEX::Windows::Allocator::SetupHooks(NtDll);
  FEX::Windows::UnixLib::Init(NtDll);
  if (FEX::Windows::UnixLib::Available()) {
    FEXCore::DiskCache::SetFileMapper(FEX::Windows::UnixLib::MapFile);
  }

  {
    auto HostFeatures =
      FEX::Windows::CPUFeatures::FetchHostFeatures(IsWine, FEXCore::HostFeatures::HostTypeEnum::Wow64, FEX::Windows::UnixLib::GetPID());
    HostFeatures.SupportsHardwareTSO = FEX::Windows::HardwareTSO::Init();
    CTX = FEXCore::Context::Context::CreateNewContext(HostFeatures);
  }

  CTX->SetSignalDelegator(SignalDelegator.get());
  CTX->SetSyscallHandler(SyscallHandler.get());
  CTX->InitCore();
  Context::HandlerConfig.emplace();
  InvalidationTracker.emplace(*CTX, Threads);
  ImageTracker.emplace(*CTX, false);

  auto MainModule = reinterpret_cast<__TEB*>(NtCurrentTeb())->Peb->ImageBaseAddress;
  HandleImageMap(reinterpret_cast<uint64_t>(MainModule), true);

  auto NtDllX86 = reinterpret_cast<SYSTEM_DLL_INIT_BLOCK*>(GetProcAddress(NtDll, "LdrSystemDllInitBlock"))->ntdll_handle;
  HandleImageMap(NtDllX86);

  CPUFeatures.emplace(*CTX);

  // Allocate the syscall/unixcall trampolines in the lower 2GB of the address space
  SIZE_T Size = 4;
  void* Addr = nullptr;
  NtAllocateVirtualMemory(NtCurrentProcess(), &Addr, (1U << 31) - 1, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(Addr), Size, PAGE_EXECUTE);
  *reinterpret_cast<uint32_t*>(Addr) = 0x2ecd2ecd;
  BridgeInstrs::Syscall = Addr;
  BridgeInstrs::UnixCall = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(Addr) + 2);

  const auto Sym = GetProcAddress(NtDll, "__wine_unix_call_dispatcher");
  if (Sym) {
    WineUnixCall = *reinterpret_cast<decltype(WineUnixCall)*>(Sym);
  }

  FEX::Windows::SetupEnvironmentVariableValues(NtDll);

  // wow64.dll will only initialise the cross-process queue if this is set
  GetTLS().Wow64Info().CpuFlags = WOW64_CPUFLAGS_SOFTWARE;

  FEX_CONFIG_OPT(ProfileStats, PROFILESTATS);
  FEX_CONFIG_OPT(StartupSleep, STARTUPSLEEP);
  FEX_CONFIG_OPT(StartupSleepProcName, STARTUPSLEEPPROCNAME);

  if (IsWine && ProfileStats()) {
    StatAllocHandler = fextl::make_unique<FEX::Windows::StatAlloc>(FEXCore::SHMStats::AppType::WIN_WOW64);
  }

  if (StartupSleep() && (StartupSleepProcName().empty() || ExecutableName == StartupSleepProcName())) {
    LogMan::Msg::IFmt("[{}][{}] Sleeping for {} seconds", GetCurrentProcessId(), ExecutableName, StartupSleep());
    std::this_thread::sleep_for(std::chrono::seconds(StartupSleep()));
  }
}

// Wine calls this around NtTerminateProcess(0), which kills every other thread wherever it is before the caller runs the
// DLL detach routines. A thread killed while it holds a JIT lock, such as the lookup cache lock taken to compile or look
// up a block, leaves it held for good, and the caller hangs once it needs that lock. So suspend the other threads first,
// as BTCpuThreadTerm does for one thread, and pause FEX's own background threads. A call for another process, or for the
// current one by handle, which ends it without running more code in it, needs nothing.
void BTCpuProcessTerm(HANDLE Handle, BOOL After, ULONG Status) {
  if (Handle) {
    return;
  }

  if (After) {
    for (auto Thread : TerminationSuspendedThreads) {
      if (!NT_SUCCESS(Status)) {
        NtResumeThread(Thread, nullptr);
      }
      NtClose(Thread);
    }
    TerminationSuspendedThreads.clear();
    if (!NT_SUCCESS(Status)) {
      CTX->ResumeBackgroundThreads();
      TerminatingThread.store(0, std::memory_order_release);
    }
    return;
  }

  // Claimed before taking the mutex, so that a thread suspending this one in BTCpuThreadTerm from now on sees the claim,
  // and so that any other thread terminating the process at the same time waits here to be killed.
  const auto Self = GetCurrentThreadId();
  for (DWORD Expected = 0;
       !TerminatingThread.compare_exchange_strong(Expected, Self, std::memory_order_acq_rel, std::memory_order_acquire) && Expected != Self;
       Expected = 0) {
    WaitForTermination();
  }

  // The threads FEX knows are collected with the mutex held, in the syscall callback state, see EnterSyscallCallback.
  // Their suspends are requested and waited for once this thread has left that state and taken a suspend of it requested
  // meanwhile, see SuspendThreadsForTermination, outside of that state as the wait goes to the server without msync.
  fextl::vector<HANDLE> Candidates;
  {
    ScopedSyscallCallback Callback;
    std::scoped_lock Lock(ThreadCreationMutex);

    constexpr ACCESS_MASK Access = THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT;
    HANDLE Thread {};
    bool Keep {};
    HANDLE Next;
    while (!NtGetNextThread(NtCurrentProcess(), Thread, Access, 0, 0, &Next)) {
      if (Thread && !Keep) {
        NtClose(Thread);
      }
      Thread = Next;
      Keep = false;

      THREAD_BASIC_INFORMATION Info;
      if (NtQueryInformationThread(Thread, ThreadBasicInformation, &Info, sizeof(Info), nullptr)) {
        continue;
      }
      const auto ThreadTID = static_cast<DWORD>(reinterpret_cast<uintptr_t>(Info.ClientId.UniqueThread));
      if (ThreadTID == Self || !Threads.contains(ThreadTID)) {
        continue;
      }
      Candidates.push_back(Thread);
      Keep = true;
    }
    if (Thread && !Keep) {
      NtClose(Thread);
    }
  }

  // Without the mutex, which a thread in the JIT may need before it can suspend. A thread that starts after the claim
  // waits in BTCpuThreadInit, and one that ends meanwhile fails the suspend.
  TerminationSuspendedThreads =
    FEX::Windows::SuspendThreadsForTermination(Candidates, [](HANDLE Thread) { return RtlWow64SuspendThread(Thread, nullptr); });
  for (auto Thread : Candidates) {
    if (std::ranges::find(TerminationSuspendedThreads, Thread) == TerminationSuspendedThreads.end()) {
      NtClose(Thread);
    }
  }

  // With the guest threads stopped, a store the disk cache writer has in progress can finish. With a disk cache, this
  // waits for the writer's mutex outside of the syscall callback state. Our arm64 builds don't enable the disk cache, so
  // there is no writer and this takes no lock.
  CTX->PauseBackgroundThreads();
}

// The part of BTCpuThreadInit that runs with ThreadCreationMutex held
static void InitThreadLocked() {
  static constexpr size_t DefaultWow64CS {4};
  FEX::Windows::InitCRTThread();
  auto* Thread = CTX->CreateThread();

  // Default segment setup.
  auto Frame = Thread->CurrentFrame;
  auto NewSegments = new FEXCore::Core::CPUState::gdt_segment[32]();

  // Setup initial code-segment GDT
  auto& GDT = NewSegments[DefaultWow64CS];
  FEXCore::Core::CPUState::SetGDTBase(&GDT, 0);
  FEXCore::Core::CPUState::SetGDTLimit(&GDT, 0xF'FFFFU);
  GDT.L = 0; // L = Long Mode = 32-bit
  GDT.D = 1; // D = Default Operand Size = 32-bit

  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = &NewSegments[0];
  // TODO: LDTs are currently unsupported, mirror them to GDT.
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = &NewSegments[0];

  Frame->State.cs_idx = DefaultWow64CS << 3;
  Frame->State.cs_cached = FEXCore::Core::CPUState::CalculateGDTBase(GDT);

  FEX::Windows::CallRetStack::InitializeThread(Thread);
  FEX::Windows::HardwareTSO::InitThread(Frame);

  const auto TLS = GetTLS();
  TLS.ThreadState() = Thread;

  Thread->FrontendPtr = new FrontendThreadData(TLS);

  auto ThreadTID = GetCurrentThreadId();
  Threads.emplace(ThreadTID, Thread);
  if (StatAllocHandler) {
    Thread->ThreadStats = StatAllocHandler->AllocateSlot(ThreadTID);
  }
}

void BTCpuThreadInit() {
  // Wine suspends a thread without a CPU area at once, which could leave ThreadCreationMutex held by a suspended thread.
  // So until FrontendThreadData sets up the thread's own area, the thread uses one on the stack and enters the syscall
  // callback state in it, see EnterSyscallCallback. Taking the mutex is then cooperative, so a thread that starts while
  // another thread terminates the process checks for that itself, and waits to be killed instead of entering the JIT.
  ULONG InitDoorbell {};
  CHPE_V2_CPU_AREA_INFO InitCpuArea {};
  InitCpuArea.SuspendDoorbell = &InitDoorbell;
  GetTLS().CpuArea() = &InitCpuArea;

  const auto Self = GetCurrentThreadId();
  bool Entered;
  while (true) {
    Entered = EnterSyscallCallback();
    ThreadCreationMutex.lock();
    const auto Terminating = TerminatingThread.load(std::memory_order_acquire);
    if (!Terminating || Terminating == Self) {
      break;
    }
    ThreadCreationMutex.unlock();
    LeaveSyscallCallback(Entered);
    WaitForTermination();
  }

  {
    std::scoped_lock Lock(std::adopt_lock, ThreadCreationMutex);
    InitThreadLocked();
  }
  // In the thread's own area by now
  LeaveSyscallCallback(Entered);
}

void BTCpuThreadTerm(HANDLE Thread, LONG ExitCode) {
  if (!FEX::Windows::ValidateHandleAccess(Thread, THREAD_TERMINATE)) {
    return;
  }

  auto ThreadDup = FEX::Windows::DupHandle(Thread, THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT);

  THREAD_BASIC_INFORMATION Info;
  if (auto Err = NtQueryInformationThread(*ThreadDup, ThreadBasicInformation, &Info, sizeof(Info), nullptr); Err) {
    return;
  }

  // A thread of another process has no state in this one to tear down.
  if (reinterpret_cast<uint64_t>(Info.ClientId.UniqueProcess) != GetCurrentProcessId()) {
    return;
  }

  LogMan::Msg::IFmt("Terminating {}", Info.ClientId.UniqueThread);
  const auto ThreadTID = reinterpret_cast<uint64_t>(Info.ClientId.UniqueThread);
  bool Self = ThreadTID == GetCurrentThreadId();
  if (!Self) {
    CONTEXT TmpContext;
    // If we are suspending a thread that isn't ourselves, try to suspend it first so we know internal JIT locks aren't being held.
    RtlWow64SuspendThread(*ThreadDup, NULL);
    // This will wait for the thread to be suspended
    TmpContext.ContextFlags = CONTEXT_CONTROL;
    NtGetContextThread(*ThreadDup, &TmpContext);

    // The target may be terminating the process, which it claimed before taking any FEX lock. It kills this thread, so
    // let it go on and wait for that, and try again if the termination fails.
    if (TerminatingThread.load(std::memory_order_acquire) == ThreadTID) {
      NtResumeThread(*ThreadDup, nullptr);
      WaitForTermination();
      return BTCpuThreadTerm(Thread, ExitCode);
    }
  }

  auto [Err, TLS] = GetThreadTLS(*ThreadDup);
  if (Err) {
    return;
  }

  // The teardown runs in the syscall callback state, see EnterSyscallCallback. The current thread's own CPU area goes away
  // in its teardown, so the thread switches to one on its stack first, which takes over a suspend requested through the
  // old one, as in BTCpuThreadInit. It drops that area once it holds no FEX locks any more.
  class TermCpuAreaSwitch final {
  public:
    TermCpuAreaSwitch(const ::TLS& TLS, bool Self)
      : TLS {TLS}
      , Own {Self ? TLS.CpuArea() : nullptr} {
      if (!Own) {
        return;
      }
      CpuArea.SuspendDoorbell = &Doorbell;
      std::atomic_signal_fence(std::memory_order_seq_cst);
      TLS.CpuArea() = &CpuArea;
      std::atomic_signal_fence(std::memory_order_seq_cst);
      if (*static_cast<volatile ULONG*>(Own->SuspendDoorbell)) {
        Doorbell = *Own->SuspendDoorbell;
      }
    }
    ~TermCpuAreaSwitch() {
      if (Own) {
        TLS.CpuArea() = TornDown ? nullptr : Own;
      }
    }
    TermCpuAreaSwitch(const TermCpuAreaSwitch&) = delete;
    TermCpuAreaSwitch& operator=(const TermCpuAreaSwitch&) = delete;

    bool TornDown {};

  private:
    ::TLS TLS;
    CHPE_V2_CPU_AREA_INFO* Own;
    ULONG Doorbell {};
    CHPE_V2_CPU_AREA_INFO CpuArea {};
  } AreaSwitch {TLS, Self};
  ScopedSyscallCallback Callback;

  {
    // Held for the whole teardown, which takes FEX locks outside of the JIT, see ThreadCreationMutexType
    std::scoped_lock Lock(ThreadCreationMutex);
    auto it = Threads.find(ThreadTID);
    if (it == Threads.end()) {
      // Thread already terminated
      return;
    }

    Threads.erase(it);
    if (StatAllocHandler) {
      StatAllocHandler->DeallocateSlot(TLS.ThreadState()->ThreadStats);
    }
    auto ThreadState = TLS.ThreadState();

    if (!Self) {
      TLS.CpuArea() = nullptr;
    }
    AreaSwitch.TornDown = true;
    delete GetFrontendThreadData(ThreadState);

    // GDT and LDT are mirrored, only free one.
    delete[] ThreadState->CurrentFrame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT];

    FEX::Windows::CallRetStack::DestroyThread(ThreadState);
    CTX->DestroyThread(ThreadState);
  }
  if (Self) {
    FEX::Windows::DeinitCRTThread();
  }
}

void* BTCpuGetBopCode() {
  return BridgeInstrs::Syscall;
}

void* __wine_get_unix_opcode() {
  return BridgeInstrs::UnixCall;
}

NTSTATUS BTCpuGetContext(HANDLE Thread, HANDLE Process, void* Unknown, WOW64_CONTEXT* Context) {
  return RtlWow64GetThreadContext(Thread, Context);
}

NTSTATUS BTCpuSetContext(HANDLE Thread, HANDLE Process, void* Unknown, WOW64_CONTEXT* Context) {
  return RtlWow64SetThreadContext(Thread, Context);
}

// .seh_pushframe doesn't restore the frame pointer, so if when unwinding from RtlCaptureContext an operation is used
// that sets SP from FP, the unwound SP value will be incorrect. Wrap RtlCaptureContext so the correct FP is immediately
// restored from the stack to prevent this.
__attribute__((naked)) void BTCpuSimulate() {
  asm(".seh_proc BTCpuSimulate;"
      "sub sp, sp, #0x390;"
      ".seh_stackalloc 0x390;"
      "stp x29, x30, [sp, #-0x10]!;"
      ".seh_save_fplr_x 16;"
      ".seh_endprologue;"
      "add x0, sp, #0x10;"
      "bl RtlCaptureContext;"
      "add x0, sp, #0x10;"
      "bl BTCpuSimulateImpl;"
      "ldp x29, x30, [sp], 0x10;"
      "add sp, sp, #0x390;"
      "ret;"
      ".seh_endproc;");
}

extern "C" void BTCpuSimulateImpl(CONTEXT* entry_context) {
  const auto TLS = GetTLS();
  TLS.EntryContext() = entry_context;
  TLS.CachedCallRetSp() = TLS.ThreadState()->CurrentFrame->State.callret_sp;

  Context::LockJITContext();
  CTX->ExecuteThread(TLS.ThreadState());
  Context::UnlockJITContext();
}

NTSTATUS BTCpuSuspendLocalThread(HANDLE Thread, ULONG* Count) {
  return NtSuspendThread(Thread, Count);
}

// Returns true if exception dispatch should be halted and the execution context restored to Ptrs->Context
bool BTCpuResetToConsistentStateImpl(EXCEPTION_POINTERS* Ptrs) {
  auto* Context = Ptrs->ContextRecord;
  auto* Exception = Ptrs->ExceptionRecord;
  auto Thread = GetTLS().ThreadState();
  FEXCORE_PROFILE_ACCUMULATION(Thread, AccumulatedSignalTime);

  if (Exception->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
    const auto FaultAddress = static_cast<uint64_t>(Exception->ExceptionInformation[1]);
    // A fault outside of the JIT, in a syscall that writes guest memory for one, takes FEX locks below
    ScopedSyscallCallback Callback;

    if (FEX::Windows::CallRetStack::HandleAccessViolation(Thread, FaultAddress, Context->X25)) {
      return true;
    }

    if (OvercommitTracker) {
      // The tracker's lock is a FEX lock taken outside of the JIT here, see ThreadCreationMutexType
      std::unique_lock Lock(ThreadCreationMutex, std::defer_lock);
      if (!IsSuspendCooperative()) {
        Lock.lock();
      }
      if (OvercommitTracker->HandleAccessViolation(FaultAddress)) {
        return true;
      }
    }

    if (FEX::Windows::JITGuardPage::HandleJITGuardPage(Thread, reinterpret_cast<void*>(FaultAddress), Context->X,
                                                       reinterpret_cast<__uint128_t*>(Context->V), &Context->Pc)) {
      return true;
    }

    if (Thread) {
      std::scoped_lock Lock(ThreadCreationMutex);
      FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSMCCount, 1);
      if (InvalidationTracker->HandleRWXAccessViolation(Thread, Context->Pc, FaultAddress)) {
        if (CTX->IsAddressInCodeBuffer(Thread, Context->Pc) && !CTX->IsCurrentBlockSingleInst(Thread) &&
            CTX->IsAddressInCurrentBlock(Thread, FaultAddress & FEXCore::Utils::FEX_PAGE_MASK, FEXCore::Utils::FEX_PAGE_SIZE)) {
          Context::ReconstructThreadState(Context);
          LogMan::Msg::DFmt("Handled inline self-modifying code: pc: {:X} rip: {:X} fault: {:X}", Context->Pc,
                            Thread->CurrentFrame->State.rip, FaultAddress);

          // Adjust context to return to the dispatcher, reloading SRA from thread state
          const auto& Config = SignalDelegator->GetConfig();
          Context->Pc = Config.AbsoluteLoopTopAddressFillSRA;
          Context->X1 = 1; // Set ENTRY_FILL_SRA_SINGLE_INST_REG to force a single step
        } else {
          LogMan::Msg::DFmt("Handled self-modifying code: pc: {:X} fault: {:X}", Context->Pc, FaultAddress);
        }
        return true;
      }
    }
  }

  if (!Thread || !IsAddressInJit(Context->Pc)) {
    return false;
  }

  if (Exception->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION && Context::HandleSuspendInterrupt(Context)) {
    LogMan::Msg::DFmt("Resumed from suspend");
    return true;
  }

  FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSIGBUSCount, 1);
  if (Exception->ExceptionCode == EXCEPTION_DATATYPE_MISALIGNMENT && Context::HandleUnalignedAccess(Context)) {
    LogMan::Msg::DFmt("Handled unaligned atomic: new pc: {:X}", Context->Pc);
    return true;
  }

  LogMan::Msg::DFmt("Reconstructing context");

  WOW64_CONTEXT* WowContext = Context::ReconstructWowContext(Context);
  LogMan::Msg::DFmt("pc: {:X} eip: {:X} code: {:X}", Context->Pc, WowContext->Eip, Exception->ExceptionCode);

  auto& Fault = Thread->CurrentFrame->SynchronousFaultData;
  BOOL FirstChance = TRUE;
  EXCEPTION_RECORD GuestException =
    FEX::Windows::HandleGuestException(Fault, *Exception, WowContext->Eip, WowContext->Eax, WowContext->Ecx, FirstChance);
  if (GuestException.ExceptionCode == EXCEPTION_SINGLE_STEP) {
    WowContext->EFlags &= ~(1 << FEXCore::X86State::RFLAG_TF_RAW_LOC);
  }
  // wow64.dll will handle adjusting PC in the dispatched context after a breakpoint

  Context::UnlockJITContext();
  NtRaiseException(&GuestException, GetTLS().EntryContext(), FirstChance);
  return false;
}

NTSTATUS BTCpuResetToConsistentState(EXCEPTION_POINTERS* Ptrs) {
  if (BTCpuResetToConsistentStateImpl(Ptrs)) {
    // Resuming JIT code does not pass through LockJITContext.
    if (auto Thread = GetTLS().ThreadState(); Thread && IsAddressInJit(Ptrs->ContextRecord->Pc)) {
      FEX::Windows::HardwareTSO::EnsureOn(Thread->CurrentFrame);
    }
    NtContinue(Ptrs->ContextRecord, FALSE);
  }

  return STATUS_SUCCESS;
}

void BTCpuFlushInstructionCache2(const void* Address, SIZE_T Size) {
  ScopedSyscallCallback Callback;
  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
}

void BTCpuFlushInstructionCacheHeavy(const void* Address, SIZE_T Size) {
  ScopedSyscallCallback Callback;
  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
}

void BTCpuNotifyMemoryDirty(void* Address, SIZE_T Size) {
  ScopedSyscallCallback Callback;
  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
}

void BTCpuNotifyMemoryAlloc(void* Address, SIZE_T Size, ULONG Type, ULONG Prot, BOOL After, ULONG Status) {
  NotifyAroundSyscall(After, [&] {
    // MEM_RESET(_UNDO) ignores the passed permissions
    if (!Status && !(Type & (MEM_RESET | MEM_RESET_UNDO))) {
      InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), Prot);
    }
  });
}

void BTCpuNotifyMemoryProtect(void* Address, SIZE_T Size, ULONG NewProt, BOOL After, ULONG Status) {
  NotifyAroundSyscall(After, [&] {
    if (!Status) {
      InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), NewProt);
    }
  });
}

void BTCpuNotifyMemoryFree(void* Address, SIZE_T Size, ULONG FreeType, BOOL After, ULONG Status) {
  NotifyAroundSyscall(After, [&] {
    if (!Status) {
      InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), true);
    }
  });
}

NTSTATUS BTCpuNotifyMapViewOfSection(void* Unk1, void* Address, void* Unk2, SIZE_T Size, ULONG AllocType, ULONG Prot) {
  ScopedSyscallCallback Callback;
  std::scoped_lock Lock(ThreadCreationMutex);
  HandleImageMap(reinterpret_cast<uint64_t>(Address));
  return STATUS_SUCCESS;
}

// Only made for a syscall of this process, which stays in the syscall callback state from the first to the second
void BTCpuNotifyUnmapViewOfSection(void* Address, BOOL After, ULONG Status) {
  auto* Data = GetCurrentFrontendThreadData();
  if (!After) {
    if (Data) {
      Data->NotifyEnteredSyscallCallback = EnterSyscallCallback();
    }
    ThreadCreationMutex.lock();
    auto [Start, Size] = InvalidationTracker->InvalidateContainingSection(reinterpret_cast<uint64_t>(Address), true);
    if (Size) {
      HandleImageUnmap(Start, Size);
    }
  } else {
    ThreadCreationMutex.unlock();
    if (Data) {
      LeaveSyscallCallback(std::exchange(Data->NotifyEnteredSyscallCallback, false));
    }
  }
}

void BTCpuNotifyReadFile(HANDLE Handle, void* Address, SIZE_T Size, BOOL After, NTSTATUS Status) {
  auto* ThreadState = GetTLS().ThreadState();
  if (!InvalidationTracker || !ThreadState) {
    return;
  }

  // See arm64ec `BTCpu64NotifyReadFile` for why this like this.
  if (After && Status == STATUS_SUCCESS) {
    ScopedSyscallCallback Callback;
    std::scoped_lock Lock(ThreadCreationMutex);
    InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
  }
}

void BTCpuNotifyProcessExecuteFlagsChange(ULONG Flags) {
  ScopedSyscallCallback Callback;
  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->HandleProcessExecuteFlagsChange(Flags);
}

BOOLEAN WINAPI BTCpuIsProcessorFeaturePresent(UINT Feature) {
  return CPUFeatures->IsFeaturePresent(Feature) ? TRUE : FALSE;
}

void BTCpuUpdateProcessorInformation(SYSTEM_CPU_INFORMATION* Info) {
  CPUFeatures->UpdateInformation(Info);
}
