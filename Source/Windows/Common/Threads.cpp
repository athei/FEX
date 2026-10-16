// SPDX-License-Identifier: MIT
#include "Threads.h"
#include "CRT/CRT.h"

#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/Threads.h>
#include <FEXCore/fextl/memory.h>

#include <atomic>

#include <winternl.h>
#include <windows.h>

#include "Handle.h"

namespace FEX::Windows {
namespace WinThreadImpl {
  class Thread final : public FEXCore::Threads::Thread {
  public:
    Thread(FEXCore::Threads::ThreadFunc Func, void* Arg, FEXCore::Threads::Flags Flags, const char* ThreadName)
      : UserFunc {Func}
      , UserArg {Arg}
      , Flags {Flags} {
      // hide everything from guest, don't initialize anything, we'll do that manually in RunThread()
      ULONG CreateFlags = THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH | THREAD_CREATE_FLAGS_SKIP_LOADER_INIT | THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE;
      if (Flags.Internal) {
        CreateFlags |= THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
      }
      NTSTATUS Status = NtCreateThreadEx(&Handle, THREAD_ALL_ACCESS, nullptr, GetCurrentProcess(),
                                         reinterpret_cast<PRTL_THREAD_START_ROUTINE>(&Thread::RunThread), this, CreateFlags, 0, 0, 0, nullptr);
      if (Status < 0) {
        LogMan::Msg::EFmt("NtCreateThreadEx failed: 0x{:x}", static_cast<uint32_t>(Status));
        Handle = nullptr;
      }

      if (ThreadName) {
        UNICODE_STRING ThreadNameW;
        if (RtlCreateUnicodeStringFromAsciiz(&ThreadNameW, ThreadName)) {
          THREAD_NAME_INFORMATION info {
            .ThreadName = ThreadNameW,
          };
          NtSetInformationThread(Handle, static_cast<THREADINFOCLASS>(38) /* ThreadNameInformation */, &info, sizeof(info));
          RtlFreeUnicodeString(&ThreadNameW);
        }
      }
    }

    bool joinable() override {
      return Handle != nullptr;
    }

    bool join(void** ret) override {
      if (!Handle) {
        return false;
      }
      NtWaitForSingleObject(Handle, FALSE, nullptr);
      if (ret) {
        *ret = ReturnValue;
      }
      return true;
    }

    bool detach() override {
      // almost no-op, it's already detached, just deref handle
      if (Handle) {
        NtClose(Handle);
        Handle = nullptr;
      }
      return true;
    }

    bool IsSelf() override {
      return TID == GetCurrentThreadId();
    }

    ~Thread() override {
      if (Handle) {
        NtClose(Handle);
      }
    }

    FEXCore::Threads::Flags GetFlags() const {
      return Flags;
    }

  private:
    static void RunThread(Thread* This) {
      This->TID = GetCurrentThreadId();
      if (This->GetFlags().LowPriority) {
        LONG Priority = THREAD_BASE_PRIORITY_IDLE;
        NtSetInformationThread(NtCurrentThread(), ThreadBasePriority, &Priority, sizeof(Priority));
      }
      // do initialization we skipped earlier here around the user entrypoint
      FEX::Windows::InitCRTThread();
      This->ReturnValue = This->UserFunc(This->UserArg);
      FEX::Windows::DeinitCRTThread();
      NtTerminateThread(GetCurrentThread(), 0);
    }

    FEXCore::Threads::ThreadFunc UserFunc;
    void* UserArg;
    FEXCore::Threads::Flags Flags {};
    HANDLE Handle {};
    DWORD TID {};
    void* ReturnValue {};
  };

  fextl::unique_ptr<FEXCore::Threads::Thread>
  CreateThread(FEXCore::Threads::ThreadFunc Func, void* Arg, FEXCore::Threads::Flags Flags, const char* ThreadName) {
    return fextl::make_unique<Thread>(Func, Arg, Flags, ThreadName);
  }

  void CleanupAfterFork() {}
} // namespace WinThreadImpl

void SetupThreadHandlers() {
  FEXCore::Threads::Pointers Ptrs = {
    .CreateThread = WinThreadImpl::CreateThread,
    .CleanupAfterFork = WinThreadImpl::CleanupAfterFork,
  };
  FEXCore::Threads::Thread::SetInternalPointers(Ptrs);
}

namespace {
  enum TerminationSuspendState : uint8_t {
    Unclaimed,
    Claimed,
    Suspended,
    NotSuspended,
  };

  // Shared by the terminating thread and the helper. The helper uses its own handles, and if it doesn't finish in time,
  // the terminating thread leaves all of this to it, so that nothing it still uses is freed or closed.
  struct TerminationSuspend {
    TerminationSuspend(const fextl::vector<HANDLE>& Targets, NTSTATUS (*Suspend)(HANDLE))
      : Threads(Targets.size())
      , States(Targets.size())
      , Suspend {Suspend} {
      for (size_t i = 0; i < Targets.size(); ++i) {
        NtDuplicateObject(NtCurrentProcess(), Targets[i], NtCurrentProcess(), &Threads[i], 0, 0, DUPLICATE_SAME_ACCESS);
      }
      NtDuplicateObject(NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &Terminating, THREAD_SUSPEND_RESUME, 0, 0);
    }

    ~TerminationSuspend() {
      for (auto Thread : Threads) {
        NtClose(Thread);
      }
      NtClose(Terminating);
    }

    fextl::vector<HANDLE> Threads;
    fextl::vector<std::atomic<uint8_t>> States;
    NTSTATUS (*Suspend)(HANDLE);
    HANDLE Terminating {};
    std::atomic<uint32_t> Done {};
  };

  // Suspends each of Threads that the other side hasn't claimed yet
  void SuspendUnclaimed(TerminationSuspend& Request, const fextl::vector<HANDLE>& Threads) {
    for (size_t i = 0; i < Threads.size(); ++i) {
      uint8_t Expected = Unclaimed;
      if (Request.States[i].compare_exchange_strong(Expected, Claimed)) {
        // Only from Claimed: if this is the helper and the terminating thread has taken over, its result stays
        const uint8_t Result = Request.Suspend(Threads[i]) ? NotSuspended : Suspended;
        Expected = Claimed;
        Request.States[i].compare_exchange_strong(Expected, Result);
      }
    }
  }

  void WaitUntilStopped(TerminationSuspend& Request, const fextl::vector<HANDLE>& Threads) {
    for (size_t i = 0; i < Threads.size(); ++i) {
      if (Request.States[i].load() == Suspended) {
        CONTEXT Context;
        Context.ContextFlags = CONTEXT_CONTROL;
        NtGetContextThread(Threads[i], &Context);
      }
    }
  }

  void* SuspendForTermination(void* Arg) {
    auto& Request = *static_cast<TerminationSuspend*>(Arg);
    SuspendUnclaimed(Request, Request.Threads);
    WaitUntilStopped(Request, Request.Threads);

    // A suspend of the terminating thread that is still in effect now comes from a thread that has stopped and will be
    // killed, or from one FEX doesn't know. Take them all back: a later resume of a thread with no suspend does nothing.
    ULONG Count;
    if (!NtSuspendThread(Request.Terminating, nullptr)) {
      while (!NtResumeThread(Request.Terminating, &Count) && Count > 1) {
      }
    }
    // The terminating thread may free Request once Done is set. The wake only uses the address as a key.
    Request.Done.store(1);
    RtlWakeAddressAll(&Request.Done);
    return nullptr;
  }
} // namespace

// The terminating thread can't suspend the other threads itself: a program thread that suspends it, as a garbage
// collector does to stop the world, and that it suspends would leave both suspended for good. So a FEX thread suspends
// them and waits until they have stopped, while the terminating thread waits for it. That thread gets no
// DLL_THREAD_ATTACH and no debug events, but the program can still find it by enumerating threads and suspend it. Then
// it takes back any suspend of the terminating thread still in effect, which a thread that has stopped may hold.
// If it can't be created or hasn't finished within 5 s, the terminating thread suspends the remaining threads and waits
// for them itself, as it did before, and in the second case leaves the helper and the state it uses alone. A thread
// whose suspend the helper had started then gets a second one, so if the termination fails, it stays suspended once.
fextl::vector<HANDLE> SuspendThreadsForTermination(const fextl::vector<HANDLE>& Threads, NTSTATUS (*Suspend)(HANDLE)) {
  auto Request = fextl::make_unique<TerminationSuspend>(Threads, Suspend);
  bool Started {};
  bool Finished {};
  auto Helper = FEXCore::Threads::Thread::Create(SuspendForTermination, Request.get(), {.Internal = true}, "FEX termination");
  if (Helper && Helper->joinable()) {
    Started = true;
    // 5 s on the performance counter, in waits of at most 1 ms, as an alert can end a wait early
    LARGE_INTEGER Start, Now, Frequency;
    NtQueryPerformanceCounter(&Start, &Frequency);
    const uint32_t NotDone = 0;
    LARGE_INTEGER Timeout {.QuadPart = -10'000};
    while (!Request->Done.load()) {
      NtQueryPerformanceCounter(&Now, nullptr);
      if (Now.QuadPart - Start.QuadPart >= 5 * Frequency.QuadPart) {
        break;
      }
      RtlWaitOnAddress(&Request->Done, &NotDone, sizeof(NotDone), &Timeout);
    }
    Finished = Request->Done.load();
    // The helper's thread object stays allocated, as the helper still uses it while it exits, so that this thread
    // never waits for it
    Helper->detach();
    (void)Helper.release();
  }

  if (!Finished) {
    LogMan::Msg::EFmt("FEX: The termination helper thread didn't finish, suspending the remaining threads directly");
    for (size_t i = 0; i < Threads.size(); ++i) {
      uint8_t Expected = Claimed;
      if (Request->States[i].load() == Claimed && !Request->Suspend(Threads[i])) {
        Request->States[i].compare_exchange_strong(Expected, Suspended);
      }
    }
    SuspendUnclaimed(*Request, Threads);
    WaitUntilStopped(*Request, Threads);
  }

  fextl::vector<HANDLE> SuspendedThreads;
  for (size_t i = 0; i < Threads.size(); ++i) {
    if (Request->States[i].load() == Suspended) {
      SuspendedThreads.push_back(Threads[i]);
    }
  }
  if (Started && !Finished) {
    // The helper may still use it
    (void)Request.release();
  }
  return SuspendedThreads;
}
} // namespace FEX::Windows
