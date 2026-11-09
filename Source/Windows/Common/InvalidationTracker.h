// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Utils/IntervalList.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/fextl/map.h>
#include <FEXCore/fextl/vector.h>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <string_view>
#include <utility>

namespace FEXCore::Core {
struct InternalThreadState;
}

namespace FEXCore::Context {
class Context;
}

namespace FEX::Windows {
/**
 * @brief Handles SMC and regular code invalidation
 */
class InvalidationTracker {
public:
  InvalidationTracker(FEXCore::Context::Context& CTX, const std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*>& Threads);
  // CodeLockHeld is true when the caller holds the code invalidation mutex, see ProtectTakesCodeAway
  void HandleMemoryProtectionNotification(uint64_t Address, uint64_t Size, ULONG Prot, bool CodeLockHeld = false);
  void HandleProcessExecuteFlagsChange(ULONG Flags);
  void HandleImageMap(std::string_view Name, uint64_t Address);
  struct InvalidateContainingSectionResult {
    uint64_t SectionStart;
    uint64_t SectionSize;
  };
  InvalidateContainingSectionResult InvalidateContainingSection(uint64_t Address, bool Free);
  // Called after the syscall of every unmap of this process, with ThreadCreationMutex held since the call of
  // InvalidateContainingSection before it. Ends the range that call kept out of the intervals, if it found a section.
  void FinishSectionUnmap();
  void InvalidateAlignedInterval(uint64_t Address, uint64_t Size, bool Free, bool CodeLockHeld = false);
  // Called after a successful free syscall, with the range it reported
  void HandleMemoryFreeNotification(uint64_t Address, uint64_t Size, bool CodeLockHeld);

  // Whether a syscall giving the range the protection Prot takes code away, in which case the caller must hold the code
  // invalidation mutex from before the syscall until its intervals are updated after it. A compile reading a page that
  // goes away faults with that mutex held shared, in the middle of the decoder, and the intervals can't protect it: they
  // say what was executable when the compile asked. A compile running after the syscall but before the intervals are
  // updated would also protect a page that just became writable, see ProtectRWXIntervalsInternal. Called with
  // ThreadCreationMutex held, before the syscall, so with the arguments the syscall got, not the range it will use.
  bool ProtectTakesCodeAway(uint64_t Address, uint64_t Size, ULONG Prot);
  // The same for an allocation syscall: a commit over existing memory sets the protection like a protect does
  bool AllocTakesCodeAway(uint64_t Address, uint64_t Size, ULONG Type, ULONG Prot);
  // The same for a free syscall, which takes code away where the range, or the allocation for a size of 0, is in the
  // intervals or has a committed page that is executable, or will be once its guard is used up. Otherwise a compile only
  // reads the range once a protect or commit has made it executable, and those of this process wait for
  // ThreadCreationMutex, which stays held across the syscall. Those of another process don't, as for a protect.
  bool FreeTakesCodeAway(uint64_t Address, uint64_t Size);

  // Code is only compiled from executable intervals and is invalidated when its interval stops being executable, so a
  // write to memory this returns false for can't affect any code.
  bool OverlapsExecutableInterval(uint64_t Address, uint64_t Size);
  void ReprotectRWXIntervals(uint64_t Address, uint64_t Size);
  bool HandleRWXAccessViolation(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPC, uint64_t FaultAddress);

  // Invalidates code in the input interval and unprotects any RWX intervals in it, which code compiled from it then
  // leaves writable until EndUntrackedWrite. If false is returned there was nothing to unprotect and no write to end.
  bool BeginUntrackedWrite(uint64_t Address, uint64_t Size);
  // Invalidates code compiled from the interval during the write, which left its pages writable.
  void EndUntrackedWrite(uint64_t Address, uint64_t Size);

  FEXCore::HLE::ExecutableRangeInfo QueryExecutableRange(uint64_t Address);

  // What to do about the execute fault of a block that couldn't decode an instruction:
  enum class FetchFault {
    Raise,     // Raise it as it is
    GuardPage, // Raise the guard page's exception instead
    Retry,     // Run the instruction again
  };
  // The fault a thread last ran again, see HandleFetchFault
  struct FetchRetry {
    uint64_t Address {};
    uint64_t Generation {};
    bool operator==(const FetchRetry&) const = default;
  };
  // Address is the first byte the instruction couldn't fetch. A guard page there has its guard used up, as the fault would
  // have on hardware. On a page that is executable now the instruction runs again, unless the thread last ran the same
  // fault again and no compile stopped at the page since. LastRetry is per thread. Called with ThreadCreationMutex held,
  // in a state where the hooks are not called for FEX's syscalls.
  FetchFault HandleFetchFault(uint64_t Address, FetchRetry& LastRetry);

private:
  // NOTE: These assume IntervalsLock is held: for writing, by the first two.
  void AddExecutableInterval(FEXCore::IntervalList<uint64_t>::Interval ProtInterval, ULONG Prot);
  bool TrackExecutableMapping(uint64_t Address);
  FEXCore::HLE::ExecutableRangeInfo QueryExecutableRangeLocked(uint64_t Address);
  bool ProtIsEffectivelyExecutable(ULONG Prot) const;
  void ForgetFetchFaultPages(uint64_t Begin, uint64_t End);

  void DetectMonoBackpatcherBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPC);
  void DisableSMCDetection();
  void InvalidateIntervalInternal(uint64_t Address, uint64_t Size, bool CodeLockHeld = false);
  // NOTE: This assumed CodeInvalidationMutex is locked by the caller
  void InvalidateIntervalInternalLocked(uint64_t Address, uint64_t Size);

  // NOTE: If ForWriteLocked is true then this assumes CodeInvalidationMutex is locked by the caller,
  // and any code in the range will be invalidated before protection as RWX, otherwise protects as RX if false.
  bool ProtectRWXIntervalsInternal(uint64_t Address, uint64_t Size, bool ForWriteLocked);

  // Returns the correct protection for trapping (removing write) or untrapping (restoring write) an RWX interval.
  // For DEP-promoted regions (originally non-exec), uses PAGE_READONLY/PAGE_READWRITE instead of PAGE_EXECUTE_READ/PAGE_EXECUTE_READWRITE.
  // NOTE: Must be called with IntervalsLock held.
  ULONG GetTrapProt(uint64_t Address) const;
  ULONG GetUntrapProt(uint64_t Address) const;

  FEXCore::IntervalList<uint64_t> XIntervals;
  FEXCore::IntervalList<uint64_t> RWXIntervals;
  std::shared_mutex IntervalsLock;
  FEXCore::Context::Context& CTX;
  const std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*>& Threads;
  bool SMCDetectionDisabled {false};                    // Protected by IntervalsLock
  bool DEPDisabled {false};                             // Protected by IntervalsLock
  FEXCore::IntervalList<uint64_t> DEPPromotedIntervals; // Protected by IntervalsLock
  // Page aligned [begin, end) of each untracked write in progress, protected by IntervalsLock
  fextl::vector<std::pair<uint64_t, uint64_t>> UntrackedWrites;
  // [begin, end) of the section between its InvalidateContainingSection and FinishSectionUnmap, and whether a compile
  // asked about it meanwhile, protected by IntervalsLock
  std::pair<uint64_t, uint64_t> UnmappingSection {};
  bool UnmappingSectionMissed {false};
  // The pages a compile found not executable, which its block raises a fetch fault for: not committed, not executable or
  // a guard page. Each has a number that the last such compile took from FetchFaultGeneration. Protected by
  // IntervalsLock, see TrackExecutableMapping and HandleFetchFault.
  fextl::map<uint64_t, uint64_t> FetchFaultPages;
  uint64_t FetchFaultGeneration {};

  bool MonoBackpatcherDetectionPending {false};
  uint64_t MonoBase {0};
  uint64_t MonoEnd {0};
};
} // namespace FEX::Windows
