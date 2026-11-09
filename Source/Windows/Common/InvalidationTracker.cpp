// SPDX-License-Identifier: MIT

#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Config/Config.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include "InvalidationTracker.h"
#include <algorithm>
#include <windef.h>
#include <winternl.h>

namespace FEX::Windows {
InvalidationTracker::InvalidationTracker(FEXCore::Context::Context& CTX, const std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*>& Threads)
  : CTX {CTX}
  , Threads {Threads} {
  FEX_CONFIG_OPT(SMCChecks, SMCCHECKS);
  SMCDetectionDisabled = (SMCChecks == FEXCore::Config::CONFIG_SMC_NONE);

  MEMORY_BASIC_INFORMATION Info;
  uint64_t Address = 0;

  while (VirtualQuery(reinterpret_cast<LPCVOID>(Address), &Info, sizeof(Info))) {
    uint64_t BaseAddress = reinterpret_cast<uint64_t>(Info.BaseAddress);
    if (Info.State == MEM_COMMIT) {
      HandleMemoryProtectionNotification(BaseAddress, Info.RegionSize, Info.Protect);
    }

    Address = BaseAddress + Info.RegionSize;
  }
}

static bool ProtHasExec(ULONG Prot) {
  return (Prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

static bool ProtIsReadable(ULONG Prot) {
  return (Prot & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                  PAGE_EXECUTE_WRITECOPY)) != 0;
}

static bool ProtIsWritable(ULONG Prot) {
  return (Prot & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

bool InvalidationTracker::ProtIsEffectivelyExecutable(ULONG Prot) const {
  // A read of a guard page uses up the guard and raises its exception in the reader, so the decoder must never get there:
  // Wine would dispatch the exception from inside the compile. Code on a guard page compiles to a block that raises the
  // fault, which HandleFetchFault makes the guard's own exception.
  return !(Prot & PAGE_GUARD) && (ProtHasExec(Prot) || (DEPDisabled && ProtIsReadable(Prot)));
}

void InvalidationTracker::AddExecutableInterval(FEXCore::IntervalList<uint64_t>::Interval ProtInterval, ULONG Prot) {
  XIntervals.Insert(ProtInterval);
  // A range made executable and read-only stays in RWXIntervals, so a write to it is still taken for SMC and made
  // writable. While FEX traps writes to a range, VirtualProtect and VirtualQuery report PAGE_EXECUTE_READ for it, so
  // a guest that saved that protection and restores it after patching still expects the range to be writable.
  if (ProtIsWritable(Prot)) {
    LogMan::Msg::DFmt("Add SMC interval: {:X} - {:X}", ProtInterval.Offset, ProtInterval.End);
    RWXIntervals.Insert(ProtInterval);
  }
  if (DEPDisabled) {
    if (ProtHasExec(Prot)) {
      DEPPromotedIntervals.Remove(ProtInterval);
    } else {
      DEPPromotedIntervals.Insert(ProtInterval);
    }
  }
}

void InvalidationTracker::HandleMemoryProtectionNotification(uint64_t Address, uint64_t Size, ULONG Prot, bool CodeLockHeld) {
  const auto AlignedBase = Address & FEXCore::Utils::FEX_PAGE_MASK;
  const auto AlignedSize = (Address - AlignedBase + Size + FEXCore::Utils::FEX_PAGE_SIZE - 1) & FEXCore::Utils::FEX_PAGE_MASK;

  const bool NeedsInvalidate = [&]() {
    std::unique_lock Lock(IntervalsLock);

    FEXCore::IntervalList<uint64_t>::Interval ProtInterval {AlignedBase, AlignedBase + AlignedSize};

    if (ProtIsEffectivelyExecutable(Prot)) {
      AddExecutableInterval(ProtInterval, Prot);
      return true;
    } else if (XIntervals.Intersect(ProtInterval)) {
      XIntervals.Remove(ProtInterval);
      RWXIntervals.Remove(ProtInterval);
      if (DEPDisabled) {
        DEPPromotedIntervals.Remove(ProtInterval);
      }
      return true;
    }

    return false;
  }();

  if (NeedsInvalidate) {
    // IntervalsLock cannot be held during invalidation
    InvalidateIntervalInternal(AlignedBase, AlignedSize, CodeLockHeld);
  }
}

bool InvalidationTracker::ProtectTakesCodeAway(uint64_t Address, uint64_t Size, ULONG Prot) {
  const auto AlignedBase = Address & FEXCore::Utils::FEX_PAGE_MASK;
  const auto AlignedEnd = (Address + Size + FEXCore::Utils::FEX_PAGE_SIZE - 1) & FEXCore::Utils::FEX_PAGE_MASK;
  if (AlignedEnd <= AlignedBase) {
    return false;
  }

  std::shared_lock Lock(IntervalsLock);
  if (ProtIsEffectivelyExecutable(Prot)) {
    return false;
  }
  if (XIntervals.Intersect({AlignedBase, AlignedEnd})) {
    return true;
  }

  // A page that isn't in the intervals can be there any moment: TrackExecutableMapping adds it in a compile, without
  // ThreadCreationMutex. So this asks for what such a compile would see, or would see once any access, of another thread
  // too, used up the guard of the page, which takes no notification.
  uint64_t Base = AlignedBase;
  while (Base < AlignedEnd) {
    MEMORY_BASIC_INFORMATION Info;
    if (NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(Base), MemoryBasicInformation, &Info, sizeof(Info), nullptr)) {
      break;
    }
    if (Info.State == MEM_COMMIT && ProtIsEffectivelyExecutable(Info.Protect & ~PAGE_GUARD)) {
      return true;
    }
    Base = reinterpret_cast<uint64_t>(Info.BaseAddress) + Info.RegionSize;
  }
  return false;
}

bool InvalidationTracker::AllocTakesCodeAway(uint64_t Address, uint64_t Size, ULONG Type, ULONG Prot) {
  // A reservation can only succeed on free memory, and MEM_RESET(_UNDO) leaves the protection alone.
  return Address && (Type & MEM_COMMIT) && !(Type & (MEM_RESERVE | MEM_RESET | MEM_RESET_UNDO)) && ProtectTakesCodeAway(Address, Size, Prot);
}

bool InvalidationTracker::FreeTakesCodeAway(uint64_t Address, uint64_t Size) {
  const auto AlignedBase = Address & FEXCore::Utils::FEX_PAGE_MASK;
  const auto AlignedEnd = (Address + Size + FEXCore::Utils::FEX_PAGE_SIZE - 1) & FEXCore::Utils::FEX_PAGE_MASK;
  if (!AlignedBase || (Size && AlignedEnd <= AlignedBase)) {
    return true;
  }

  if (Size && OverlapsExecutableInterval(AlignedBase, AlignedEnd - AlignedBase)) {
    return true;
  }

  // Without a size, a release or decommit covers the whole allocation from its base, which ends where the regions of
  // another allocation or free memory start. As for a protect, a page that is executable, or will be once its guard is
  // used up, can enter the intervals in a compile any moment, see ProtectTakesCodeAway. IntervalsLock isn't held across
  // the walk, so a compile that misses the intervals doesn't wait for it in QueryExecutableRange. A page that compile
  // adds is one the walk counts as executable. Apart from a guard being used up, only a protect, commit or DEP change
  // makes a page of an allocation executable, as no view can be mapped into one, and those of this process wait for
  // ThreadCreationMutex, which the caller holds. That also keeps DEPDisabled as it is.
  uint64_t Base = AlignedBase;
  void* AllocationBase {};
  while (!Size || Base < AlignedEnd) {
    MEMORY_BASIC_INFORMATION Info;
    if (NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(Base), MemoryBasicInformation, &Info, sizeof(Info), nullptr)) {
      break;
    }
    if (!Size) {
      if (Base == AlignedBase) {
        AllocationBase = Info.AllocationBase;
      }
      if (Info.State == MEM_FREE || Info.AllocationBase != AllocationBase) {
        break;
      }
    }
    if (Info.State == MEM_COMMIT && ProtIsEffectivelyExecutable(Info.Protect & ~PAGE_GUARD)) {
      return true;
    }
    Base = reinterpret_cast<uint64_t>(Info.BaseAddress) + Info.RegionSize;
  }

  return !Size && Base > AlignedBase && OverlapsExecutableInterval(AlignedBase, Base - AlignedBase);
}

void InvalidationTracker::HandleProcessExecuteFlagsChange(ULONG Flags) {
  const bool DisableDEP = (Flags & MEM_EXECUTE_OPTION_ENABLE) != 0;

  std::scoped_lock CodeLock(CTX.GetCodeInvalidationMutex());
  std::unique_lock Lock(IntervalsLock);

  if (DisableDEP == DEPDisabled) {
    return;
  }

  DEPDisabled = DisableDEP;

  if (DisableDEP) {
    DEPPromotedIntervals.Clear();

    MEMORY_BASIC_INFORMATION Info;
    uint64_t Address = 0;

    while (VirtualQuery(reinterpret_cast<LPCVOID>(Address), &Info, sizeof(Info))) {
      uint64_t BaseAddress = reinterpret_cast<uint64_t>(Info.BaseAddress);
      if (Info.State == MEM_COMMIT && ProtIsEffectivelyExecutable(Info.Protect) && !ProtHasExec(Info.Protect)) {
        const auto AlignedBase = BaseAddress & FEXCore::Utils::FEX_PAGE_MASK;
        const auto AlignedSize = (BaseAddress - AlignedBase + Info.RegionSize + FEXCore::Utils::FEX_PAGE_SIZE - 1) & FEXCore::Utils::FEX_PAGE_MASK;
        FEXCore::IntervalList<uint64_t>::Interval ProtInterval {AlignedBase, AlignedBase + AlignedSize};

        XIntervals.Insert(ProtInterval);
        if (ProtIsWritable(Info.Protect)) {
          RWXIntervals.Insert(ProtInterval);
        }
        DEPPromotedIntervals.Insert(ProtInterval);
      }

      Address = BaseAddress + Info.RegionSize;
    }
  } else {
    for (const auto& Interval : DEPPromotedIntervals) {
      XIntervals.Remove(Interval);
      RWXIntervals.Remove(Interval);
    }
    DEPPromotedIntervals.Clear();
  }

  // Invalidate all cached code: previously-compiled blocks may contain NoExec stubs for addresses
  // that are now executable (or reference regions whose executability just changed).
  InvalidateIntervalInternalLocked(0, std::numeric_limits<uint64_t>::max());
}

void InvalidationTracker::HandleImageMap(std::string_view Name, uint64_t Address) {
  auto* Nt = RtlImageNtHeader(reinterpret_cast<HMODULE>(Address));
  auto* SectionsBegin = IMAGE_FIRST_SECTION(Nt);
  auto* SectionsEnd = SectionsBegin + Nt->FileHeader.NumberOfSections;
  uint64_t LastExecutableSectionEnd = 0;
  // For an image with at least page-sized section alignment, Wine protects each section up to its size rounded
  // to the section alignment, so code past VirtualSize in that last part runs too. SectionAlignment is at the
  // same offset for PE32 and PE32+.
  const uint64_t SectionAlignment = std::max<uint64_t>(Nt->OptionalHeader.SectionAlignment, FEXCore::Utils::FEX_PAGE_SIZE);

  for (auto* Section = SectionsBegin; Section != SectionsEnd; Section++) {
    if (Section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
      std::unique_lock Lock(IntervalsLock);

      const uint64_t SectionSize = Section->Misc.VirtualSize ? Section->Misc.VirtualSize : Section->SizeOfRawData;
      uint64_t SectionBase = Address + Section->VirtualAddress;
      uint64_t SectionEnd = Address + FEXCore::AlignUp(Section->VirtualAddress + SectionSize, SectionAlignment);
      XIntervals.Insert({SectionBase, SectionEnd});
      LastExecutableSectionEnd = std::max(LastExecutableSectionEnd, SectionEnd);
      if (Section->Characteristics & IMAGE_SCN_MEM_WRITE) {
        LogMan::Msg::DFmt("Add image SMC interval: {:X} - {:X}", SectionBase, SectionEnd);
        RWXIntervals.Insert({SectionBase, SectionEnd});
      }
    }
  }

  FEX_CONFIG_OPT(MonoHacks, MONOHACKS);
  if (MonoHacks && (Name == "mono-2.0-bdwgc.dll" || Name == "mono.dll")) {
    FEX_CONFIG_OPT(MaxInst, MAXINST);
    FEX_CONFIG_OPT(Multiblock, MULTIBLOCK);
    if (Multiblock && MaxInst() >= 500) {
      // Require these settings to ensure we can safely hook all SMC sites in a single block
      CTX.MarkMonoDetected();
      MonoBackpatcherDetectionPending = true;
      MonoBase = Address;
      MonoEnd = LastExecutableSectionEnd;
    } else {
      LogMan::Msg::IFmt("Not applying mono hacks, Multiblock with MaxInst >= 500 required");
    }
  }
}

InvalidationTracker::InvalidateContainingSectionResult InvalidationTracker::InvalidateContainingSection(uint64_t Address, bool Free) {
  MEMORY_BASIC_INFORMATION Info;
  if (NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(Address), MemoryBasicInformation, &Info, sizeof(Info), nullptr)) {
    return {Address, 0};
  }

  // Only a view of a section can be unmapped. For free memory (type 0) or a private allocation the unmap fails, and
  // the allocation, which may hold live code, must stay tracked.
  if (Info.Type != MEM_IMAGE && Info.Type != MEM_MAPPED) {
    return {Address, 0};
  }

  const auto SectionBase = reinterpret_cast<uint64_t>(Info.AllocationBase);
  auto SectionSize = reinterpret_cast<uint64_t>(Info.BaseAddress) + Info.RegionSize - SectionBase;

  while (!NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(SectionBase + SectionSize), MemoryBasicInformation, &Info,
                               sizeof(Info), nullptr) &&
         reinterpret_cast<uint64_t>(Info.AllocationBase) == SectionBase) {
    SectionSize += Info.RegionSize;
  }

  // Removed before invalidating, so no code compiled from the range outlives it
  if (Free) {
    std::unique_lock Lock(IntervalsLock);
    XIntervals.Remove({SectionBase, SectionBase + SectionSize});
    RWXIntervals.Remove({SectionBase, SectionBase + SectionSize});
    ForgetFetchFaultPages(SectionBase, SectionBase + SectionSize);
    UnmappingSection = {SectionBase, SectionBase + SectionSize};
  }

  InvalidateIntervalInternal(SectionBase, SectionSize);

  return {SectionBase, SectionSize};
}

void InvalidationTracker::FinishSectionUnmap() {
  const auto [Section, Missed] = [&] {
    std::unique_lock Lock(IntervalsLock);
    return std::pair {std::exchange(UnmappingSection, {}), std::exchange(UnmappingSectionMissed, false)};
  }();

  // What a compile made of the section while it was going away, see TrackExecutableMapping
  if (Missed) {
    InvalidateIntervalInternal(Section.first, Section.second - Section.first);
  }
}

void InvalidationTracker::InvalidateAlignedInterval(uint64_t Address, uint64_t Size, bool Free, bool CodeLockHeld) {
  if (!Address) {
    // Match the Windows behaviour when passed a NULL base address.
    Size = std::numeric_limits<uint64_t>::max();
  }

  const auto AlignedBase = Address & FEXCore::Utils::FEX_PAGE_MASK;
  const auto AlignedSize = std::max(Size, (Address - AlignedBase + Size + FEXCore::Utils::FEX_PAGE_SIZE - 1) & FEXCore::Utils::FEX_PAGE_MASK);

  // Removed before invalidating, so no code compiled from the range outlives it
  if (Free) {
    std::unique_lock Lock(IntervalsLock);
    // Code is only compiled from the intervals and is invalidated when it leaves them. A block that stopped at a page
    // outside of them raises a fetch fault, and TrackExecutableMapping put that page in FetchFaultPages, or the block goes
    // in FinishSectionUnmap. So a free outside of both has no block to invalidate.
    if (!XIntervals.Intersect({AlignedBase, AlignedBase + AlignedSize}) &&
        FetchFaultPages.lower_bound(AlignedBase) == FetchFaultPages.lower_bound(AlignedBase + AlignedSize)) {
      return;
    }
    XIntervals.Remove({AlignedBase, AlignedBase + AlignedSize});
    RWXIntervals.Remove({AlignedBase, AlignedBase + AlignedSize});
    ForgetFetchFaultPages(AlignedBase, AlignedBase + AlignedSize);
  }

  InvalidateIntervalInternal(AlignedBase, AlignedSize, CodeLockHeld);
}

void InvalidationTracker::HandleMemoryFreeNotification(uint64_t Address, uint64_t Size, bool CodeLockHeld) {
  // A release reports what it freed, but Wine reports no size for a decommit without one, which decommits the whole
  // allocation from its base. The allocation is still reserved, so its regions are walked to its end.
  if (Address && !Size) {
    MEMORY_BASIC_INFORMATION Info;
    uint64_t End = Address;
    while (!NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(End), MemoryBasicInformation, &Info, sizeof(Info), nullptr) &&
           Info.State != MEM_FREE && reinterpret_cast<uint64_t>(Info.AllocationBase) == Address) {
      End = reinterpret_cast<uint64_t>(Info.BaseAddress) + Info.RegionSize;
    }
    Size = End - Address;
  }

  InvalidateAlignedInterval(Address, Size, true, CodeLockHeld);
}

bool InvalidationTracker::OverlapsExecutableInterval(uint64_t Address, uint64_t Size) {
  const auto AlignedBase = Address & FEXCore::Utils::FEX_PAGE_MASK;
  const auto AlignedEnd = (Address + Size + FEXCore::Utils::FEX_PAGE_SIZE - 1) & FEXCore::Utils::FEX_PAGE_MASK;

  std::shared_lock Lock(IntervalsLock);
  return XIntervals.Intersect({AlignedBase, AlignedEnd});
}

void InvalidationTracker::ReprotectRWXIntervals(uint64_t Address, uint64_t Size) {
  ProtectRWXIntervalsInternal(Address, Size, false);
}

bool InvalidationTracker::HandleRWXAccessViolation(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPc, uint64_t FaultAddress) {
  const auto [NeedsInvalidate, UntrapProt] = [&](uint64_t Address) -> std::pair<bool, ULONG> {
    std::shared_lock Lock(IntervalsLock);
    if (!RWXIntervals.Query(Address).Enclosed) {
      return {false, 0};
    }
    return {true, GetUntrapProt(Address)};
  }(FaultAddress);

  if (NeedsInvalidate) {
    // A page that can't be read isn't one FEX trapped, whatever the intervals say. The faulting thread may be a compile
    // holding the code invalidation mutex shared, so it must not go on to wait for it exclusively. A writable page is
    // fine: another thread racing on the same page may have untrapped it already.
    MEMORY_BASIC_INFORMATION Info;
    if (NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(FaultAddress), MemoryBasicInformation, &Info, sizeof(Info), nullptr) ||
        Info.State != MEM_COMMIT || !ProtIsReadable(Info.Protect) || (Info.Protect & PAGE_GUARD)) {
      return false;
    }

    // IntervalsLock cannot be held during invalidation
    {
      std::scoped_lock Lock(CTX.GetCodeInvalidationMutex());

      InvalidateIntervalInternalLocked(FaultAddress & FEXCore::Utils::FEX_PAGE_MASK, FEXCore::Utils::FEX_PAGE_SIZE);

      // Invalidate, then unprotect the faulting page with the compilation lock held to ensure that any racing invalidations are not dropped.
      const auto Untrap = [FaultAddress](ULONG Prot) {
        ULONG TmpProt;
        void* TmpAddress = reinterpret_cast<void*>(FaultAddress);
        SIZE_T TmpSize = 1;
        return NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess(), &TmpAddress, &TmpSize, Prot, &TmpProt));
      };
      // Wine refuses the writable protections on a copy-on-write view of a section. A write that can't go through
      // either way is the guest's access violation, not one to retry.
      if (!Untrap(UntrapProt) && !Untrap(UntrapProt == PAGE_READWRITE ? PAGE_WRITECOPY : PAGE_EXECUTE_WRITECOPY)) {
        return false;
      }
    }
    DetectMonoBackpatcherBlock(Thread, HostPc);
    return true;
  }
  return false;
}

bool InvalidationTracker::BeginUntrackedWrite(uint64_t Address, uint64_t Size) {
  const auto AlignedBase = Address & FEXCore::Utils::FEX_PAGE_MASK;
  const auto AlignedEnd = (Address + Size + FEXCore::Utils::FEX_PAGE_SIZE - 1) & FEXCore::Utils::FEX_PAGE_MASK;

  // Held exclusively, so no code is compiled from the range, which would protect it again, before it is registered
  std::scoped_lock CodeLock(CTX.GetCodeInvalidationMutex());
  if (!ProtectRWXIntervalsInternal(AlignedBase, AlignedEnd - AlignedBase, true)) {
    return false;
  }

  std::unique_lock Lock(IntervalsLock);
  UntrackedWrites.emplace_back(AlignedBase, AlignedEnd);
  return true;
}

void InvalidationTracker::EndUntrackedWrite(uint64_t Address, uint64_t Size) {
  const auto AlignedBase = Address & FEXCore::Utils::FEX_PAGE_MASK;
  const auto AlignedEnd = (Address + Size + FEXCore::Utils::FEX_PAGE_SIZE - 1) & FEXCore::Utils::FEX_PAGE_MASK;

  std::scoped_lock CodeLock(CTX.GetCodeInvalidationMutex());
  {
    std::unique_lock Lock(IntervalsLock);
    const auto It = std::ranges::find(UntrackedWrites, std::pair {AlignedBase, AlignedEnd});
    if (It != UntrackedWrites.end()) {
      UntrackedWrites.erase(It);
    }
  }
  // Compiling it again protects the pages
  InvalidateIntervalInternalLocked(AlignedBase, AlignedEnd - AlignedBase);
}

bool InvalidationTracker::TrackExecutableMapping(uint64_t Address) {
  // The section is still mapped, up to its unmap syscall, but whatever is added for it now would outlive it
  if (Address >= UnmappingSection.first && Address < UnmappingSection.second) {
    UnmappingSectionMissed = true;
    return false;
  }

  MEMORY_BASIC_INFORMATION Info;
  if (NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(Address), MemoryBasicInformation, &Info, sizeof(Info), nullptr)) {
    return false;
  }

  // The compile stops before the page, and a block that starts there raises a fetch fault. A new generation tells it
  // from the blocks of earlier compiles in HandleFetchFault, and keeps a free of the page from skipping the
  // invalidation, see InvalidateAlignedInterval.
  if (Info.State != MEM_COMMIT || !ProtIsEffectivelyExecutable(Info.Protect)) {
    FetchFaultPages[Address & FEXCore::Utils::FEX_PAGE_MASK] = ++FetchFaultGeneration;
    return false;
  }

  const auto Base = reinterpret_cast<uint64_t>(Info.BaseAddress);
  AddExecutableInterval({Base, Base + Info.RegionSize}, Info.Protect);
  return true;
}

void InvalidationTracker::ForgetFetchFaultPages(uint64_t Begin, uint64_t End) {
  FetchFaultPages.erase(FetchFaultPages.lower_bound(Begin), FetchFaultPages.lower_bound(End));
}

InvalidationTracker::FetchFault InvalidationTracker::HandleFetchFault(uint64_t Address, FetchRetry& LastRetry) {
  const auto Page = Address & FEXCore::Utils::FEX_PAGE_MASK;

  MEMORY_BASIC_INFORMATION Info;
  if (NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(Page), MemoryBasicInformation, &Info, sizeof(Info), nullptr) ||
      Info.State != MEM_COMMIT) {
    LastRetry = {};
    return FetchFault::Raise;
  }

  // The block that raised the fault goes in the notifications below. It has this page among its code pages even when it
  // starts on the page before, as the decoder adds the page of the longest instruction it could find there.
  if (Info.Protect & PAGE_GUARD) {
    const ULONG Prot = Info.Protect & ~PAGE_GUARD;
    void* TmpAddress = reinterpret_cast<void*>(Page);
    SIZE_T TmpSize = FEXCore::Utils::FEX_PAGE_SIZE;
    ULONG TmpProt;
    if (!NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess(), &TmpAddress, &TmpSize, Prot, &TmpProt))) {
      return FetchFault::Raise;
    }

    HandleMemoryProtectionNotification(Page, FEXCore::Utils::FEX_PAGE_SIZE, Prot);
    return FetchFault::GuardPage;
  }

  // A block compiled while its page wasn't executable raises the fault until something drops it, and a page can become
  // executable without a notification: nothing notifies when a guard goes to a data read or to another thread's fetch,
  // a view of a section that isn't an image is executable from its map syscall on, and an image mapped outside of the
  // loader isn't announced. So a fault on a page that is executable now runs the instruction again, after the
  // notification below has dropped the blocks of the page. The generation says which compile last stopped at the page,
  // see TrackExecutableMapping. The instruction runs again unless this is the fault the thread last ran again, at the
  // same generation. Then no compile stopped at the page since, so the fault is real, as with an instruction over the
  // length limit, and is raised. Only the last fault is kept, so faults that take turns in a thread each run again
  // before their raise. A raise for a page that isn't committed or executable forgets it, so the next fault that finds
  // its page executable runs again.
  const auto [Executable, Generation] = [&]() -> std::pair<bool, uint64_t> {
    std::shared_lock Lock(IntervalsLock);
    const auto It = FetchFaultPages.find(Page);
    return {ProtIsEffectivelyExecutable(Info.Protect), It != FetchFaultPages.end() ? It->second : 0};
  }();

  if (!Executable) {
    LastRetry = {};
    return FetchFault::Raise;
  }

  const FetchRetry Retry {Address, Generation};
  if (LastRetry == Retry) {
    return FetchFault::Raise;
  }

  LastRetry = Retry;
  HandleMemoryProtectionNotification(Page, FEXCore::Utils::FEX_PAGE_SIZE, Info.Protect);
  return FetchFault::Retry;
}

FEXCore::HLE::ExecutableRangeInfo InvalidationTracker::QueryExecutableRange(uint64_t Address) {
  {
    std::shared_lock Lock(IntervalsLock);
    if (XIntervals.Query(Address).Enclosed) {
      return QueryExecutableRangeLocked(Address);
    }
  }

  // Only memory whose protection a syscall set is known here: a view of a section that isn't an image, such as the code
  // of an assembly in a .NET single-file bundle, is executable from its map syscall on, without any notification. This
  // only runs in a compile, when the decoder gets to memory outside the intervals. An entry point that isn't executable
  // compiles to a block that raises the fault, which stays cached, while a branch target there is asked about again by
  // each compile that reaches it. The lock is held across the query, so a change of protection or a release that
  // notifies after its syscall can't be overwritten by what the query saw before it. ThreadCreationMutex can't be taken
  // for that. The locks go in the order ThreadCreationMutex, code invalidation mutex, IntervalsLock, and a compile holds
  // the code invalidation mutex here. A free, protect or commit that takes code away holds that mutex from before its
  // syscall on, see ProtectTakesCodeAway, so no compile gets here during one. An unmap doesn't, as UnmappingSection
  // already keeps what a compile finds here out of the intervals, see TrackExecutableMapping.
  std::unique_lock Lock(IntervalsLock);
  if (!XIntervals.Query(Address).Enclosed && !TrackExecutableMapping(Address)) {
    return {};
  }
  return QueryExecutableRangeLocked(Address);
}

FEXCore::HLE::ExecutableRangeInfo InvalidationTracker::QueryExecutableRangeLocked(uint64_t Address) {
  const auto XResult = XIntervals.Query(Address);
  const auto RWXResult = RWXIntervals.Query(Address);
  if (RWXResult.Enclosed) {
    return {RWXResult.Interval.Offset, RWXResult.Interval.End - RWXResult.Interval.Offset, true};
  } else if (RWXResult.Size && RWXResult.Size < XResult.Size) {
    return {XResult.Interval.Offset, RWXResult.Interval.Offset - XResult.Interval.Offset, false};
  }
  return {XResult.Interval.Offset, XResult.Interval.End - XResult.Interval.Offset, false};
}

void InvalidationTracker::DetectMonoBackpatcherBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPc) {
  if (!MonoBackpatcherDetectionPending) {
    return;
  }

  if (!CTX.IsAddressInCodeBuffer(Thread, HostPc)) {
    return;
  }

  uint64_t RIP = CTX.RestoreRIPFromHostPC(Thread, HostPc);
  if (!RIP || RIP < MonoBase || RIP >= MonoEnd) {
    return;
  }

  static constexpr uint8_t XChgOp = 0x87;
  if (*reinterpret_cast<uint8_t*>(RIP) != XChgOp && *reinterpret_cast<uint8_t*>(RIP + 1) != XChgOp) {
    return;
  }

  uint64_t BlockEntry = CTX.GetGuestBlockEntry(Thread);
  LogMan::Msg::DFmt("Detected mono backpatcher at: {:X}", BlockEntry);
  DisableSMCDetection();
  {
    std::scoped_lock CodeLock(CTX.GetCodeInvalidationMutex());
    CTX.MarkMonoBackpatcherBlock(BlockEntry);
  }
  InvalidateAlignedInterval(BlockEntry, FEXCore::Utils::FEX_PAGE_SIZE, false);
}

void InvalidationTracker::DisableSMCDetection() {
  std::unique_lock Lock(IntervalsLock);
  SMCDetectionDisabled = true;
  uint64_t Address = 0;

  // Reprotect all RWX intervals as writable
  FEXCore::IntervalList<uint64_t>::QueryResult Query;
  do {
    Query = RWXIntervals.Query(Address);
    if (Query.Enclosed) {
      void* TmpAddress = reinterpret_cast<void*>(Address);
      SIZE_T TmpSize = static_cast<SIZE_T>(Query.Size);
      ULONG TmpProt;
      NtProtectVirtualMemory(NtCurrentProcess(), &TmpAddress, &TmpSize, GetUntrapProt(Address), &TmpProt);
    }
    Address += Query.Size;
  } while (Query.Size);
}

ULONG InvalidationTracker::GetTrapProt(uint64_t Address) const {
  if (DEPDisabled && DEPPromotedIntervals.Query(Address).Enclosed) {
    return PAGE_READONLY;
  }
  return PAGE_EXECUTE_READ;
}

ULONG InvalidationTracker::GetUntrapProt(uint64_t Address) const {
  if (DEPDisabled && DEPPromotedIntervals.Query(Address).Enclosed) {
    return PAGE_READWRITE;
  }
  return PAGE_EXECUTE_READWRITE;
}

void InvalidationTracker::InvalidateIntervalInternal(uint64_t Address, uint64_t Size, bool CodeLockHeld) {
  if (CodeLockHeld) {
    InvalidateIntervalInternalLocked(Address, Size);
    return;
  }

  std::scoped_lock CodeLock(CTX.GetCodeInvalidationMutex());
  InvalidateIntervalInternalLocked(Address, Size);
}

void InvalidationTracker::InvalidateIntervalInternalLocked(uint64_t Address, uint64_t Size) {
  // NOTE: This assumes CodeInvalidationMutex is locked by the caller
  CTX.InvalidateCodeBuffersCodeRange(Address, Size);
  for (auto Thread : Threads) {
    CTX.InvalidateThreadCachedCodeRange(Thread.second, Address, Size);
  }
}

bool InvalidationTracker::ProtectRWXIntervalsInternal(uint64_t Address, uint64_t Size, bool ForWriteLocked) {
  const auto End = Address + Size;
  std::shared_lock Lock(IntervalsLock);

  if (SMCDetectionDisabled) {
    return false;
  }

  bool HitRWXInterval = false;
  do {
    const auto Query = RWXIntervals.Query(Address);
    if (Query.Enclosed) {
      if (!HitRWXInterval) {
        if (ForWriteLocked) {
          // If we are protecting as writable, then the entire range must be invalidated before any protections are
          // applied and the invalidation mutex must be locked throughout.
          // Do this lazily only when an RWX region is actually hit.
          // NOTE: This assumes CodeInvalidationMutex is locked by the caller
          InvalidateIntervalInternalLocked(Address, Size);
        }
        HitRWXInterval = true;
      }
      const auto Protect = [&](uint64_t ProtectBase, uint64_t ProtectEnd) {
        void* TmpAddress = reinterpret_cast<void*>(ProtectBase);
        SIZE_T TmpSize = static_cast<SIZE_T>(ProtectEnd - ProtectBase);
        ULONG TmpProt;
        NtProtectVirtualMemory(NtCurrentProcess(), &TmpAddress, &TmpSize,
                               ForWriteLocked ? GetUntrapProt(ProtectBase) : GetTrapProt(ProtectBase), &TmpProt);
      };
      const auto ChunkEnd = std::min(End, Address + Query.Size);
      if (ForWriteLocked || UntrackedWrites.empty()) {
        Protect(Address, ChunkEnd);
      } else {
        // Pages an untracked write is filling stay writable until it ends, see BeginUntrackedWrite
        for (auto Page = Address & FEXCore::Utils::FEX_PAGE_MASK; Page < ChunkEnd; Page += FEXCore::Utils::FEX_PAGE_SIZE) {
          if (std::ranges::none_of(UntrackedWrites, [Page](const auto& Write) { return Page >= Write.first && Page < Write.second; })) {
            Protect(std::max(Page, Address), std::min(Page + FEXCore::Utils::FEX_PAGE_SIZE, ChunkEnd));
          }
        }
      }
    } else if (!Query.Size) {
      // No more regions past `Address` in the interval list
      break;
    }

    Address += Query.Size;
  } while (Address < End);

  return HitRWXInterval;
}

} // namespace FEX::Windows
