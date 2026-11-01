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

void InvalidationTracker::HandleMemoryProtectionNotification(uint64_t Address, uint64_t Size, ULONG Prot) {
  const auto AlignedBase = Address & FEXCore::Utils::FEX_PAGE_MASK;
  const auto AlignedSize = (Address - AlignedBase + Size + FEXCore::Utils::FEX_PAGE_SIZE - 1) & FEXCore::Utils::FEX_PAGE_MASK;

  const bool NeedsInvalidate = [&]() {
    std::unique_lock Lock(IntervalsLock);

    FEXCore::IntervalList<uint64_t>::Interval ProtInterval {AlignedBase, AlignedBase + AlignedSize};

    const bool EffectiveExec = ProtHasExec(Prot) || (DEPDisabled && ProtIsReadable(Prot));

    if (EffectiveExec) {
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
    InvalidateIntervalInternal(AlignedBase, AlignedSize);
  }
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
      if (Info.State == MEM_COMMIT && ProtIsReadable(Info.Protect) && !ProtHasExec(Info.Protect)) {
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

void InvalidationTracker::InvalidateAlignedInterval(uint64_t Address, uint64_t Size, bool Free) {
  if (!Address) {
    // Match the Windows behaviour when passed a NULL base address.
    Size = std::numeric_limits<uint64_t>::max();
  }

  const auto AlignedBase = Address & FEXCore::Utils::FEX_PAGE_MASK;
  const auto AlignedSize = std::max(Size, (Address - AlignedBase + Size + FEXCore::Utils::FEX_PAGE_SIZE - 1) & FEXCore::Utils::FEX_PAGE_MASK);

  // Removed before invalidating, so no code compiled from the range outlives it
  if (Free) {
    std::unique_lock Lock(IntervalsLock);
    XIntervals.Remove({AlignedBase, AlignedBase + AlignedSize});
    RWXIntervals.Remove({AlignedBase, AlignedBase + AlignedSize});
  }

  InvalidateIntervalInternal(AlignedBase, AlignedSize);
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
  if (NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(Address), MemoryBasicInformation, &Info, sizeof(Info), nullptr) ||
      Info.State != MEM_COMMIT || (Info.Protect & PAGE_GUARD) ||
      !(ProtHasExec(Info.Protect) || (DEPDisabled && ProtIsReadable(Info.Protect)))) {
    return false;
  }

  const auto Base = reinterpret_cast<uint64_t>(Info.BaseAddress);
  AddExecutableInterval({Base, Base + Info.RegionSize}, Info.Protect);
  return true;
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
  // for that: a compile holds the code invalidation mutex here, which the notifications take with ThreadCreationMutex
  // held.
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

void InvalidationTracker::InvalidateIntervalInternal(uint64_t Address, uint64_t Size) {
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
