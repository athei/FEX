// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/fextl/vector.h>

#include <winternl.h>

namespace FEX::Windows {
void SetupThreadHandlers();

// Suspends the given threads with Suspend for a termination of the process by the current thread, waits until they have
// stopped, and returns the ones it suspended. See the definition. Suspend must be a FEX function: under ARM64EC, the
// address of an ntdll export is its x64 entry, which can't be called from here.
fextl::vector<HANDLE> SuspendThreadsForTermination(const fextl::vector<HANDLE>& Threads, NTSTATUS (*Suspend)(HANDLE));
} // namespace FEX::Windows
