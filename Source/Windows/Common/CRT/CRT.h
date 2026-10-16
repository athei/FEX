// SPDX-License-Identifier: MIT
#pragma once

namespace FEX::Windows {
// Makes rpmalloc map its spans as aligned reservations. InitCRTProcess calls it before initializing rpmalloc.
void SetupRpmallocMapHook();
void InitCRTProcess();
void InitCRTThread();
void DeinitCRTThread();
} // namespace FEX::Windows
