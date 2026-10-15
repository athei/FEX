.text
.balign 16

  // Hardware TSO (see Windows/Common/HardwareTSO.h). The state of a thread is CpuStateFrame::HardwareTSOState, which
  // directly follows the suspend doorbell that ChpeV2CpuAreaInfo->SuspendDoorbell points to: Off (0), On (1) or
  // NotUsed (2). The Mach trap thread_set_x86_64_compat(Enable), whose number is in HardwareTSOTrap, is issued with
  // svc #0x80 and returns 0 in x0 on success. It was seen to keep every other register, but being undocumented, the
  // registers that hold x64 state, x30 and NZCV are saved around it anyway.

  // Saves x0-x12, x15, x30 and NZCV below a 16-byte aligned stack pointer, as the x64 stack may be only 8-byte aligned.
  // x13 and x14 are not part of the ARM64EC register state.
.macro TSO_SAVE_X64_STATE
  mov x16, sp
  sub x17, x16, #0x90
  and x17, x17, #~0xf
  mov sp, x17
  stp x0, x1, [sp, #0x00]
  stp x2, x3, [sp, #0x10]
  stp x4, x5, [sp, #0x20]
  stp x6, x7, [sp, #0x30]
  stp x8, x9, [sp, #0x40]
  stp x10, x11, [sp, #0x50]
  stp x12, x15, [sp, #0x60]
  mrs x0, nzcv
  stp x30, x0, [sp, #0x70]
  str x16, [sp, #0x80] // Original stack pointer
.endm

.macro TSO_RESTORE_X64_STATE
  ldp x30, x0, [sp, #0x70]
  msr nzcv, x0
  ldp x0, x1, [sp, #0x00]
  ldp x2, x3, [sp, #0x10]
  ldp x4, x5, [sp, #0x20]
  ldp x6, x7, [sp, #0x30]
  ldp x8, x9, [sp, #0x40]
  ldp x10, x11, [sp, #0x50]
  ldp x12, x15, [sp, #0x60]
  ldr x16, [sp, #0x80]
  mov sp, x16
.endm

  // __os_arm64x_x64_jump in ARM64EC docs
  // Expects target code address in x9
.globl DispatchJump
DispatchJump:
  str lr, [sp, #-8]! // Push return address to stack, this will be popped by the x86 RET instr.
  b check_target_ec

  // __os_arm64x_dispatch_ret in ARM64EC docs
  // Expects target code address in lr
.globl RetToEntryThunk
RetToEntryThunk:
  mov x9, lr

check_target_ec:
  // Check if target is in fact x86 code
  ldr x16, [x18, #0x60] // TEB->PEB
  ldr x16, [x16, #0x368] // PEB->EcCodeBitMap
  lsr x17, x9, #18
  ldr x16, [x16, x17, lsl #3]
  lsr x17, x9, #12
  lsr x16, x16, x17
  tbnz x16, #0, ExitFunctionEC
  b enter_jit

  // __os_arm64x_dispatch_call_no_redirect in ARM64EC docs
  // Expects target code address in x9, and to be called using a 'blr x16' instruction.
.globl ExitToX64
ExitToX64:
  str lr, [sp, #-8]! // Push return address to stack, this will be popped by the x86 RET instr.

enter_jit:
  ldr x17, [x18, #0x1788] // TEB->ChpeV2CpuAreaInfo
  mov w16, #1
  strb w16, [x17, #0x0] // ChpeV2CpuAreaInfo->InSimulation
  ldr x16, [x17, #0x20] // ChpeV2CpuAreaInfo->SuspendDoorbell
  ldr w16, [x16, #0x4] // CpuStateFrame::HardwareTSOState
  cbz w16, enter_jit_tso_on // Off: switch the thread to hardware TSO before running JIT code

enter_jit_dispatch:
  ldr x16, [x17, #0x40] // ChpeV2CpuAreaInfo->EmulatorData[2] - DispatcherLoopTopEnterEC
  br x16 // DispatcherLoopTopEnterEC(RIP:x9, CPUArea:x17)

enter_jit_tso_on:
  TSO_SAVE_X64_STATE
  mov w0, #1
  adrp x16, HardwareTSOTrap
  ldr x16, [x16, #:lo12:HardwareTSOTrap]
  svc #0x80 // thread_set_x86_64_compat(1)
  cbnz w0, tso_enable_failed
  ldr x17, [x18, #0x1788] // TEB->ChpeV2CpuAreaInfo
  ldr x16, [x17, #0x20] // ChpeV2CpuAreaInfo->SuspendDoorbell
  mov w0, #1
  str w0, [x16, #0x4] // CpuStateFrame::HardwareTSOState = On
  TSO_RESTORE_X64_STATE
  b enter_jit_dispatch

tso_enable_failed:
  bl "#HardwareTSOEnableFailed" // Does not return

  // Invoked by KiUserEmulationDispatcher after e.g. an NtContinue to x86 code
.global BeginSimulation
BeginSimulation:
  ldr x17, [x18, #0x1788] // TEB->ChpeV2CpuAreaInfo
  ldr x16, [x17, #0x8] // ChpeV2CpuAreaInfo->EmulatorStackBase
  mov sp, x16
  ldr x0, [x17, #0x18] // ChpeV2CpuAreaInfo->ContextAmd64
  bl "#SyncThreadContext"
  ldr x17, [x18, #0x1788] // TEB->ChpeV2CpuAreaInfo
  ldr x16, [x17, #0x48] // ChpeV2CpuAreaInfo->EmulatorData[3] - DispatcherLoopTopEnterECFillSRA
  mov x11, #0 // Zero ENTRY_FILL_SRA_SINGLE_INST_REG to avoid single step
  br x16 // DispatcherLoopTopEnterECFillSRA(SingleInst:x10, CPUArea:x17)

  // Called into by FEXCore
  // Expects the target code address in x9
.global ExitFunctionEC
ExitFunctionEC:
  // Clear the AFP NEP and AH bits in FPCR as native code won't expect their behaviour. Skip the write when they are
  // already clear, which is always the case unless AFP is in use, as FPCR writes are slow on some hardware. NZCV still
  // holds the guest flags here, so test the bits without touching it.
  mrs x17, fpcr
  tbnz x17, #1, 1f // AH
  tbz x17, #2, 2f // NEP
1:
  and x17, x17, #~6 // NEP + AH
  msr fpcr, x17
2:
  ldr x17, [x18, #0x1788] // TEB->ChpeV2CpuAreaInfo
  strb wzr, [x17, #0x0] // ChpeV2CpuAreaInfo->InSimulation
  ldr x17, [x17, #0x20] // ChpeV2CpuAreaInfo->SuspendDoorbell
  ldr w17, [x17]
  cbnz w17, ExitFunctionSuspendPoint

.global ExitFunctionSuspendResumePoint
ExitFunctionSuspendResumePoint:
  // Either return to an exit thunk (return to ARM64EC function) or call an entry thunk (call to ARM64EC function).
  // It is assumed that a 'blr x16' instruction is only ever used to call into x86 code from an exit thunk, and that all
  // exported ARM64EC functions have a 4-byte offset to their entry thunk immediately before their first instruction.
  mov x17, x9
  mov w16, #0x200
  movk w16, #0xd63f, lsl 16 // blr x16
  ldursw x23, [x17, #-0x4] // Load either the entry thunk offset or the calling instruction.
  cmp w23, w16
  beq ret_sp_aligned

  and x23, x23, #-0x4
  add x17, x17, x23 // Resolve entry thunk address.

  mov x4, sp
  tbz x4, #3, ret_sp_misaligned
  ldr lr, [x4], #0x8 // Pop the return address into lr.
  mov sp, x4

ret_sp_aligned:
  br x17

ret_sp_misaligned:
  // In the case of the x64 caller leaving sp only 8-byte aligned, leave the return address on the stack to keep 16-byte
  // alignment and have the callee return to an x86 ret instruction. FEX can then return to the actual caller keeping
  // the misaligned RSP.
  adrp lr, X64ReturnInstr
  ldr lr, [lr, #:lo12:X64ReturnInstr]
  br x17

.global ExitFunctionSuspendPoint
ExitFunctionSuspendPoint:
  brk #0xCAFE
  // Resume will jump back to `ExitFunctionSuspendResumePoint`

  // Wrappers around ntdll's __wine_syscall_dispatcher and __wine_unix_call_dispatcher_arm64ec, installed by
  // InstallHardwareTSOHooks. They switch the calling thread off before native code handles the call if it is On and
  // InSimulation is clear. InSimulation is set while FEX itself runs inside JIT execution (compiling, handling a
  // fault) and returns straight into JIT code without passing an entry point; all of FEX's syscalls other than the
  // *Native ones go through these wrappers and stay on only because of that check, which code that calls ntdll and
  // then resumes JIT code must keep. Everything the original dispatchers read (x0-x9, x30, sp) is passed on unchanged,
  // and x10-x17 are free as the originals overwrite them. The stack pointer is 16-byte aligned as these are called
  // from ARM64EC code. There is no unwind information: nothing can raise an exception here, and only a stack walk of
  // a thread suspended at the trap would see the caller's stack pointer 0x70 off, as with ExitFunctionEC.
.macro TSO_DISPATCHER_WRAPPER Name, Orig
.global \Name
\Name:
  hint 34 // bti c
  ldr x16, [x18, #0x1788] // TEB->ChpeV2CpuAreaInfo
  cbz x16, 2f
  ldrb w17, [x16, #0x0] // ChpeV2CpuAreaInfo->InSimulation
  cbnz w17, 2f
  ldr x16, [x16, #0x20] // ChpeV2CpuAreaInfo->SuspendDoorbell, null before ThreadInit and after ThreadTerm
  cbz x16, 2f
  ldr w17, [x16, #0x4] // CpuStateFrame::HardwareTSOState
  tbz w17, #0, 2f // Only On (1) has bit 0 set
  str wzr, [x16, #0x4] // CpuStateFrame::HardwareTSOState = Off, before the trap (see HardwareTSO.h)
  stp x29, x30, [sp, #-0x70]!
  stp x0, x1, [sp, #0x10]
  stp x2, x3, [sp, #0x20]
  stp x4, x5, [sp, #0x30]
  stp x6, x7, [sp, #0x40]
  stp x8, x9, [sp, #0x50]
  mrs x0, nzcv
  str x0, [sp, #0x60]
  mov w0, #0
  adrp x16, HardwareTSOTrap
  ldr x16, [x16, #:lo12:HardwareTSOTrap]
  svc #0x80 // thread_set_x86_64_compat(0), a failure leaves the thread on, which is harmless
  ldr x17, [sp, #0x60]
  msr nzcv, x17
  ldp x0, x1, [sp, #0x10]
  ldp x2, x3, [sp, #0x20]
  ldp x4, x5, [sp, #0x30]
  ldp x6, x7, [sp, #0x40]
  ldp x8, x9, [sp, #0x50]
  ldp x29, x30, [sp], #0x70
2:
  adrp x16, \Orig
  ldr x16, [x16, #:lo12:\Orig]
  br x16
.endm

TSO_DISPATCHER_WRAPPER TSOSyscallDispatcher, TSOOrigSyscallDispatcher
TSO_DISPATCHER_WRAPPER TSOUnixCallDispatcher, TSOOrigUnixCallDispatcher

  // This table will contain all of the possible SVC #x instructions that we might need.
  // We index into this table in DIRECT_SYSCALL_WRAPPER based on the syscall number we find
  // by parsing the table __arm64ec_syscall_ffs from NTDLL.
#define SYSCALL_TABLE_ENTRIES 512
.global SyscallTable
SyscallTable:
  .set SyscallId, 0
  .rept SYSCALL_TABLE_ENTRIES
    svc #SyscallId
    ret
    .set SyscallId, SyscallId + 1
  .endr
.global SyscallTableEnd
SyscallTableEnd:

  // Makes a wrapper for calling a system call directly, skipping the usual ntdll thunks
#define HASH #
#define DIRECT_SYSCALL_WRAPPER(Name, WineIdName) \
  .global Name; \
  Name:; \
    adrp x16, WineSyscallDispatcher; \
    ldr x16, [x16, HASH:lo12:WineSyscallDispatcher]; \
    cbz x16, 1f; \
    mov x9, x30; \
    adrp x8, WineIdName; \
    ldr x8, [x8, HASH:lo12:WineIdName]; \
    blr x16; \
    ret; \
  1:; \
    adrp x16, SyscallTable; \
    add x16, x16, HASH:lo12:SyscallTable; \
    adrp x17, WineIdName; \
    ldr x17, [x17, HASH:lo12:WineIdName]; \
    add x16, x16, x17, lsl HASH 3; \
    br x16

  // Allows for continuing from a full native context, as the NTDLL NtContinue export takes in an x64 context with EC and
  // the conversion to that loses the ARM64EC ABI-disallowed registers that FEX uses.
DIRECT_SYSCALL_WRAPPER("#NtContinueNative", WineNtContinueSyscallId)
DIRECT_SYSCALL_WRAPPER("#NtRaiseExceptionNative", WineNtRaiseExceptionSyscallId)

  // Both of these are wrapped as FEX needs them to setup its call checker at startup time and their NTDLL thunks could
  // already be patched by then (and because the call checker isn't installed, their patched x86 versions would be invoked
  // when called by FEX).
DIRECT_SYSCALL_WRAPPER("#NtAllocateVirtualMemoryExNative", WineNtAllocateVirtualMemoryExSyscallId)
DIRECT_SYSCALL_WRAPPER("#NtProtectVirtualMemoryNative", WineNtProtectVirtualMemorySyscallId)

  // A replacement for the standard ARM64EC call checker that ignores any FFS patches and always redirects to a function's
  // native implementation. As the only library FEX calls into is NTDLL, this is done using a LUT generated at init time.
  // Expects the FFS address in x11, exit thunk address in x10 (unused) and it's own address in x9. Return address is in x11.
.global "CheckCall"
"CheckCall":
  adrp x9, NtDllBase
  ldr x9, [x9, #:lo12:NtDllBase]
  subs x16, x11, x9
  b.lo end
  adrp x17, NtDllRedirectionLUTSize
  ldr w17, [x17, #:lo12:NtDllRedirectionLUTSize]
  cmp x16, x17
  b.hs end
  adrp x17, NtDllRedirectionLUT
  ldr x17, [x17, #:lo12:NtDllRedirectionLUT]
  ldr w11, [x17, x16, lsl #2]
  add x11, x11, x9
end:
  ret

  // Expects target address in x0, and the SP to set in x1
.global "#JumpSetStack"
"#JumpSetStack":
  mov sp, x1
  br x0
