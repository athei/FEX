%ifdef CONFIG
{
  "Env": { "FEX_X87REDUCEDPRECISION" : "1" },
  "RegData": {
    "RAX": "0x000012688b70e62b",
    "RBX": "0x000012688b70e62b",
    "RCX": "0",
    "RDX": "0"
  }
}
%endif

; FEX used to copy bit 12 of the x87 control word (infinity control, which
; has no effect since the 80387) into FPCR.FZ, so Delphi's default control
; word 0x1332 flushed subnormal SSE and x87 results to zero. And an x87
; control word write or FNINIT cleared the FTZ that MXCSR had set.

fninit

; The control word with infinity control set, all exceptions masked.
fldcw [rel .cw_ic]

; 1e-300 * 1e-10 is subnormal.
movsd xmm0, [rel .tiny_a]
mulsd xmm0, [rel .tiny_b]
movq rax, xmm0

fld qword [rel .tiny_a]
fmul qword [rel .tiny_b]
fstp qword [rel .tmp]
mov rbx, [rel .tmp]

; MXCSR.FTZ must survive FLDCW and FNINIT.
fldcw [rel .cw_default]
ldmxcsr [rel .mxcsr_ftz]
fldcw [rel .cw_default]
movsd xmm1, [rel .tiny_a]
mulsd xmm1, [rel .tiny_b]
movq rcx, xmm1

fninit
movsd xmm2, [rel .tiny_a]
mulsd xmm2, [rel .tiny_b]
movq rdx, xmm2

ldmxcsr [rel .mxcsr_default]

hlt

align 8
.tiny_a:
dq 1.0e-300
.tiny_b:
dq 1.0e-10
.tmp:
dq 0
.cw_ic:
dw 0x137f
.cw_default:
dw 0x037f
align 4
.mxcsr_ftz:
dd 0x9f80
.mxcsr_default:
dd 0x1f80
