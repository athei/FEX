%ifdef CONFIG
{
  "Env": { "FEX_X87REDUCEDPRECISION" : "1" },
  "RegData": {
    "RAX": "0x3fb9999999999999",
    "RBX": "0x3fb9999999999999",
    "RCX": "0x3fb999999999999a"
  }
}
%endif

; FXRSTOR must apply the rounding control of the restored x87 control word,
; as FLDCW does. x87 and SSE share FPCR's rounding mode with reduced
; precision, so MXCSR's rounding control is taken when it is not round to
; nearest.

fninit
ldmxcsr [rel .mxcsr_default]

; x87 rounding toward zero, MXCSR round to nearest: 1/10 rounds down.
fxsave [rel .save]
mov word [rel .save], 0x0f7f
fxrstor [rel .save]
fld qword [rel .one]
fdiv qword [rel .ten]
fstp qword [rel .tmp]
mov rax, [rel .tmp]

; x87 round to nearest, MXCSR round down: MXCSR wins.
fninit
fxsave [rel .save]
mov dword [rel .save + 24], 0x3f80
fxrstor [rel .save]
movsd xmm0, [rel .one]
divsd xmm0, [rel .ten]
movq rbx, xmm0

; Both round to nearest again.
fninit
ldmxcsr [rel .mxcsr_default]
fxsave [rel .save]
fxrstor [rel .save]
fld qword [rel .one]
fdiv qword [rel .ten]
fstp qword [rel .tmp]
mov rcx, [rel .tmp]

hlt

align 8
.one:
dq 1.0
.ten:
dq 10.0
.tmp:
dq 0
.mxcsr_default:
dd 0x1f80

align 16
.save:
times 512 db 0
