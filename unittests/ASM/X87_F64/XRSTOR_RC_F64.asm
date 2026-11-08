%ifdef CONFIG
{
  "Env": { "FEX_X87REDUCEDPRECISION" : "1" },
  "HostFeatures": ["XSAVE"],
  "RegData": {
    "RAX": "0x3fb9999999999999",
    "RBX": "0x3fb9999999999999"
  }
}
%endif

; XRSTOR must apply the rounding control of the restored x87 control word,
; as FLDCW does, whether or not it restores MXCSR too.

fninit
ldmxcsr [rel .mxcsr_default]

; x87 and SSE state: x87 rounding toward zero, MXCSR round to nearest.
mov eax, 3
xor edx, edx
xsave [rel .save]
mov word [rel .save], 0x0f7f
mov qword [rel .save + 512], 3
xrstor [rel .save]
fld qword [rel .one]
fdiv qword [rel .ten]
fstp qword [rel .tmp]
mov r8, [rel .tmp]

; x87 state only.
fninit
mov eax, 3
xor edx, edx
xsave [rel .save]
mov word [rel .save], 0x0f7f
mov qword [rel .save + 512], 1
mov eax, 1
xrstor [rel .save]
fld qword [rel .one]
fdiv qword [rel .ten]
fstp qword [rel .tmp]
mov rbx, [rel .tmp]

mov rax, r8
fninit

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

align 64
.save:
times 4096 db 0
