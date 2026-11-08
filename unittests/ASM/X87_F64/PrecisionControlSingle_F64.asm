%ifdef CONFIG
{
  "RegData": {
    "R9":  "0x419603fe",
    "RBX": "0x4032c07fc0000000",
    "RCX": "0x0",
    "RDX": "0x44358dd8",
    "RSI": "0x419603fe",
    "RDI": "0x3dce717e",
    "R10": "0x3dce717e"
  },
  "Env": { "FEX_X87REDUCEDPRECISION" : "1" }
}
%endif

; With 24-bit precision and 32-bit operands, reduced precision computes in
; 32-bit floats. Each result is the exact result rounded once to 24 bits, as
; on an x87.
; X87/PrecisionControlSingle.asm runs the same code in full precision.

lea rbp, [rel data]
mov r8, 0xe0000000

fldcw [rbp + cw24]

; A chain of 32-bit operations, stored as m32 and m64.
fld dword [rbp + a]
fmul dword [rbp + b]
fadd dword [rbp + c]
fdiv dword [rbp + b]
fabs
fsqrt
fchs
fsubr dword [rbp + a]
fdivr dword [rbp + c]
fst dword [r8]
fstp qword [r8 + 8]
mov r9d, [r8]
mov rbx, [r8 + 8]

; FCOM m32 of a 24-bit result: greater, so C0, C2 and C3 are clear.
fld dword [rbp + c]
fdiv dword [rbp + a]
fcom dword [rbp + b]
fnstsw ax
and eax, 0x4500
mov ecx, eax
fstp dword [r8]
mov edx, [r8]

; FTZ only matters below the normal range of 32-bit floats: the chain gives
; the same result. (There, reduced precision gives a 32-bit subnormal, or
; zero with FTZ, where the x87 has a normal number.)
ldmxcsr [rbp + mxcsr_ftz]
fld dword [rbp + a]
fmul dword [rbp + b]
fadd dword [rbp + c]
fdiv dword [rbp + b]
fabs
fsqrt
fchs
fsubr dword [rbp + a]
fdivr dword [rbp + c]
fstp dword [r8]
mov esi, [r8]
ldmxcsr [rbp + mxcsr_default]

; A value live in from the block before, 0.1 as a 64-bit float, which isn't
; an exact 32-bit float, times a 32-bit float: the exact product rounded to
; 24 bits, not the product with 0.1 rounded to 32 bits first (0x3dce717f).
; Twice, so the second time the loop block is entered from itself.
fld qword [rbp + tenth]
mov ecx, 2
loop1:
fld dword [rbp + m]
fmul st0, st1
fstp dword [r8]
mov edi, [r8]
dec ecx
jnz loop1
fstp st0

; The same live in as an exact 32-bit float, from FLD m32, which the block
; uses as a 32-bit float.
fld dword [rbp + m]
mov ecx, 2
loop2:
fld qword [rbp + tenth]
fmul st0, st1
fstp dword [r8]
mov r10d, [r8]
dec ecx
jnz loop2
fstp st0

hlt

align 8
data:
tenth equ $ - data
  dq 0.1
m equ $ - data
  dd 0x3f8106ef
a equ $ - data
  dd 1.7
b equ $ - data
  dd -0.3
c equ $ - data
  dd 1234.5678
mxcsr_ftz equ $ - data
  dd 0x9fc0
mxcsr_default equ $ - data
  dd 0x1f80
cw24 equ $ - data
  dw 0x007f
