%ifdef CONFIG
{
  "RegData": {
    "R9":  "0x419603fe",
    "RBX": "0x4032c07fc0000000",
    "RCX": "0x0",
    "RDX": "0x44358dd8",
    "RSI": "0x37916c2620000000",
    "RDI": "0x37916c2620000000",
    "R10": "0x3dce717e",
    "R11": "0x3dce717e"
  }
}
%endif

; With 24-bit precision, each result is the exact result rounded once to 24
; bits, with the full exponent range.
; X87_F64/PrecisionControlSingle_F64.asm runs most of it in reduced
; precision, which gives different results for the products below the
; normal range of 32-bit floats.

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

; A product below the normal range of 32-bit floats is still a normal
; number, with and without FTZ, which only affects SSE.
fld dword [rbp + tiny]
fmul dword [rbp + tiny]
fmul dword [rbp + half]
fstp qword [r8]
mov rsi, [r8]
ldmxcsr [rbp + mxcsr_ftz]
fld dword [rbp + tiny]
fmul dword [rbp + tiny]
fmul dword [rbp + half]
fstp qword [r8]
mov rdi, [r8]
ldmxcsr [rbp + mxcsr_default]

; A value live in from the block before, 0.1 as a 64-bit float, times a
; 32-bit float: the exact product rounded to 24 bits.
fld qword [rbp + tenth]
mov ecx, 2
loop1:
fld dword [rbp + m]
fmul st0, st1
fstp dword [r8]
mov r10d, [r8]
dec ecx
jnz loop1
fstp st0

fld dword [rbp + m]
mov ecx, 2
loop2:
fld qword [rbp + tenth]
fmul st0, st1
fstp dword [r8]
mov r11d, [r8]
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
tiny equ $ - data
  dd 1.0e-20
half equ $ - data
  dd 0.5
mxcsr_ftz equ $ - data
  dd 0x9fc0
mxcsr_default equ $ - data
  dd 0x1f80
cw24 equ $ - data
  dw 0x007f
