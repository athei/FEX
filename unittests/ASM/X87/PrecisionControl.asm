%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x4000",
    "RBX": "0x0",
    "RCX": "0x3fd5555560000000",
    "RSI": "0x3fd5555555555555",
    "RDI": "0x3ff6a09e60000000",
    "R8":  "0x3fd5555555555555",
    "R9":  "0x1000001",
    "R10": "0x3fd5555555555555",
    "R11": "0x1000000",
    "R12": "0x3fe5555560000000",
    "R13": "0x3fd5555540000000",
    "R14": "0x5357452e46535745",
    "R15": "0x3fd5555560000000"
  }
}
%endif

; With the precision control at 24 bits, FADD, FSUB, FMUL, FDIV and FSQRT
; round their results to single precision. Nothing else does.
; X87_F64/PrecisionControl_F64.asm runs the same code in reduced precision.

lea rbp, [rel data]
mov rdx, 0xe0000000

; LEGO Indiana Jones' fade gate: equal with 24-bit precision (C3 set).
fldcw [rbp + cw24]
fld dword [rbp + f03]
fadd qword [rbp + d25]
fadd dword [rbp + f03]
fadd dword [rbp + f02]
fcomp dword [rbp + f33]
fnstsw ax
and eax, 0x4500
mov [rdx + 64], eax

; The same with 53-bit precision: greater (C0, C2 and C3 clear).
fldcw [rbp + cw53]
fld dword [rbp + f03]
fadd qword [rbp + d25]
fadd dword [rbp + f03]
fadd dword [rbp + f02]
fcomp dword [rbp + f33]
fnstsw ax
and eax, 0x4500
mov ebx, eax

; FDIV with 24-bit precision, then 53-bit precision in the same block.
fldcw [rbp + cw24]
fld qword [rbp + one]
fdiv qword [rbp + three]
fstp qword [rdx]
mov rcx, [rdx]
fldcw [rbp + cw53]
fld qword [rbp + one]
fdiv qword [rbp + three]
fstp qword [rdx]
mov rsi, [rdx]

; The precision set in one block applies in the next.
fldcw [rbp + cw24]
jmp next_block
next_block:
fld qword [rbp + two]
fsqrt
fstp qword [rdx]
mov rdi, [rdx]

; Loads, sign changes, stores and integer loads are not rounded.
fld qword [rbp + third]
fchs
fchs
fstp qword [rdx]
mov r8, [rdx]
fild dword [rbp + int24p1]
fistp dword [rdx]
mov r9d, [rdx]

; FIADD rounds, here a tie to even.
fld qword [rbp + one]
fiadd dword [rbp + int24]
fistp dword [rdx]
mov r11d, [rdx]

; Register form of FSUB.
fld1
fld qword [rbp + third]
fsubp st1, st0
fstp qword [rdx]
mov r12, [rdx]

; FMUL rounds even when multiplying by one.
fld qword [rbp + third]
fmul qword [rbp + one]
fstp qword [rdx]
mov r15, [rdx]

; FILD m64 and FISTP m64 copy exactly, also across the block FLDCW starts.
fild qword [rbp + ewsf]
fldcw [rbp + cw24]
fistp qword [rdx]
mov r14, [rdx]

; Rounding towards zero with 24-bit precision.
fldcw [rbp + cw24rz]
fld qword [rbp + one]
fdiv qword [rbp + three]
fstp qword [rdx]
mov r13, [rdx]

; FNINIT sets 64-bit precision.
fninit
fld qword [rbp + one]
fdiv qword [rbp + three]
fstp qword [rdx]
mov r10, [rdx]

mov eax, [rdx + 64]
hlt

align 8
data:
one equ $ - data
  dq 1.0
two equ $ - data
  dq 2.0
three equ $ - data
  dq 3.0
third equ $ - data
  dq 0x3fd5555555555555
ewsf equ $ - data
  dq 0x5357452e46535745
d25 equ $ - data
  dq 2.5
f03 equ $ - data
  dd 0.3
f02 equ $ - data
  dd 0.2
f33 equ $ - data
  dd 3.3
int24 equ $ - data
  dd 0x1000000
int24p1 equ $ - data
  dd 0x1000001
cw24 equ $ - data
  dw 0x007f
cw53 equ $ - data
  dw 0x027f
cw24rz equ $ - data
  dw 0x0c7f
