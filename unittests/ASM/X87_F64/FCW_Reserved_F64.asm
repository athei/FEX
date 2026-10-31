%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x27f",
    "RBX": "0x27f",
    "RCX": "0x27f",
    "RDX": "0x1f7f",
    "RSI": "0x1f7f",
    "RDI": "0x1f7f",
    "R8":  "0x40",
    "R9":  "0x40",
    "R10": "0x40",
    "R11": "0x67f",
    "R12": "0x67f",
    "R13": "0x67f"
  },
  "Env": { "FEX_X87REDUCEDPRECISION" : "1" }
}
%endif

; x87 hardware reads bit 6 of the control word as one and bits 7, 13, 14 and 15
; as zero, whatever was loaded.
; X87/FCW_Reserved.asm runs the same code in full precision.

; FNSTENV goes last: it sets the exception masks after storing the word.
; Only the low 16 bits of its first field are the control word.
%macro read_cw 3
  fnstcw [rel cw]
  movzx %1, word [rel cw]
  fxsave [rel area]
  movzx %2, word [rel area]
  fnstenv [rel env]
  movzx %3, word [rel env]
%endmacro

fninit

fldcw [rel word_23f]
read_cw rax, rbx, rcx

fldcw [rel word_ffff]
read_cw rdx, rsi, rdi

fldcw [rel word_0000]
read_cw r8, r9, r10

; The same through an FXRSTOR image with the reserved bits inverted.
fninit
fxsave [rel image]
mov word [rel image], 0xe6bf
fxrstor [rel image]
read_cw r11, r12, r13

fninit
hlt

align 8
word_23f:
dw 0x23f
word_ffff:
dw 0xffff
word_0000:
dw 0x0000
cw:
dw 0

align 8
env:
times 28 db 0

align 16
area:
times 512 db 0

align 16
image:
times 512 db 0
