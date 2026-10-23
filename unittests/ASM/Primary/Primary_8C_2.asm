%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x2b",
    "RBX": "0x2c",
    "RCX": "0x2d"
  }
}
%endif
; This relies on some behaviour that isn't guaranteed in 64bit mode

; A selector past the end of its table raises #GP, so these stay inside the
; 32-entry GDT and LDT
mov rax, 0x2b

db 0x44 ; REX.R
mov es, ax

inc rax

db 0x44 ; REX.R
mov ss, ax

inc rax

db 0x44 ; REX.R
mov ds, ax

; Can't test FS/GS here
; Behaviour is ill-defined and needs to be worked through

mov rax, 0
mov rbx, 0
mov rcx, 0

db 0x44 ; REX.R
mov ax, es

db 0x44 ; REX.R
mov bx, ss

db 0x44 ; REX.R
mov cx, ds

hlt
