%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x4142434445464748",
    "RBX": "0x4142434445464748",
    "RCX": "0x6162636467686768",
    "RDX": "0xe0000068",
    "RSI": "0xe000007a"
  }
}
%endif

; POP with a memory destination computes an address based on RSP with the
; incremented RSP.

mov rsp, 0xe0000080

mov rax, 0x6162636465666768
push rax
mov rax, 0x5152535455565758
push rax
mov rax, 0x4142434445464748
push rax
mov rdx, rsp

; Loads from 0xe0000068, stores to 0xe0000070.
pop qword [rsp]
mov rax, [rsp]

; Loads from 0xe0000070, stores to 0xe0000080.
pop qword [rsp + 8]
mov rbx, [rsp + 8]

; Loads the low word from 0xe0000078, stores it to 0xe000007a.
pop word [rsp]
mov rcx, [rsp - 2]
mov rsi, rsp

hlt
