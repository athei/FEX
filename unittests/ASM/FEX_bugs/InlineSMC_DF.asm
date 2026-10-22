%ifdef CONFIG
{
  "Match": "All",
  "RegData": {
    "RAX": "0x400",
    "RBX": "0",
    "RDX": "0x0042424242424242",
    "RSI": "0"
  }
}
%endif

; FEX had a bug where DF was only written back to the context at the end of
; a block. A store into the page of the running block is inline SMC: the
; fault handler rebuilds the state from the context and steps the store
; again on its own, so a DF that the block changed before the store was
; lost. The data below sits in the same page as the code.
mov rsp, 0xe000_1000

; Erase a NUL terminated string backwards, the way the PEtite packer erases
; import names after looking them up. With DF lost, rep stosb runs forwards
; from the terminator and wipes the start of the next string instead.
lea rdi, [rel name1]
or rcx, -1
xor eax, eax
repne scasb
std
not rcx
dec rdi
rep stosb
cld

mov rbx, qword [rel name1]
mov rdx, qword [rel name2]

; DF set in the block right before a store into the block's own page.
std
mov byte [rel scratch], 0
pushfq
pop rax
cld
and rax, 0x400

; DF cleared in a block that is entered with DF set.
std
call clear_df
pushfq
pop rsi
and rsi, 0x400

hlt

clear_df:
cld
mov byte [rel scratch], 1
ret

align 8
name1: db "AAAAAAA", 0
name2: db "BBBBBBB", 0
scratch: dq 0
