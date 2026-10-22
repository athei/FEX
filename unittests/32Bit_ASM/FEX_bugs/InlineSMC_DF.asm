%ifdef CONFIG
{
  "Match": "All",
  "RegData": {
    "RAX": "0x400",
    "RBX": "0",
    "RDX": "0x00424242",
    "RSI": "0"
  },
  "Mode": "32BIT"
}
%endif

; FEX had a bug where DF was only written back to the context at the end of
; a block. A store into the page of the running block is inline SMC: the
; fault handler rebuilds the state from the context and steps the store
; again on its own, so a DF that the block changed before the store was
; lost. The data below sits in the same page as the code.
mov esp, 0xe000_1000

; Erase a NUL terminated string backwards, the way the PEtite packer erases
; import names after looking them up. With DF lost, rep stosb runs forwards
; from the terminator and wipes the start of the next string instead.
call base_addr
base_addr:
pop ebp

lea edi, [ebp + name1 - base_addr]
or ecx, -1
xor eax, eax
repne scasb
std
not ecx
dec edi
rep stosb
cld

mov ebx, dword [ebp + name1 - base_addr]
mov edx, dword [ebp + name2 - base_addr]

; DF set in the block right before a store into the block's own page.
std
mov byte [ebp + scratch - base_addr], 0
pushfd
pop eax
cld
and eax, 0x400

; DF cleared in a block that is entered with DF set.
std
call clear_df
pushfd
pop esi
and esi, 0x400

hlt

clear_df:
cld
mov byte [ebp + scratch - base_addr], 1
ret

align 4
name1: db "AAA", 0
name2: db "BBB", 0
scratch: dd 0
