%ifdef CONFIG
{
  "RegData": {
    "MM0": "0x2222333344445555"
  },
  "Mode": "32BIT"
}
%endif

; FEX had a bug where MMX registers were only written back to the context at
; the end of a block. A store into the page of the running block is inline
; SMC: the fault handler rebuilds the state from the context and steps the
; store again on its own, so a value the block had loaded into an MMX
; register before the store was lost. The data below sits in the same page
; as the code.
mov esp, 0xe000_1000

call base_addr
base_addr:
pop ebp

; An older value, written back at the end of this block.
movq mm0, [ebp + old_mm - base_addr]
jmp .next

.next:
movq mm0, [ebp + new_mm - base_addr]
mov byte [ebp + scratch - base_addr], 0

hlt

align 8
old_mm: dq 0x1111111111111111
new_mm: dq 0x2222333344445555
scratch: dd 0
