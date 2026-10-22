%ifdef CONFIG
{
  "HostFeatures": ["AVX"],
  "RegData": {
    "MM0": "0x2222333344445555",
    "XMM1": ["0x4142434445464748", "0x5152535455565758", "0x6162636465666768", "0x7172737475767778"]
  }
}
%endif

; FEX had a bug where MMX registers and the upper halves of the YMM
; registers were only written back to the context at the end of a block. A
; store into the page of the running block is inline SMC: the fault handler
; rebuilds the state from the context and steps the store again on its own,
; so values the block had loaded into them before the store were lost. The
; data below sits in the same page as the code.
mov rsp, 0xe000_1000

; Older values, written back at the end of this block.
movq mm0, [rel old_mm]
vmovdqu ymm1, [rel old_ymm]
jmp .next

.next:
movq mm0, [rel new_mm]
vmovdqu ymm1, [rel new_ymm]
mov byte [rel scratch], 0

hlt

align 32
old_mm: dq 0x1111111111111111
new_mm: dq 0x2222333344445555
align 32
old_ymm: times 4 dq 0x1111111111111111
new_ymm: dq 0x4142434445464748, 0x5152535455565758, 0x6162636465666768, 0x7172737475767778
scratch: dq 0
