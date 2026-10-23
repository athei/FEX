
%ifdef CONFIG
{
  "RegData": {
    "RSP": "0xE0000040"
  },
  "Mode": "32BIT"
}
%endif

mov esp, 0xe0000040
; SS can't be null, so pop the data selector the test setup loads into DS.
; Both halves of EAX hold it, since the 16-bit and 32-bit pops below read
; the pushed words at different offsets.
mov eax, 0x00170017

push eax
push eax
push eax
push eax
push eax

push ax
push ax
push ax
push ax
push ax

; Only pops the segments
; Doesn't check for a correct segment value
; Just ensures we are popping the correct amount of data
pop ss
pop ds
pop es
pop fs
pop gs

o16 pop ss
o16 pop ds
o16 pop es
o16 pop fs
o16 pop gs

hlt
