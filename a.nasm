global _start

section .text
_start:
    mov edx, 0x12345678
    xor ecx,ecx
    mul ecx
    mov dx,0xfff
    inc edx
    mov ecx, 0xff