; Filename: project3: egghunter.nasm

global _start

section .data
        msg     db "We found the egg!",0ah,0dh
        msg_len equ $-msg
        egg     equ "egg "
        egg1    equ "mark"

section .text
        global  _start

_start:
        jmp     _return

_continue:
        pop     eax             ;This can point anywhere valid
_next:
        inc     eax             ;change to dec if you want to search backwards
_isEgg:
        cmp     dword [eax-8],egg
        jne     _next
        cmp     dword [eax-4],egg1
        jne     _next
        jmp     eax
_return:
        call    _continue


        
_egg:
        db  "egg mark"              ;QWORD egg marker
        sub     eax,8
        mov     ecx,eax
        mov     edx,8
        mov     eax,4
        mov     ebx,1
        int     80h
        mov     eax,1
        mov     ebx,0
        int     80h