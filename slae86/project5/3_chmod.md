# Analyze: chmod

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

Here I have cleaned and commented the code

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
