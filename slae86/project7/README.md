## Assignment 7

Create a custom crypter like the one shown in the “crypters” video 
- Free to use any existing encryption schema 
- Can use any programming language

For this assignment, the task is to create a cryptor and decryptor for shellcode. I had some confusion when trying to understand this assignment. Mainly, when looking at previous student's work, the methodology seems to be to encrypt using a program/script, then decrypt it with a seperate script. My thinking was that the shellcode should be able to decrypt itself. 

I didn't fully get it working, however I thought I would speak to my process and document it for this assignment to make it a bit unique.

Firstly, I was thinking if the encryption/decryption was done in c and compiled to an executable, I could dump the shellcode and execute it. I wanted to use C as the resulting shellcode should be leaner than compiling another language such as Python into an executable to dump. To start, I used [this blog post](https://medium.com/@nlahoz/slae-assignment-7-6c53ab6e68a6) from a previous student. They did an excellent job documenting the methodology. Essentially, they use [tiny aes.c](https://github.com/kokke/tiny-AES-c) to help with the encryption functions to encrypt and decrypt the payload. To make it a bit different, I thought about using a different encryption scheme, but after a bit of research on [AES Encryption](https://www.highgo.ca/2019/08/08/the-difference-in-five-modes-in-the-aes-encryption-algorithm/) I didn't think it would be that valuable. 

My next thought was that I could go one step further and have a final shellcode that decrypts itself. To do this, I modified the Decryptor.c program and morphed it into a decrypt_and_run.c program:

```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define CBC 1
#define CTR 1
#define ECB 1

#include "aes.h"

int i;
static void decrypt(void)
{
    /// Generating Key:
    uint8_t key[] = { 0x1c, 0x17, 0x02, 0x41, 0xa7, 0x98, 0xe6, 0x25, 0x37, 0xc9, 0x35, 0x1f, 0xca, 0x8c, 0xe8, 0xd8, 0x9d, 0x2f, 0x10, 0xe6, 0x8f, 0x59, 0xf8, 0x05, 0x7a, 0x81, 0x03, 0xa7, 0xb8, 0xe1, 0x84, 0xd4, };

    // Generating IV:
    uint8_t iv[]  = { 0xf8, 0x86, 0x15, 0x9f, 0x1f, 0xfb, 0xc4, 0x56, 0xc5, 0xfa, 0x76, 0x8f, 0x86, 0x5e, 0x68, 0x24, };

    // Encrypted Shellcode:
    uint8_t shellcode[] = { 0x72, 0x4c, 0x44, 0x6c, 0x46, 0x2c, 0x81, 0x61, 0x59, 0x75, 0x3a, 0x40, 0x48, 0x05, 0xc4, 0x3f, 0x59, 0x6d, 0xc4, 0xd9, 0xe4, 0x04, 0x22, 0xfd, 0xa5, 0x1f, 0xd1, 0x60, 0x3a, 0xb9, 0x14, 0x3f, };
    
    
    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, shellcode, sizeof(shellcode));

    printf("Decrypted Shellcode:\n");

    for (i = 0; i < sizeof shellcode; i ++)
    {
        printf("\\x%02x", shellcode[i]);
    }
    printf("\n");
}

int main(void)
{
    decrypt();
}
```

The idea being that the shellcode would be decrypted and executed all from the same program. It works after compiling and executing the program:

```bash
gcc aes.c Decrypt_and_run.c -m32 -o decrypt_and_run
./decrypt_and_run
```

So now I have a hardcoded key and IV that is embedded into the program. If this payload were distributed and a forensic team got their hands on it, they would be able to statically decrypt all payloads across any devices they found with this same Key/IV. To make this a bit more dynamic and make the defenders life a little more difficult (maybe?), I modified the Cryptor.c program to randomly generate a new IV and Key with every execution. It also does the proper padding for the payload for CBC encryption, thus a new payload can be easily entered without worrying about having to pad the new shellcode with the proper number of `nop`'s in order to fill out the last encryption block.

```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>     // for rand()
#include <time.h>       // for time()

#define CBC 1
#define CTR 1
#define ECB 1

#include "aes.h"

int rand_byte() {
    int byte;
    do {
        byte = rand() & 0xff;
    } while (byte == 0x00);
    return byte;
}


int i;
static void encrypt(void)
{
    uint8_t key[32];
    uint8_t iv[16];

    // Shellcode "execve-stack"
	uint8_t unpadded_shellcode[] = { 
                            0x31, 0xc0, 0x50, 0x68, 0x62, 0x61, 0x73, 0x68,
                            0x68, 0x62, 0x69, 0x6e, 0x2f, 0x68, 0x2f, 0x2f,
                            0x2f, 0x2f, 0x89, 0xe3, 0x50, 0x89, 0xe2, 0x53,
                            0x89, 0xe1, 0xb0, 0x0b, 0xcd, 0x80 
                        };


    // seed random function
    srand(time(0));

    // pad shellcode with nops: \x90
    // for proper encryption block size
    int len = sizeof unpadded_shellcode;
    int padding = 8 - (len % 8);
    int new_len = len + padding;
    uint8_t shellcode[new_len];
    for (int x = 0; x < new_len; x++ )
        shellcode[x] = (x >= len) ? 0x90 : unpadded_shellcode[x];


    printf("Padded Shellcode:\n");
    for (int x = 0; x < new_len; x++)
        printf("\\x%02x", shellcode[x]);

    printf("\n\n// Generating Key:");
    printf("\nuint8_t key[] = { ");
    for (int x = 0; x < 32; x++) {
        int b = rand_byte();
        printf("0x%02x, ", b);
        key[x] = b;
    }
    printf("};\n\n");

    printf("// Generating IV:\n");
    printf("uint8_t iv[]  = { ");
    for (int x = 0; x < 16; x++) {
        int b = rand_byte();
        printf("0x%02x, ", b);
        iv[x] = b;
    }
    printf("};\n\n");

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, shellcode, sizeof(shellcode));
    
    printf("// Encrypted Shellcode:\n");
    printf("uint8_t shellcode[] = { ");
    for (i = 0; i < sizeof shellcode; i ++)
        printf("0x%02x, ", shellcode[i]);
    printf("};\n");
}

int main(void)
{
    encrypt();
}
```

After compiling and executing with:

```bash
gcc aes.c Cryptor.c -m32 -o cryptor
./cryptor
```

It outputs some rows to copy/paste into the decryptor script:
```c
// Generating Key:
uint8_t key[] = { 0xf5, 0x1d, 0xaf, 0x2f, 0xb7, 0xda, 0x71, 0xfa, 0x05, 0xc1, 0x2e, 0x22, 0x57, 0xa7, 0xa4, 0x23, 0xa6, 0x67, 0xb1, 0xa6, 0x5a, 0x18, 0xb2, 0xea, 0xc7, 0x54, 0xce, 0xa6, 0xab, 0x6b, 0xd9, 0xa1, };

// Generating IV:
uint8_t iv[]  = { 0x88, 0x88, 0xd0, 0x40, 0x62, 0x41, 0x3a, 0x67, 0x02, 0x68, 0x8a, 0x5a, 0x0f, 0x2e, 0x7d, 0xb6, };

// Encrypted Shellcode:
uint8_t shellcode[] = { 0x76, 0xcc, 0x51, 0x49, 0xfa, 0xe7, 0xe1, 0x7d, 0xe0, 0xcb, 0xde, 0x52, 0x70, 0x94, 0xd1, 0x87, 0xe3, 0x58, 0x50, 0x2c, 0x9d, 0xed, 0x79, 0xa6, 0x1e, 0xee, 0xbe, 0x00, 0xd7, 0xc3, 0x12, 0x09, };
```

Now, with this dynamiclly generated IV/Key/shellcode, it is trivial to copy/paste into the decrypt_and_run.c source code above.

So now that I have a working decrypt_and_run program, my goal was to dump it's shellcode and execute it usng a c program wrapper, the same methodology as previous shellcode payloads. However, when dumping this shellcode with `objdump`, it reuslts in a payload with null bytes `\x00`. That's ok! Because my custom encoder from project 4 encodes by xor'ing and ensures no null bytes exist! 

After running my custom encoder, I recieve a very large shellcode without null bytes. Unfortunately, it segfaults when trying to execute it. 

Actually, when just writing a basic .nasm file to execute the unencoded decrypt_and_run shellcode, it segfaults. However, a regular msfvenom payload that reads /etc/passwd without removing nulls does work.

```assembly
global _start


section .text
_start:
    jmp _shellcode

_shellcode:
    ; read /etc/passwd, with null bytes
    db 0xeb, 0x36, 0xb8, 0x05, 0x00, 0x00, 0x00, 0x5b, 0x31, 0xc9, 0xcd, 0x80, 0x89, 0xc3, 0xb8, 0x03, 0x00, 0x00, 0x00, 0x89, 0xe7, 0x89, 0xf9, 0xba, 0x00, 0x10, 0x00, 0x00, 0xcd, 0x80, 0x89, 0xc2, 0xb8, 0x04, 0x00, 0x00, 0x00, 0xbb, 0x01, 0x00, 0x00, 0x00, 0xcd, 0x80, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbb, 0x00, 0x00, 0x00, 0x00, 0xcd, 0x80, 0xe8, 0xc5, 0xff, 0xff, 0xff, 0x2f, 0x65, 0x74, 0x63, 0x2f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x64, 0x00
    
    ; decrypt_and_run 
    ; db 0x53, 0x83, 0xec, 0x08, 0xe8, 0xa7, 0x00, 0x00, 0x00, 0x81, 0xc3, 0xf7, 0x3f, 0x00, 0x00, 0x8b, 0x83, 0xf4, 0xff, 0xff, 0xff, 0x85, 0xc0, 0x74, 0x02, 0xff, 0xd0, 0x83, 0xc4, 0x08, 0x5b, 0xc3, 0xff, 0xb3, 0x04, 0x00, 0x00, 0x00, 0xff, 0xa3, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xa3, 0x0c, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0xe9, 0xe0, 0xff, 0xff, 0xff, 0xff, 0xa3, 0x10, 0x00, 0x00, 0x00, 
    ; .....
    ; .....
    ; .....
    ; 0x2c, 0xff, 0x74, 0x24, 0x2c, 0xff, 0x94, 0xb5, 0xf4, 0xfe, 0xff, 0xff, 0x83, 0xc6, 0x01, 0x83, 0xc4, 0x10, 0x39, 0xf3, 0x75, 0xe3, 0x83, 0xc4, 0x0c, 0x5b, 0x5e, 0x5f, 0x5d, 0xc3, 0x8d, 0x76, 0x00, 0xc3, 0x8b, 0x2c, 0x24, 0xc3, 0x53, 0x83, 0xec, 0x08, 0xe8, 0x5f, 0xe9, 0xff, 0xff, 0x81, 0xc3, 0xaf, 0x28, 0x00, 0x00, 0x83, 0xc4, 0x08, 0x5b, 0xc3

```

I have a few theories on why this doesn't work. Perhaps the `objdump` command I'm using to dump shellcode isn't capturing all bytes. Or perhaps it's because the shellcode doesn't have access to dependencies (module imports) of the ELF. I'm also thinking a likely cause is that using `gcc` on the .c files is not building the ELF in a similar way that compiling and linking assembly does - as I cannot get even a basic shellcode dumped from a gcc compiled ELF to execute. 

As an aside, this is my current version of dumping shellcode with objdump. It seems to work with every ELF created from a .nasm file, so perhaps compiling with gcc is breaking things or maybe it's the aes.c functions and increased dependency usage that may be causing the segfaults?

```bash
dump-shellcode () {
    objdump -d "$1" |grep '[0-9a-f]:' | grep -v file | cut -d':' -f2- | sed 's/^\W*//g' | grep -Po "^([0-9a-f]{2} )+" | tr -d '\n' | sed 's/\W/\\x/g' | sed 's/^/\\x/g' | rev | cut -c3- |rev
}
```

Since this was mainly just experimenting and not required for this assignment, I will continue without figuing this out and table this for an exercise for myself later. 

So, in addition to the dynamic Cryptor.c program above, a basic Decryptor.c program that outputs the original shellcode can be created. Just be sure to copy/paste the output from the Cryptor.c to replace the `key` `iv` and `shellcode` parameters, as each run of Cryptor.c will result in new values for each, even for the same orignial shellcode payload:

```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define CBC 1
#define CTR 1
#define ECB 1

#include "aes.h"

int i;
static void decrypt(void)
{
    /// Generating Key:
    uint8_t key[] = { 0x1c, 0x17, 0x02, 0x41, 0xa7, 0x98, 0xe6, 0x25, 0x37, 0xc9, 0x35, 0x1f, 0xca, 0x8c, 0xe8, 0xd8, 0x9d, 0x2f, 0x10, 0xe6, 0x8f, 0x59, 0xf8, 0x05, 0x7a, 0x81, 0x03, 0xa7, 0xb8, 0xe1, 0x84, 0xd4, };

    // Generating IV:
    uint8_t iv[]  = { 0xf8, 0x86, 0x15, 0x9f, 0x1f, 0xfb, 0xc4, 0x56, 0xc5, 0xfa, 0x76, 0x8f, 0x86, 0x5e, 0x68, 0x24, };

    // Encrypted Shellcode:
    uint8_t shellcode[] = { 0x72, 0x4c, 0x44, 0x6c, 0x46, 0x2c, 0x81, 0x61, 0x59, 0x75, 0x3a, 0x40, 0x48, 0x05, 0xc4, 0x3f, 0x59, 0x6d, 0xc4, 0xd9, 0xe4, 0x04, 0x22, 0xfd, 0xa5, 0x1f, 0xd1, 0x60, 0x3a, 0xb9, 0x14, 0x3f, };
    
    
    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, shellcode, sizeof(shellcode));

    printf("Decrypted Shellcode:\n");

    for (i = 0; i < sizeof shellcode; i ++)
    {
        printf("\\x%02x", shellcode[i]);
    }
    printf("\n");
}

int main(void)
{
    decrypt();
}
```

Compiled and run with:
```bash
gcc -m32 Decryptor.c aes.c -o decryptor
./decryptor
```

It outputs the original shellcode (padded with nops: \x90):
```text
\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80\x90\x90     
```

And that's it, my failed experimentation with getting a null free, self decrypting shellcode and some updates that enable dynamic IV/Key generation for each run of the Cryptor program.

It's been fun.

# Certification Requirements

This blog post has been created for completing the requirements of the SecurityTube/PentesterAcademy [x86 Assembly Language and Shellcoding on Linux (SLAE)](https://www.pentesteracademy.com/course?id=3) certification:

Student ID: PA-29350
