; Filename: test.nasm



global _start

section .text
_start:

	; print hello world using write syscall
	mov eax, 0x4
	mov ebx, 1
	mov ecx, message
	mov edx, mlen
	int 0x80 

	mov eax, 1
	mov ebx, 10   ; sys_exit syscall
	int 0x80

section .data
	
	message: db "Hello World!"
	mlen equ $-message
