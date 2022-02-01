# slae86

Project files for SLAE x86 exercises


## Important Information

This information is relavent to all assignments.

### x86 Calling Convention

This is the calling convention for system calls (syscall()) in x86 linux and will be referenced throughout my assignments.

| Register | Argument (info) |
| ------ | ------ |
| EAX | system call numer ( + return data ) |
| EBX | 1st |
| ECX | 2nd |
| EDX | 3rd |
| ESI | 4th |
| EDI | 5th |
| EBP | 6th |


## Assignment 1 
Create a Shell_Bind_TCP shellcode
- Binds to a port  
- Execs Shell on incoming connection 

- Port number should be easily configurable

## Assignment 2
Create a Shell_Reverse_TCP shellcode
- Reverse connects to configured IP and Port 
- Execs shell on successful connection 
- IP and Port should be easily configurable

## Assignment 3 
- Study about the Egg Hunter shellcode
- Create a working demo of the Egghunter
- Should be configurable for different payloads

## Assignment 4 
- Create a custom encoding scheme like the 
“InserSon Encoder” we showed you 
- PoC with using execve-stack as the shellcode
to encode with your schema and execute 

## Assignment 5
Take up at least 3 shellcode samples created 
using Msfpayload for linux/x86  
- Use GDB/Ndisasm/Libemu to dissect the 
funcSonality of the shellcode
- Present your analysis

## Assignment 6
Take up 3 shellcodes from Shell-Storm and 
create polymorphic versions of them to beat 
paLern matching 
- The polymorphic versions cannot be larger 
150% of the exisSng shellcode
- Bonus points for making it shorter in length 
than original

## Assignment 7
Create a custom crypter like the one shown in 
the “crypters” video 
- Free to use any exisSng encrypSon schema 
- Can use any programming language