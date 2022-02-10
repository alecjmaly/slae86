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


## Introduction

This is my collection of projects to satisfy the requirements for the [x86 Assembly Language and Shellcoding on Linux (SLAE)](https://www.pentesteracademy.com/course?id=3) course.



# Assignments

## [Assignment 1](./project1)

- Create a Shell_Bind_TCP shellcode
- Binds to a port
- Execs Shell on incoming connection
- Port number should be easily configurable

## [Assignment 2](./project2)

- Create a Shell_Reverse_TCP shellcode
- Reverse connects to configured IP and Port
- Execs shell on successful connection
- IP and Port should be easily configurable

## [Assignment 3](./project3)

- Study about the Egg Hunter shellcode
- Create a working demo of the Egghunter
- Should be configurable for different payloads

## [Assignment 4](./project4)

- Create a custom encoding scheme like the “Insertion Encoder” we showed you
- PoC with using execve-stack as the shellcode to encode with your schema and execute

## [Assignment 5](./project5)

- Use GDB/Ndisasm/Libemu to dissect the funcSonality of the shellcode
- Present your analysis

**Analysis**:

1. [readfile](https://github.com/alecmaly/slae/blob/master/slae86/project5/1_readfile.md)
2. [adduser](https://github.com/alecmaly/slae/blob/master/slae86/project5/2_adduser.md)
3. [chmod](https://github.com/alecmaly/slae/blob/master/slae86/project5/3_chmod.md)

## [Assignment 6](./project6)

- Take up 3 shellcodes from Shell-Storm and create polymorphic versions of them to beat pattern matching
- The polymorphic versions cannot be larger 150% of the exisSng shellcode
- Bonus points for making it shorter in length than original

### Shellstorm

Both payloads #1 and #3 are shorter in length than the original.

1. [read_passwd](https://github.com/alecmaly/slae/blob/master/slae86/project6/1_read_passwd.md)
2. [execve](https://github.com/alecmaly/slae/blob/master/slae86/project6/2_execve.md)
3. [chmod_shadow](https://github.com/alecmaly/slae/blob/master/slae86/project6/3_chmod_shadow.md)
    
### msfvenom

I also analyzed a couple msfvenom payloads as well for fun:

1. [read_file](https://github.com/alecmaly/slae/blob/master/slae86/project6/msfvenom-1_readfile.md)
2. [adduser](https://github.com/alecmaly/slae/blob/master/slae86/project6/msfvenom-2_adduser.md)
3. [chmod](https://github.com/alecmaly/slae/blob/master/slae86/project6/msfvenom-3_chmod.md)


## [Assignment 7](./project7)

- Create a custom crypter like the one shown in the “crypters” video
- Free to use any existing encrypSon schema
- Can use any programming language

