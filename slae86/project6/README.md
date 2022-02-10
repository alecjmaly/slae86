## Assignment 6
Take up 3 shellcodes from Shell-Storm and create polymorphic versions of them to beat pattern matching

- The polymorphic versions cannot be larger 
150% of the exisSng shellcode
- Bonus points for making it shorter in length 
than original



# Shellstorm

My polymorphic code for #1 and #2 are shorter in length than the original.<br>
#3 is also shorter, however, the original is meant to be obfuscated and I removed that obfuscation, so it doesn't really count.

1. [read_passwd](./1_read_passwd.md)
2. [execve](./2_execve.md)
3. [chmod_shadow](./3_chmod_shadow.md)


Additionally, I also analyzed some msfvenom payloads as well:

# MSFVenom

Both payloads #1 and #3 are shorter in length than the original.

1. [msfvenom-readfile](./msfvenom-1_readfile.md)
2. [msfvenom-adduser](./msfvenom-2_adduser.md)
3. [msfvenom-chmod](./msfvenom-3_chmod.md)



# Certification Requirements

This blog post has been created for completing the requirements of the SecurityTube/PentesterAcademy [x86 Assembly Language and Shellcoding on Linux (SLAE)](https://www.pentesteracademy.com/course?id=3) certification:

Student ID: SLAE-alecjmaly


