# Project 2: TCP Reverse Shell

This assignment is similar to the previous of creating a bind shell, however, instead of opening a listening port it will connect back to the IP and port of our choosing upon execution of the shellcode. In Assignment 1 I went into great detail about how I get the syscall enumerator indices. In this assignment I will not go into such depth but rather focus on the shellcode itself.  

Create a Shell_Reverse_TCP shellcode
- Reverse connects to configured IP and Port 
- Execs shell on successful connection 

- IP and Port should be easily configurable



