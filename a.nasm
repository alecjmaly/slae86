mov dword [esp-4], 0x776f6461
mov dword [esp-8], 0x68732f2f      
mov dword [esp-12], 0x6374652f     
sub esp, 12
mov ebx,esp


push 0x776f6461
push 0x68732f2f       
push 0x6374652f      
mov ebx,esp

