#!/bin/bash
# compiles .nasm to binary

nasm -F dwarf -g -F dwarf -f elf32 -o $1.o $1.asm

# link binary
# if compiling on x64, add parameters in []
# -N : make text section executable
# -z execstack : make stack executable
ld -m elf_i386 -z execstack -N -o $1 $1.o 


rm $1.o 