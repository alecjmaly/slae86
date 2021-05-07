#!/bin/bash
# compiles .nasm to binary

nasm -F dwarf -g -F dwarf -f elf32 -o $1.o $1.nasm

# link binary
# if compiling on x64, add parameters in []
ld -m elf_i386 -o $1 $1.o 


rm $1.o 