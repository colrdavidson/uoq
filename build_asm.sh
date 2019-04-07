mkdir -p build bin
nasm -felf64 -o build/test.o test.asm
ld -o bin/test build/test.o
