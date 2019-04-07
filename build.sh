mkdir -p build bin
clang -O3 -Wall -Werror -fno-strict-aliasing -o bin/uoq src/main.c
