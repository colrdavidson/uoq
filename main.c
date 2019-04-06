#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define fatal(...) do { printf("\033[0;31m"); printf(__VA_ARGS__); printf("\033[0m"); exit(1); } while(0);

void *emalloc(size_t sz) {
    void *ptr = malloc(sz);
    if (!ptr)
        fatal("Out of memory!\n");

    return ptr;
}

int is_char(char c) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
        return 1;
    return 0;
}

int is_digit(char c) {
    if (c >= '0' && c <= '9')
        return 1;
    return 0;
}

int strtoi(char *s, int sz) {
    int ret = 0;
    int shift = 1;
    for (int i = sz - 1; i >= 0; i--) {
        ret += (s[i] - '0') * shift;
        shift *= 10;
    }

    return ret;
}

char *get_next_token(char *buf, char *end, int *size) {
    char *token = NULL;
    *size = 0;

    while (buf < end) {
        if (is_digit(*buf)) {
            token = buf;
            while (is_digit(*token)) {
                token++;
            }

            *size = token - buf;
            token = buf;
            goto exit;
        } else if (is_char(*buf)) {
            token = buf;
            while (is_char(*token)) {
                token++;
            }

            *size = token - buf;
            token = buf;
            goto exit;
        } else if (*buf == ';' || *buf == '(' || 
                   *buf == ')' || *buf == '{' || *buf == '}') {
            token = buf;
            *size = 1;
            goto exit;
        }

        buf++;
    }
    
exit:
//    if (*size)
//        printf("token: %.*s\n", *size, token); 

    return token;
}

int main() {
    int fd = open("test.c", O_RDONLY, 0);
    if (fd < 0)
        fatal("Cannot open file!\n");

    off_t file_size = lseek(fd, 0, SEEK_END);
    if (file_size == -1)
        fatal("seek to end of file failed?\n");

    if (lseek(fd, 0, SEEK_SET) == -1)
        fatal("seek to beginning of file failed?\n");

    char *file_buf = emalloc(file_size + 1);
    file_buf[file_size] = '\0';

    size_t n = read(fd, file_buf, file_size);
    if (n != file_size)
        fatal("Failed to read the whole file! %zu != %zu\n", n, file_size);

    int size;
    char *file_ptr = file_buf;
    char *file_end = file_buf + file_size;
    while (file_ptr < file_end) {

        char *token = get_next_token(file_ptr, file_end, &size);
        if (!size) break;

        if (!memcmp(token, "int", size)) {
            file_ptr = token + size;
            token = get_next_token(file_ptr, file_end, &size);
            if (!size) fatal("Expected function name!\n");

            char *func_name = token;
            int func_name_sz = size;
            printf("found function %.*s\n", func_name_sz, func_name);

            file_ptr = token + size;
            token = get_next_token(file_ptr, file_end, &size);
            if (!size || *token != '(')
                fatal("Expected (\n");

            file_ptr = token + size;
            while (file_ptr < file_end) {
                token = get_next_token(file_ptr, file_end, &size);
                if (!size) fatal("Expected )\n");
                if (*token == ')') break;
                file_ptr = token + size;
            }

            file_ptr = token + size;
            token = get_next_token(file_ptr, file_end, &size);
            if (!size || *token != '{')
                fatal("Expected {\n");

            // Function Body
            file_ptr = token + size;
            while (file_ptr < file_end) {
                token = get_next_token(file_ptr, file_end, &size);
                if (!size) fatal("Expected }\n");
                if (*token == '}') break;
                file_ptr = token + size;

                if (!memcmp(token, "return", size)) {
                    token = get_next_token(file_ptr, file_end, &size);
                    if (!size) fatal("Expected constant!\n");
                    file_ptr = token + size;

                    printf("returning %d\n", strtoi(token, size));
                }
            }
        }

        file_ptr = token + size;
    }
}
