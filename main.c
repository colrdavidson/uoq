#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define fatal(...) do { printf(__VA_ARGS__); exit(1); } while(0);

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

char *get_next_token(char *buf, char *end, int *size) {
    char *token;

    while (buf < end) {
        if (is_digit(*buf)) {
            token = buf;
            while (is_digit(*token)) {
                token++;
            }
            int token_size = token - buf;

            *size = token_size;
            return buf;
        } else if (is_char(*buf)) {
            char *token = buf;
            while (is_char(*token)) {
                token++;
            }
            int token_size = token - buf;

            *size = token_size;
            return buf;
        } else if (*buf == ';' || *buf == '(' || 
                   *buf == ')' || *buf == '{' || *buf == '}') {

            *size = 1;
            return buf;
        }

        buf++;
    }
    
    *size = 0;
    return NULL;
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

    int line_num = 1;
    int line_off = 0;

    int size;
    char *file_ptr = file_buf;
    char *file_end = file_buf + file_size;
    while (file_ptr < file_end) {
        line_off++;
        if (*file_ptr == '\n') {
            line_num++;
            line_off = 1;
        }

        char *token = get_next_token(file_ptr, file_end, &size);
        if (!size) break;

        printf("token: %.*s\n", size, token);
        file_ptr = token + size;

        if (!memcmp(token, "return", size)) {
            printf("Found keyword return!\n");
        }

        if (!memcmp(token, "int", size)) {
            printf("Found token int!\n");
        }
    }
}
