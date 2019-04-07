#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define fatal(...) do { printf("\033[0;31m"); printf(__VA_ARGS__); printf("\033[0m"); exit(1); } while(0);

typedef enum {
    Type_Program,
    Type_Function,
    Type_Statement,
    Type_Literal
} Type;

typedef enum {
    Op_Return,
    Op_Add
} Op;

typedef struct ASTNode {
    Type type;
    int val;
    char *name;
    int name_sz;
    struct ASTNode *child;
    struct ASTNode *parent;
    Op op;
} ASTNode;

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

int main(int argc, char *argv[]) {
    if (argc != 3)
        fatal("uoq: should be %s <in_file> <out_file>\n", argv[0]);

    int in_fd = open(argv[1], O_RDONLY);
    if (in_fd < 0)
        fatal("Cannot open input file!\n");

    int out_fd = open(argv[2], O_WRONLY | O_TRUNC | O_CREAT, 0666);
    if (out_fd < 0)
        fatal("Cannot open output file!\n");

    off_t file_size = lseek(in_fd, 0, SEEK_END);
    if (file_size == -1)
        fatal("seek to end of file failed?\n");

    if (lseek(in_fd, 0, SEEK_SET) == -1)
        fatal("seek to beginning of file failed?\n");

    char *file_buf = emalloc(file_size + 1);
    file_buf[file_size] = '\0';

    size_t n = read(in_fd, file_buf, file_size);
    if (n != file_size)
        fatal("Failed to read the whole file! %zu != %zu\n", n, file_size);

    char *func_name;
    int func_name_sz;
    int ret_val;

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

            func_name = token;
            func_name_sz = size;

            file_ptr = token + size;
            token = get_next_token(file_ptr, file_end, &size);
            if (!size || *token != '(')
                fatal("Expected (\n");

            // Function Params
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

                if (memcmp(token, "return", size))
                    fatal("Expected return!\n");

                token = get_next_token(file_ptr, file_end, &size);
                if (!size) fatal("Expected constant!\n");
                file_ptr = token + size;
                ret_val = strtoi(token, size);

                token = get_next_token(file_ptr, file_end, &size);
                if (!size || *token != ';') fatal("Expected ;\n");
                file_ptr = token + size;
            }
        }

        file_ptr = token + size;
    }

    ASTNode literal, statement, function, program;

    program.type = Type_Program;
    program.child = &function;
    program.parent = NULL;

    function.type = Type_Function;
    function.child = &statement;
    function.parent = &program;
    function.name = func_name;
    function.name_sz = func_name_sz;

    statement.type = Type_Statement;
    statement.child = &literal;
    statement.parent = &function;
    statement.op = Op_Return;

    literal.type = Type_Literal;
    literal.child = NULL;
    literal.parent = &statement;
    literal.val = ret_val; 

    n = 0;
    char out_buf[1500] = {0};

    ASTNode *node = &program;
    while (node) {
        switch (node->type) {
            case Type_Statement: {
                if (node->op == Op_Return) {
                    n += sprintf(out_buf + n, "    mov rax, 60\n" 
                                              "    mov rdi, %d\n" 
                                              "    syscall\n",
                                              node->child->val);
                } else {
                    fatal("Op type %d not handled yet!\n", node->op);
                }
            } break;
            case Type_Function: {
                if (!memcmp("main", node->name, node->name_sz)) {
                    n += sprintf(out_buf + n, "    global _start\n"
                                              "_start:\n");
                } else {
                    n += sprintf(out_buf + n, "    global _%.*s\n"
                                              "_%.*s:\n", 
                                              node->name_sz, node->name,  
                                              node->name_sz, node->name);  
                }
            } break;
            case Type_Program: {
                n += sprintf(out_buf + n, "bits 64\n"
                                          "section .text\n");
            } break;
            case Type_Literal: {

            } break;
            default: {
                fatal("node type %d not handled yet!\n", node->type);
            }
        }

        node = node->child;
    }

    write(out_fd, out_buf, n);
}
