#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

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
    struct ASTNode **children;
    int children_len;
    struct ASTNode *parent;
    Op op;
} ASTNode;

void *emalloc(size_t sz) {
    void *ptr = malloc(sz);
    if (!ptr)
        fatal("Out of memory!\n");

    return ptr;
}

void *ecalloc(size_t sz) {
    void *ptr = calloc(sz, 1);
    if (!ptr)
        fatal("Out of memory!\n");

    return ptr;
}

int is_char(char c) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c == '_'))
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
        if (!is_digit(s[i])) {
            errno = EINVAL;
            return 0;
        }
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
            while (is_char(*token) || is_digit(*token)) {
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

    int ret_val;

    ASTNode program = {0};
    program.type = Type_Program;
    program.children = ecalloc(sizeof(ASTNode *) * 10);

    int size;
    char *file_ptr = file_buf;
    char *file_end = file_buf + file_size;
    while (file_ptr <= file_end) {

        char *token = get_next_token(file_ptr, file_end, &size);
        if (!size) break;

        if (!memcmp(token, "int", size)) {
            file_ptr = token + size;
            token = get_next_token(file_ptr, file_end, &size);
            if (!size) fatal("Expected function name!\n");

            ASTNode *function = ecalloc(sizeof(ASTNode));
            function->type = Type_Function;
            function->children = ecalloc(sizeof(ASTNode *) * 10);
            function->parent = &program;
            function->name = token;
            function->name_sz = size;
            program.children[program.children_len++] = function;

            file_ptr = token + size;
            token = get_next_token(file_ptr, file_end, &size);
            if (!size || *token != '(')
                fatal("Expected (\n");

            // Function Params
            file_ptr = token + size;
            while (file_ptr <= file_end) {
                token = get_next_token(file_ptr, file_end, &size);
                file_ptr = token + size;

                if (!size) fatal("Expected )\n");
                if (*token == ')') break;
            }

            token = get_next_token(file_ptr, file_end, &size);
            if (!size || *token != '{')
                fatal("Expected {\n");

            // Function Body
            file_ptr = token + size;
            while (file_ptr <= file_end) {
                token = get_next_token(file_ptr, file_end, &size);
                file_ptr = token + size;

                if (!size) fatal("Expected }\n");
                if (*token == '}') break;

                if (memcmp(token, "return", size))
                    fatal("Expected return!\n");

                ASTNode *statement = ecalloc(sizeof(ASTNode));
                statement->type = Type_Statement;
                statement->children = ecalloc(sizeof(ASTNode *) * 10);
                statement->parent = function;
                statement->op = Op_Return;
                function->children[function->children_len++] = statement;

                token = get_next_token(file_ptr, file_end, &size);
                if (!size) fatal("Expected constant!\n");
                file_ptr = token + size;

                errno = 0;
                ret_val = strtoi(token, size);
                if (!ret_val && errno)
                    fatal("Invalid return value!\n");

                ASTNode *literal = ecalloc(sizeof(ASTNode));
                literal->type = Type_Literal;
                literal->parent = statement;
                literal->val = ret_val;
                statement->children[statement->children_len++] = literal;

                token = get_next_token(file_ptr, file_end, &size);
                if (!size || *token != ';') fatal("Expected ;\n");
                file_ptr = token + size;
            }
        }

        file_ptr = token + size;
    }

    char out_buf[1500] = {0};

    n = sprintf(out_buf, "bits 64\n"
                         "section .text\n\n");

    int i = 0;
    int stack_depth = 0;
    ASTNode *stack[100] = {0};

    ASTNode *node = &program;
    for (i = node->children_len - 1; i >= 0; i--) {
        stack[stack_depth++] = node->children[i];
    }

    while (stack_depth) {
        node = stack[--stack_depth];

        switch (node->type) {
            case Type_Statement: {
                if (node->op == Op_Return) { 
                    if (!memcmp("main", node->parent->name, node->parent->name_sz)) {
                        n += sprintf(out_buf + n, "    mov rax, 60\n" 
                                                  "    mov rdi, %d\n" 
                                                  "    syscall\n",
                                                  node->children[0]->val);
                    } else {
                        n += sprintf(out_buf + n, "    mov rax, %d\n" 
                                                  "    ret\n\n", 
                                                  node->children[0]->val);
                    }
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
            case Type_Literal: {

            } break;
            default: {
                fatal("node type %d not handled yet!\n", node->type);
            }
        }

        for (i = node->children_len - 1; i >= 0; i--) {
            stack[stack_depth++] = node->children[i];
        }
    }

    write(out_fd, out_buf, n);
}
