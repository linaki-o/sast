#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_NAME 64
#define SAFE_ADD(a, b) ((a) + (b))

typedef struct {
    char name[MAX_NAME];
    int  age;
} User;

enum Status {
    STATUS_OK = 0,
    STATUS_FAIL = 1
};

static int counter = 0;

int compute(int a, int b, int *out)
{
    int result = 0;

    if (out == NULL) {
        return -1;
    }

    if (a > 0 && b > 0) {
        result = SAFE_ADD(a, b);
    } else if (a < 0) {
        result = 0;
    } else {
        result = a;
    }

    *out = result;
    counter++;
    return result;
}

void copy_name(char *dst, const char *src)
{
    strcpy(dst, src);
}

char *make_greeting(const char *name)
{
    static char buffer[MAX_NAME];
    snprintf(buffer, sizeof(buffer), "Hello, %s!", name);
    return buffer;
}

void process_users(User *users, int count)
{
    int i;
    for (i = 0; i < count; i++) {
        char name_buf[MAX_NAME];
        copy_name(name_buf, users[i].name);
        printf("%s\n", name_buf);
    }
}

int divide(int a, int b)
{
    if (b == 0) {
        return 0;
    }
    return a / b;
}
