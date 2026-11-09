#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

typedef enum {
    STATE_IDLE = 0,
    STATE_RUNNING = 1,
    STATE_DONE = 2
} State;

typedef struct Node {
    int   value;
    struct Node *next;
} Node;

typedef int (*CompareFn)(int, int);

static int counter = 0;
static const char *const greeting = "hello";

int compare_ints(int a, int b)
{
    return (a > b) ? a - b : b - a;
}

int sum_array(const int *values, int count)
{
    int total = 0;
    int i;

    for (i = 0; i < count; i++) {
        total += values[i];
    }
    return total;
}

int classify(State state)
{
    switch (state) {
    case STATE_IDLE:
        return 0;
    case STATE_RUNNING:
        return 1;
    case STATE_DONE:
    default:
        return -1;
    }
}

int risky_division(int a, int b)
{
    int result = 0;

    if (b != 0) {
        result = a / b;
    } else {
        result = -1;
    }
    return result;
}

int loops(int limit)
{
    int total = 0;
    int i = 0;

    while (i < limit) {
        if (i % 2 == 0) {
            total += i;
        } else {
            total -= i;
        }
        i++;
    }

    do {
        total++;
    } while (total < 100);

    for (i = 0; i < 10; i++) {
        if (i == 5) {
            continue;
        }
        if (i == 8) {
            break;
        }
        total += i;
    }
    return total;
}

Node *build_list(int count)
{
    Node *head = NULL;
    int i;

    for (i = 0; i < count; i++) {
        Node *node = (Node *)malloc(sizeof(Node));
        if (node == NULL) {
            return NULL;
        }
        node->value = i;
        node->next = head;
        head = node;
    }
    return head;
}

int list_length(Node *head)
{
    int length = 0;

    while (head != NULL) {
        length++;
        head = head->next;
    }
    return length;
}

void free_list(Node *head)
{
    while (head != NULL) {
        Node *next = head->next;
        free(head);
        head = next;
    }
}

int apply(CompareFn fn, int a, int b)
{
    return fn(a, b);
}

int main(void)
{
    int values[4];
    values[0] = 1;
    values[1] = 2;
    values[2] = 3;
    values[3] = 4;

    printf("%s %d\n", greeting, sum_array(values, ARRAY_SIZE(values)));
    printf("%d\n", classify(STATE_RUNNING));
    printf("%d\n", risky_division(10, 2));
    printf("%d\n", loops(5));
    printf("%d\n", apply(compare_ints, 3, 9));

    {
        Node *list = build_list(3);
        printf("%d\n", list_length(list));
        free_list(list);
    }
    return counter;
}
