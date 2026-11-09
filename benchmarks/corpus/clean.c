/*
 * CodeShield benchmark corpus - the control group.
 *
 * This file contains no planted defect.  Every finding reported here is a
 * false positive, so the benchmark uses it to measure the precision of the
 * tool on code that follows the conventions the rules promote.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ITEMS_MAX 32
#define NAME_MAX 24

typedef struct
{
    int  identifier;
    char name[NAME_MAX];
} Entry;

static int  entry_count;
static Entry entries[ITEMS_MAX];

int entry_is_valid(const Entry *entry)
{
    if (entry == NULL) {
        return 0;
    }
    if (entry->identifier < 0) {
        return 0;
    }
    return 1;
}

void entries_clear(void)
{
    int index;

    for (index = 0; index < ITEMS_MAX; index++) {
        entries[index].identifier = 0;
        entries[index].name[0] = '\0';
    }
    entry_count = 0;
}

int entries_add(int identifier, const char *name)
{
    Entry candidate;

    if (entry_count >= ITEMS_MAX) {
        return -1;
    }
    if (name == NULL) {
        return -1;
    }
    candidate.identifier = identifier;
    strncpy(candidate.name, name, sizeof(candidate.name) - 1);
    candidate.name[sizeof(candidate.name) - 1] = '\0';
    entries[entry_count] = candidate;
    entry_count++;
    return 0;
}

const Entry *entries_find(int identifier)
{
    int index;

    for (index = 0; index < entry_count; index++) {
        if (entries[index].identifier == identifier) {
            return &entries[index];
        }
    }
    return NULL;
}

int entries_count(void)
{
    return entry_count;
}

static int entries_capacity(void)
{
    return ITEMS_MAX;
}

int entries_has_room(void)
{
    return entry_count < entries_capacity();
}

void entries_print(const Entry *entry)
{
    if (!entry_is_valid(entry)) {
        return;
    }
    printf("%d %s\n", entry->identifier, entry->name);
}
