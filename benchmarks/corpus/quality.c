/*
 * CodeShield benchmark corpus - code quality defects.
 *
 * The clean functions are deliberately written in the style the tool
 * promotes, so that the false positive rate is measured against code that
 * a careful developer would have produced.
 */

#include <stdio.h>
#include <stdlib.h>

#define READ_BUFFER_SIZE 512
#define WRITE_ATTEMPTS 3
#define THRESHOLD_PERCENT 75

typedef struct
{
    int    id;
    char   label[32];
    double ratio;
} Measurement;

typedef struct
{
    Measurement *items;
    int          count;
    int          capacity;
} MeasurementList;

/* ------------------------------------------------------------------ */
/* Clean code                                                          */
/* ------------------------------------------------------------------ */

int measurement_is_valid(const Measurement *measurement)
{
    if (measurement == NULL) {
        return 0;
    }
    if (measurement->id < 0) {
        return 0;
    }
    return 1;
}

void measurement_list_init(MeasurementList *list)
{
    if (list == NULL) {
        return;
    }
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

int measurement_list_append(MeasurementList *list, const Measurement *item)
{
    if ((list == NULL) || (item == NULL)) {
        return -1;
    }
    if (list->count == list->capacity) {
        int new_capacity = (list->capacity == 0) ? 8 : (list->capacity * 2);
        Measurement *resized = realloc(list->items, (size_t)new_capacity * sizeof(Measurement));

        if (resized == NULL) {
            return -1;
        }
        list->items = resized;
        list->capacity = new_capacity;
    }
    list->items[list->count] = *item;
    list->count++;
    return 0;
}

double measurement_list_average(const MeasurementList *list)
{
    double total = 0.0;
    int    index;

    if ((list == NULL) || (list->count == 0)) {
        return 0.0;
    }
    for (index = 0; index < list->count; index++) {
        total += list->items[index].ratio;
    }
    return total / (double)list->count;
}

void measurement_list_clear(MeasurementList *list)
{
    if (list == NULL) {
        return;
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static int clamp_percent(int percent) /* sast:expect QLT-UNUSED-003 */
{
    if (percent < 0) {
        return 0;
    }
    if (percent > 100) {
        return 100;
    }
    return percent;
}

/* ------------------------------------------------------------------ */
/* Planted defects                                                     */
/* ------------------------------------------------------------------ */

void unused_local(void)
{
    int scratch = 42; /* sast:expect QLT-UNUSED-001 */
}

void unused_parameter(int used, int ignored) /* sast:expect QLT-UNUSED-002 */
{
    (void)used;
}

int shadowed_name(void)
{
    int value = 1;

    {
        int value = 2; /* sast:expect QLT-SHADOW-001 */
        return value;
    }
}

void use_goto(int limit)
{
    int index = 0;

loop:
    if (index < limit) {
        index++;
        goto loop; /* sast:expect QLT-GOTO-001 */
    }
}

void missing_braces(int flag)
{
    if (flag > 0) /* sast:expect QLT-BRACE-001 */
        flag = 1;
    else
        flag = 0;
}

int compare_against_null(void *pointer)
{
    if (pointer == 0) { /* sast:expect QLT-NULL-002 */
        return 1;
    }
    return 0;
}

void assign_in_condition(int value)
{
    if ((value = compute_secret(value))) { /* sast:expect QLT-ASSIGN-001 */
        return;
    }
}

void magic_threshold(int percent)
{
    if (percent > 75) { /* sast:expect QLT-MAGIC-001 */
        percent = 75;
    }
}

int complex_function(int a, int b, int c, int d, int e, int f)
{
    int result = 0;

    if (a > 0 && b > 0 && c > 0) {
        result += 1;
    }
    if (a > 1 && b > 1 && c > 1) {
        result += 2;
    }
    if (a > 2 && b > 2 && c > 2) {
        result += 3;
    }
    if (a > 3 && b > 3 && c > 3) {
        result += 4;
    }
    if (d > 0 && e > 0 && f > 0) {
        result += 5;
    }
    if (a + b + c + d + e + f > 100) {
        result += 6;
    }
    return result;
}
