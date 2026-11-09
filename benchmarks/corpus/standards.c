/*
 * CodeShield benchmark corpus - MISRA C:2012 violations.
 */

#include <stdlib.h>
#include <time.h>

#define CHANNEL_COUNT 8
#define TIMEOUT_MS 500

static unsigned int tick_counter;

unsigned int global_channel;
int           signed_channel;

/* ------------------------------------------------------------------ */
/* MISRA compliant code                                                */
/* ------------------------------------------------------------------ */

uint32_t checked_add(uint32_t left, uint32_t right)
{
    uint32_t sum = left + right;

    if (sum < left) {
        return UINT32_MAX;
    }
    return sum;
}

static void clear_state(void) /* sast:expect QLT-UNUSED-003 */
{
    tick_counter = 0U;
}

int read_channel(unsigned int index)
{
    if (index >= (unsigned int)CHANNEL_COUNT) {
        return -1;
    }
    return (int)global_channel + (int)index;
}

void set_channel(unsigned int index, int value)
{
    if (index >= (unsigned int)CHANNEL_COUNT) {
        return;
    }
    global_channel = (unsigned int)value;
}

/* ------------------------------------------------------------------ */
/* Planted violations                                                  */
/* ------------------------------------------------------------------ */

void missing_default(int selector) /* sast:expect MISRA-16-004 */
{
    switch (selector)
    {
    case 1:
        tick_counter++;
        break;
    case 2:
        tick_counter--;
        break;
    }
}

void default_in_the_middle(int selector) /* sast:expect MISRA-16-005 */
{
    switch (selector)
    {
    case 1:
        tick_counter++;
        break;
    default:
        tick_counter = 0U;
        break;
    case 2:
        tick_counter--;
        break;
    }
}

void single_exit(int value)
{
    if (value > 0)
    {
        tick_counter++;
        return;
    }
    tick_counter = 0U;
}

void unbraced_loop(int count)
{
    int index;

    for (index = 0; index < count; index++)
    {
        tick_counter++;
    }
}

void unbraced_branch(int value) /* sast:expect MISRA-15-007 */
{
    if (value > 0)
        tick_counter++;
    else
        tick_counter = 0U;
}

void comma_operator(int left, int right)
{
    int result = (left, right); /* sast:expect MISRA-12-003 */
    tick_counter = (unsigned int)result;
}

void signed_to_unsigned(int value)
{
    global_channel = (unsigned int)value;
    signed_channel = value;
}

void use_time_functions(void) /* sast:expect MISRA-21-010 */
{
    time_t now = time(NULL);

    tick_counter = (unsigned int)now;
}

void use_dynamic_memory(void) /* sast:expect MISRA-21-006 */
{
    int *memory = (int *)malloc(sizeof(int) * CHANNEL_COUNT);

    if (memory != NULL)
    {
        memory[0] = 0;
        free(memory);
    }
}
