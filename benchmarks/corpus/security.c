/*
 * CodeShield benchmark corpus - security defects.
 *
 * Every planted defect carries a "sast:expect <RULE-ID>" annotation on the
 * line that the finding must be reported at.  The annotation is part of the
 * ground truth: the benchmark harness turns it into an expectation and
 * checks the tool against it.
 *
 * The file also contains a substantial amount of clean code so that the
 * false positive rate is measured on realistic surroundings.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HOSTNAME_MAX 64
#define RESPONSE_MAX 256
#define RETRY_LIMIT 3

typedef struct
{
    char  host[HOSTNAME_MAX];
    int   port;
    int   secure;
} Endpoint;

typedef struct
{
    char   name[32];
    int    identifier;
    double balance;
} Account;

static int   request_counter;
static char  session_token[RESPONSE_MAX];

static Endpoint primary_endpoint = { "localhost", 8080, 1 };

/* ------------------------------------------------------------------ */
/* Clean helpers                                                       */
/* ------------------------------------------------------------------ */

int endpoint_port(const Endpoint *endpoint)
{
    if (endpoint == NULL) {
        return 0;
    }
    return endpoint->port;
}

const char *endpoint_host(const Endpoint *endpoint)
{
    if (endpoint == NULL) {
        return "";
    }
    return endpoint->host;
}

void account_reset(Account *account)
{
    if (account == NULL) {
        return;
    }
    account->identifier = 0;
    account->balance = 0.0;
    memset(account->name, 0, sizeof(account->name));
}

int account_deposit(Account *account, double amount)
{
    if ((account == NULL) || (amount <= 0.0)) {
        return -1;
    }
    account->balance += amount;
    return 0;
}

double account_total(const Account *accounts, int count)
{
    double total = 0.0;
    int    index;

    for (index = 0; index < count; index++) {
        total += accounts[index].balance;
    }
    return total;
}

static int retry_count(void) /* sast:expect QLT-UNUSED-003 */
{
    request_counter++;
    if (request_counter >= RETRY_LIMIT) {
        request_counter = 0;
    }
    return request_counter;
}

/* ------------------------------------------------------------------ */
/* Planted defects                                                     */
/* ------------------------------------------------------------------ */

void copy_host(Endpoint *endpoint, const char *source)
{
    char buffer[HOSTNAME_MAX];

    strcpy(buffer, source); /* sast:expect SEC-BUF-001 */
    strncpy(endpoint->host, buffer, HOSTNAME_MAX);
}

void build_response(char *out, const char *user_input)
{
    char buffer[64];

    sprintf(buffer, "status=%s", user_input); /* sast:expect SEC-BUF-003 */
    strcpy(out, buffer);
}

void run_command(const char *argument)
{
    system(argument); /* sast:expect SEC-CMD-001 */
}

void log_message(const char *user_supplied)
{
    printf(user_supplied); /* sast:expect SEC-FMT-001 */
}

void store_credentials(void)
{
    const char *password = "hunter2"; /* sast:expect SEC-CRED-001 */
    strncpy(session_token, password, sizeof(session_token) - 1);
}

void allocate_buffer(size_t count)
{
    char *memory = malloc(count); /* sast:expect SEC-NULL-003 */

    memset(memory, 0, count);
    free(memory);
}

void release_twice(void)
{
    char *memory = malloc(16);

    if (memory == NULL) {
        return;
    }
    free(memory);
    free(memory); /* sast:expect SEC-USE-002 */
}

void use_after_release(void)
{
    char *memory = malloc(16);

    if (memory == NULL) {
        return;
    }
    memset(memory, 0, 16);
    free(memory);
    memset(memory, 0, 16); /* sast:expect SEC-USE-001 */
}

void copy_with_unchecked_size(const char *source)
{
    char   destination[16];
    size_t length = 32;

    memcpy(destination, source, length); /* sast:expect SEC-BUF-004 */
}

void truncate_without_check(char *destination)
{
    snprintf(destination, RESPONSE_MAX, "%s", "value"); /* sast:expect SEC-LEAK-001 */
}

int compute_secret(int seed)
{
    int secret = rand(); /* sast:expect SEC-RAND-001 */

    return secret ^ seed;
}

void weak_digest(const char *payload)
{
    unsigned char digest[20];

    MD5(payload, digest); /* sast:expect SEC-CRYPTO-001 */
}
