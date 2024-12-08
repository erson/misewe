#include "rate_limit.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stddef.h>

#define MAX_CLIENTS 10000

/* Client tracking structure */
typedef struct {
    char ip[16];
    unsigned int count;
    time_t window_start;
} client_entry_t;

/* Rate limiter context */
struct rate_limiter {
    unsigned int max_requests;
    unsigned int window_seconds;
    client_entry_t *clients;
    size_t client_count;
    pthread_mutex_t lock;
};

/* Create rate limiter */
rate_limiter_t *rate_limiter_create(unsigned int max_requests,
                                   unsigned int window_seconds) {
    rate_limiter_t *limiter = calloc(1, sizeof(*limiter));
    if (!limiter) return NULL;

    limiter->max_requests = max_requests;
    limiter->window_seconds = window_seconds;
    limiter->clients = calloc(MAX_CLIENTS, sizeof(client_entry_t));

    if (!limiter->clients) {
        free(limiter);
        return NULL;
    }

    pthread_mutex_init(&limiter->lock, NULL);
    return limiter;
}

/* Clean up rate limiter */
void rate_limiter_destroy(rate_limiter_t *limiter) {
    if (limiter) {
        pthread_mutex_destroy(&limiter->lock);
        free(limiter->clients);
        free(limiter);
    }
}

/* Check if request is allowed */
bool rate_limiter_check(rate_limiter_t *limiter, const char *ip) {
    bool allowed = true;
    time_t now = time(NULL);

    pthread_mutex_lock(&limiter->lock);

    /* Find or create client entry */
    client_entry_t *client = NULL;
    for (size_t i = 0; i < limiter->client_count; i++) {
        if (strcmp(limiter->clients[i].ip, ip) == 0) {
            client = &limiter->clients[i];
            break;
        }
    }

    if (!client && limiter->client_count < MAX_CLIENTS) {
        client = &limiter->clients[limiter->client_count++];
        strncpy(client->ip, ip, sizeof(client->ip) - 1);
        client->window_start = now;
    }

    if (client) {
        /* Reset window if needed */
        if (now - client->window_start >= limiter->window_seconds) {
            client->count = 0;
            client->window_start = now;
        }

        /* Check rate limit */
        if (client->count >= limiter->max_requests) {
            allowed = false;
        } else {
            client->count++;
        }
    }

    pthread_mutex_unlock(&limiter->lock);
    return allowed;
}