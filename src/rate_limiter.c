#include "rate_limiter.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define MAX_CLIENTS 10000

/* Client tracking structure */
typedef struct {
    char ip[16];
    time_t *requests;
    size_t count;
    time_t window_start;
    bool blocked;
} client_track_t;

/* Rate limiter context */
struct rate_limiter {
    rate_limit_config_t config;
    client_track_t *clients;
    size_t client_count;
    pthread_mutex_t lock;
};

/* Create rate limiter */
rate_limiter_t *rate_limiter_create(const rate_limit_config_t *config) {
    rate_limiter_t *limiter = calloc(1, sizeof(*limiter));
    if (!limiter) return NULL;

    /* Copy configuration */
    limiter->config = *config;

    /* Allocate client tracking array */
    limiter->clients = calloc(MAX_CLIENTS, sizeof(client_track_t));
    if (!limiter->clients) {
        free(limiter);
        return NULL;
    }

    /* Initialize mutex */
    if (pthread_mutex_init(&limiter->lock, NULL) != 0) {
        free(limiter->clients);
        free(limiter);
        return NULL;
    }

    return limiter;
}

/* Find or create client entry */
static client_track_t *get_client(rate_limiter_t *limiter, const char *ip) {
    /* Look for existing client */
    for (size_t i = 0; i < limiter->client_count; i++) {
        if (strcmp(limiter->clients[i].ip, ip) == 0) {
            return &limiter->clients[i];
        }
    }

    /* Add new client if space available */
    if (limiter->client_count < MAX_CLIENTS) {
        client_track_t *client = &limiter->clients[limiter->client_count++];
        strncpy(client->ip, ip, sizeof(client->ip) - 1);
        client->requests = calloc(limiter->config.burst_size, sizeof(time_t));
        client->window_start = time(NULL);
        return client;
    }

    return NULL;
}

/* Check if request should be allowed */
bool rate_limiter_check(rate_limiter_t *limiter, const char *ip) {
    bool allowed = true;
    time_t now = time(NULL);

    pthread_mutex_lock(&limiter->lock);

    client_track_t *client = get_client(limiter, ip);
    if (!client) {
        pthread_mutex_unlock(&limiter->lock);
        return false;
    }

    /* Check if client is blocked */
    if (client->blocked) {
        pthread_mutex_unlock(&limiter->lock);
        return false;
    }

    /* Reset window if needed */
    if (now - client->window_start >= limiter->config.window_seconds) {
        client->count = 0;
        client->window_start = now;
    }

    /* Check rate limit */
    if (client->count >= limiter->config.requests_per_second) {
        allowed = false;
        client->blocked = true;
        log_write(LOG_WARN, "Rate limit exceeded for IP: %s", ip);
    } else {
        client->requests[client->count++] = now;
    }

    pthread_mutex_unlock(&limiter->lock);
    return allowed;
}

/* Clean up rate limiter */
void rate_limiter_destroy(rate_limiter_t *limiter) {
    if (!limiter) return;

    pthread_mutex_lock(&limiter->lock);

    /* Free client request arrays */
    for (size_t i = 0; i < limiter->client_count; i++) {
        free(limiter->clients[i].requests);
    }

    free(limiter->clients);

    pthread_mutex_unlock(&limiter->lock);
    pthread_mutex_destroy(&limiter->lock);

    free(limiter);
}