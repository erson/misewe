#include "rate_limiter.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* Client tracking structure */
typedef struct {
    char ip[16];                /* Client IP address */
    time_t *timestamps;         /* Array of request timestamps */
    size_t count;              /* Number of requests in window */
    bool blocked;              /* Whether client is blocked */
    time_t block_expires;      /* When block expires */
} client_info_t;

/* Rate limiter context */
struct rate_limiter {
    rate_limit_config_t config;
    client_info_t *clients;
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
    limiter->clients = calloc(config->max_clients, sizeof(client_info_t));
    if (!limiter->clients) {
        free(limiter);
        return NULL;
    }

    /* Initialize each client's timestamp array */
    for (size_t i = 0; i < config->max_clients; i++) {
        limiter->clients[i].timestamps = calloc(config->max_requests,
                                              sizeof(time_t));
        if (!limiter->clients[i].timestamps) {
            for (size_t j = 0; j < i; j++) {
                free(limiter->clients[j].timestamps);
            }
            free(limiter->clients);
            free(limiter);
            return NULL;
        }
    }

    /* Initialize mutex */
    if (pthread_mutex_init(&limiter->lock, NULL) != 0) {
        for (size_t i = 0; i < config->max_clients; i++) {
            free(limiter->clients[i].timestamps);
        }
        free(limiter->clients);
        free(limiter);
        return NULL;
    }

    return limiter;
}

/* Find or create client entry */
static client_info_t *get_client(rate_limiter_t *limiter, const char *ip) {
    /* First, try to find existing client */
    for (size_t i = 0; i < limiter->client_count; i++) {
        if (strcmp(limiter->clients[i].ip, ip) == 0) {
            return &limiter->clients[i];
        }
    }

    /* If not found and we have room, create new entry */
    if (limiter->client_count < limiter->config.max_clients) {
        client_info_t *client = &limiter->clients[limiter->client_count++];
        strncpy(client->ip, ip, sizeof(client->ip) - 1);
        return client;
    }

    return NULL;  /* No room for new client */
}

/* Check if request should be allowed */
bool rate_limiter_check(rate_limiter_t *limiter, const char *client_ip) {
    bool allowed = false;
    time_t now = time(NULL);

    pthread_mutex_lock(&limiter->lock);

    client_info_t *client = get_client(limiter, client_ip);
    if (!client) {
        pthread_mutex_unlock(&limiter->lock);
        return false;  /* No room to track client */
    }

    /* Check if client is blocked */
    if (client->blocked) {
        if (now >= client->block_expires) {
            client->blocked = false;
            client->count = 0;  /* Reset count after block expires */
        } else {
            pthread_mutex_unlock(&limiter->lock);
            return false;
        }
    }

    /* Remove old timestamps */
    size_t valid_count = 0;
    for (size_t i = 0; i < client->count; i++) {
        if (now - client->timestamps[i] < limiter->config.window_seconds) {
            client->timestamps[valid_count++] = client->timestamps[i];
        }
    }
    client->count = valid_count;

    /* Check if under limit */
    if (client->count < limiter->config.max_requests) {
        client->timestamps[client->count++] = now;
        allowed = true;
    } else if (limiter->config.block_on_breach) {
        client->blocked = true;
        client->block_expires = now + (limiter->config.window_seconds * 2);
    }

    pthread_mutex_unlock(&limiter->lock);
    return allowed;
}

/* Clean up old entries */
void rate_limiter_cleanup(rate_limiter_t *limiter) {
    time_t now = time(NULL);

    pthread_mutex_lock(&limiter->lock);

    /* Remove expired entries */
    size_t write = 0;
    for (size_t read = 0; read < limiter->client_count; read++) {
        client_info_t *client = &limiter->clients[read];
        bool keep = false;

        /* Check if client has recent activity or is blocked */
        if (client->blocked && now < client->block_expires) {
            keep = true;
        } else {
            for (size_t i = 0; i < client->count; i++) {
                if (now - client->timestamps[i] < limiter->config.window_seconds) {
                    keep = true;
                    break;
                }
            }
        }

        if (keep && write != read) {
            /* Move to new position */
            memcpy(&limiter->clients[write], client, sizeof(*client));
            write++;
        } else if (!keep) {
            /* Free timestamps array */
            free(client->timestamps);
            client->timestamps = NULL;
        }
    }
    limiter->client_count = write;

    pthread_mutex_unlock(&limiter->lock);
}

/* Destroy rate limiter */
void rate_limiter_destroy(rate_limiter_t *limiter) {
    if (!limiter) return;

    /* Free all client timestamp arrays */
    for (size_t i = 0; i < limiter->config.max_clients; i++) {
        free(limiter->clients[i].timestamps);
    }

    pthread_mutex_destroy(&limiter->lock);
    free(limiter->clients);
    free(limiter);
}