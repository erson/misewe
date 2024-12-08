#include "dos_protection.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

struct dos_ctx {
    dos_config_t config;
    connection_entry_t *entries;
    size_t count;
    pthread_mutex_t lock;
};

/* Create DOS protection context */
dos_ctx_t *dos_protection_create(const dos_config_t *config) {
    dos_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    /* Copy configuration */
    ctx->config = *config;

    /* Allocate connection tracking array */
    ctx->entries = calloc(config->max_tracked_ips, 
                         sizeof(connection_entry_t));
    if (!ctx->entries) {
        free(ctx);
        return NULL;
    }

    /* Initialize mutex */
    if (pthread_mutex_init(&ctx->lock, NULL) != 0) {
        free(ctx->entries);
        free(ctx);
        return NULL;
    }

    return ctx;
}

/* Find or create entry for IP */
static connection_entry_t *get_entry(dos_ctx_t *ctx, const char *ip) {
    time_t now = time(NULL);

    /* First, try to find existing entry */
    for (size_t i = 0; i < ctx->count; i++) {
        if (strcmp(ctx->entries[i].ip, ip) == 0) {
            return &ctx->entries[i];
        }
    }

    /* If not found and we have room, create new entry */
    if (ctx->count < ctx->config.max_tracked_ips) {
        connection_entry_t *entry = &ctx->entries[ctx->count++];
        strncpy(entry->ip, ip, sizeof(entry->ip) - 1);
        entry->first_seen = entry->last_seen = now;
        return entry;
    }

    return NULL;
}

/* Check if IP should be allowed */
bool dos_check_ip(dos_ctx_t *ctx, const char *ip) {
    time_t now = time(NULL);
    bool allowed = false;

    pthread_mutex_lock(&ctx->lock);

    connection_entry_t *entry = get_entry(ctx, ip);
    if (!entry) {
        pthread_mutex_unlock(&ctx->lock);
        return false;  /* No room to track */
    }

    /* Check if banned */
    if (entry->banned_until > now) {
        pthread_mutex_unlock(&ctx->lock);
        return false;
    }

    /* Calculate request rate */
    if (now - entry->last_seen >= 1) {
        /* Reset counter for new second */
        entry->count = 1;
    } else {
        entry->count++;
    }
    entry->last_seen = now;

    /* Check rate limits */
    if (entry->count <= ctx->config.max_requests_per_second) {
        allowed = true;
    } else {
        /* Ban if threshold exceeded */
        if (entry->count >= ctx->config.ban_threshold) {
            entry->banned_until = now + ctx->config.ban_time;
        }
        allowed = false;
    }

    pthread_mutex_unlock(&ctx->lock);
    return allowed;
}

/* Clean up expired entries */
void dos_cleanup_expired(dos_ctx_t *ctx) {
    time_t now = time(NULL);

    pthread_mutex_lock(&ctx->lock);

    size_t write = 0;
    for (size_t read = 0; read < ctx->count; read++) {
        connection_entry_t *entry = &ctx->entries[read];

        /* Keep entry if recent activity or banned */
        if (now - entry->last_seen < 60 || entry->banned_until > now) {
            if (write != read) {
                memcpy(&ctx->entries[write], entry, 
                       sizeof(connection_entry_t));
            }
            write++;
        }
    }
    ctx->count = write;

    pthread_mutex_unlock(&ctx->lock);
}

/* Clean up DOS protection */
void dos_protection_destroy(dos_ctx_t *ctx) {
    if (!ctx) return;
    pthread_mutex_destroy(&ctx->lock);
    free(ctx->entries);
    free(ctx);
}