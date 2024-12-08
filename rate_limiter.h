#ifndef RATE_LIMITER_H
#define RATE_LIMITER_H

#include <stdint.h>
#include <time.h>
#include <stdbool.h>

/* Rate limiter context */
typedef struct rate_limiter rate_limiter_t;

/* Rate limit configuration */
typedef struct {
    uint32_t window_seconds;    /* Time window in seconds */
    uint32_t max_requests;      /* Maximum requests per window */
    size_t max_clients;         /* Maximum number of tracked clients */
    bool block_on_breach;       /* Whether to block clients that breach limits */
} rate_limit_config_t;

/* Function prototypes */
rate_limiter_t *rate_limiter_create(const rate_limit_config_t *config);
void rate_limiter_destroy(rate_limiter_t *limiter);
bool rate_limiter_check(rate_limiter_t *limiter, const char *client_ip);
void rate_limiter_cleanup(rate_limiter_t *limiter);

#endif /* RATE_LIMITER_H */