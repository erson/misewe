#ifndef RATE_LIMIT_H
#define RATE_LIMIT_H

#include <stdbool.h>

/* Rate limiter context */
typedef struct rate_limiter rate_limiter_t;

/* Function prototypes */
rate_limiter_t *rate_limiter_create(unsigned int max_requests,
                                   unsigned int window_seconds);
void rate_limiter_destroy(rate_limiter_t *limiter);
bool rate_limiter_check(rate_limiter_t *limiter, const char *ip);

#endif /* RATE_LIMIT_H */