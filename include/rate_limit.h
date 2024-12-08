```c
#ifndef RATE_LIMIT_H
#define RATE_LIMIT_H

#include <stdbool.h>

/* Rate limiter context */
typedef struct rate_limiter rate_limiter_t;

/* Create rate limiter */
rate_limiter_t *rate_limiter_create(unsigned int requests_per_minute);
void rate_limiter_destroy(rate_limiter_t *limiter);

/* Check if request is allowed */
bool rate_limiter_check(rate_limiter_t *limiter, const char *ip);

#endif /* RATE_LIMIT_H */
```