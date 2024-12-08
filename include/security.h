#ifndef SECURITY_H
#define SECURITY_H

#include <stdbool.h>
#include "security_config.h"

/* Security context */
typedef struct security_ctx security_ctx_t;

/* Function prototypes */
security_ctx_t *security_create(const security_config_t *config);
void security_destroy(security_ctx_t *ctx);

bool security_check_request(security_ctx_t *ctx,
                          const char *ip,
                          const char *method,
                          const char *path,
                          const char *query,
                          const char *body,
                          size_t body_length);

#endif /* SECURITY_H */ 