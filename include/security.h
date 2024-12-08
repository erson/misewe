#ifndef SECURITY_H
#define SECURITY_H

#include <stdbool.h>
#include "http.h"

/* Security context */
typedef struct security_ctx security_ctx_t;

/* Security result */
typedef struct {
    bool allowed;
    char reason[256];
} security_result_t;

/* Function prototypes */
security_ctx_t *security_create(void);
void security_destroy(security_ctx_t *ctx);

security_result_t security_check_request(security_ctx_t *ctx,
                                       const char *client_ip,
                                       const http_request_t *req);

void security_add_headers(http_response_t *resp);

#endif /* SECURITY_H */