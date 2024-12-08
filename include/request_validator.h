#ifndef REQUEST_VALIDATOR_H
#define REQUEST_VALIDATOR_H

#include <stdbool.h>
#include "http.h"

/* Validation result */
typedef struct {
    bool valid;
    const char *error;
} validation_result_t;

/* Function prototypes */
validation_result_t validate_request(const http_request_t *request);
bool is_path_safe(const char *path);
bool is_method_allowed(http_method_t method);

#endif /* REQUEST_VALIDATOR_H */