#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>
#include <time.h>

/* Security context */
typedef struct {
    /* Memory limits */
    size_t max_request_size;
    size_t max_response_size;
    
    /* Rate limiting */
    int max_requests_per_window;
    int window_seconds;
    
    /* Request validation */
    char allowed_methods[8][16];
    size_t method_count;
    char allowed_extensions[16][16];
    size_t extension_count;
    
    /* Connection settings */
    int timeout_seconds;
    int max_header_count;
    
    /* IP blocking */
    char **blocked_ips;
    size_t blocked_count;
    
    /* Headers */
    char **security_headers;
    size_t header_count;
} security_ctx_t;

/* Request validation result */
typedef enum {
    VALID_REQUEST = 0,
    INVALID_METHOD = -1,
    INVALID_PATH = -2,
    INVALID_PROTOCOL = -3,
    INVALID_HEADERS = -4,
    RATE_LIMITED = -5,
    IP_BLOCKED = -6
} validation_result_t;

/* Function prototypes */
security_ctx_t *security_init(void);
void security_cleanup(security_ctx_t *ctx);
validation_result_t validate_request(security_ctx_t *ctx, const char *method, 
                                   const char *path, const char *headers);
int check_rate_limit(security_ctx_t *ctx, const char *ip);
void add_security_headers(char *response, size_t size);
int sanitize_input(char *buf, size_t size);

#endif /* SECURITY_H */