#ifndef SECURITY_CONFIG_H
#define SECURITY_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

/* Security configuration structure */
typedef struct {
    bool enable_https;              /* Enable HTTPS */
    bool require_auth;              /* Require authentication */
    bool enable_rate_limit;         /* Enable rate limiting */
    uint32_t rate_limit_requests;   /* Max requests per window */
    uint32_t rate_limit_window;     /* Time window in seconds */
    bool enable_xss_protection;     /* Enable XSS protection */
    bool enable_csrf_protection;    /* Enable CSRF protection */
    char csrf_token_secret[64];     /* Secret for CSRF tokens */
    bool enable_cors;               /* Enable CORS */
    char allowed_origins[1024];     /* Allowed origins for CORS */
    bool enable_hsts;               /* Enable HSTS */
    uint32_t hsts_max_age;         /* HSTS max age in seconds */
    bool enable_csp;               /* Enable Content Security Policy */
    char csp_policy[1024];         /* CSP policy string */
} security_config_t;

/* Function prototypes */
security_config_t *security_config_create(void);
void security_config_destroy(security_config_t *config);
bool security_config_load(security_config_t *config, const char *filename);
bool security_config_save(const security_config_t *config, const char *filename);
void security_config_set_defaults(security_config_t *config);

#endif /* SECURITY_CONFIG_H */ 