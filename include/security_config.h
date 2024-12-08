#ifndef SECURITY_CONFIG_H
#define SECURITY_CONFIG_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Security levels */
typedef enum {
    SECURITY_LOW,
    SECURITY_MEDIUM,
    SECURITY_HIGH,
    SECURITY_PARANOID
} security_level_t;

/* Rate limiting and connection settings */
typedef struct {
    uint32_t max_requests_per_min;
    uint32_t max_connections;
    size_t max_request_size;
    uint32_t timeout_seconds;
} security_limits_t;

/* File restrictions */
typedef struct {
    char allowed_exts[16][8];  /* Max 16 extensions of 7 chars + null */
    size_t ext_count;
} security_files_t;

/* Security configuration structure */
typedef struct {
    security_level_t level;
    security_limits_t limits;
    security_files_t files;
    bool log_requests;
    bool log_errors;
    char log_dir[256];
    
    /* Web security features */
    bool enable_https;
    bool require_auth;
    bool enable_rate_limit;
    uint32_t rate_limit_requests;
    uint32_t rate_limit_window;
    bool enable_xss_protection;
    bool enable_csrf_protection;
    char csrf_token_secret[64];
    bool enable_cors;
    char allowed_origins[1024];
    bool enable_hsts;
    uint32_t hsts_max_age;
    bool enable_csp;
    char csp_policy[1024];
} security_config_t;

/* Function prototypes */
security_config_t *security_config_create(void);
void security_config_destroy(security_config_t *config);
bool security_config_load(security_config_t *config, const char *filename);
bool security_config_save(const security_config_t *config, const char *filename);
void security_config_set_defaults(security_config_t *config);

#endif /* SECURITY_CONFIG_H */ 