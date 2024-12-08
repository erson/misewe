#include "security.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Security context structure */
struct security_ctx {
    security_config_t config;
    size_t request_count;
};

/* SQL injection patterns */
static const char *sql_patterns[] = {
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "UNION",
    "OR 1=1",
    "--",
    NULL
};

/* XSS patterns */
static const char *xss_patterns[] = {
    "<script",
    "javascript:",
    "onerror=",
    "onload=",
    "eval(",
    NULL
};

/* Check for dangerous patterns */
static bool contains_pattern(const char *str, const char *patterns[]) {
    if (!str) return false;
    
    char *tmp = strdup(str);
    if (!tmp) return false;
    
    /* Convert to uppercase for case-insensitive comparison */
    for (char *p = tmp; *p; p++) {
        *p = toupper(*p);
    }
    
    bool found = false;
    for (const char **pattern = patterns; *pattern; pattern++) {
        char *upper_pattern = strdup(*pattern);
        if (!upper_pattern) {
            free(tmp);
            return false;
        }
        
        for (char *p = upper_pattern; *p; p++) {
            *p = toupper(*p);
        }
        
        if (strstr(tmp, upper_pattern)) {
            found = true;
            free(upper_pattern);
            break;
        }
        free(upper_pattern);
    }
    
    free(tmp);
    return found;
}

/* Create security context */
security_ctx_t *security_create(const security_config_t *config) {
    if (!config) return NULL;
    
    security_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (ctx) {
        ctx->config = *config;
    }
    return ctx;
}

/* Clean up security context */
void security_destroy(security_ctx_t *ctx) {
    free(ctx);
}

/* Check if request is allowed */
bool security_check_request(security_ctx_t *ctx,
                          const char *ip,
                          const char *method,
                          const char *path,
                          const char *query,
                          const char *body,
                          size_t body_length) {
    if (!ctx || !ip || !method || !path) return false;
    
    /* Check rate limit */
    if (ctx->config.enable_rate_limit) {
        if (++ctx->request_count > ctx->config.rate_limit_requests) {
            log_write(LOG_WARN, "Rate limit exceeded for IP: %s", ip);
            return false;
        }
    }
    
    /* Check for SQL injection */
    if (contains_pattern(query, sql_patterns) ||
        contains_pattern(body, sql_patterns)) {
        log_write(LOG_WARN, "SQL injection attempt from IP: %s", ip);
        return false;
    }
    
    /* Check for XSS */
    if (ctx->config.enable_xss_protection &&
        (contains_pattern(query, xss_patterns) ||
         contains_pattern(body, xss_patterns))) {
        log_write(LOG_WARN, "XSS attempt from IP: %s", ip);
        return false;
    }
    
    /* Check request size */
    if (body_length > ctx->config.limits.max_request_size) {
        log_write(LOG_WARN, "Request too large from IP: %s", ip);
        return false;
    }
    
    return true;
} 