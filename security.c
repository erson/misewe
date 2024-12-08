#include "security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <arpa/inet.h>

/* Security context structure */
struct security_ctx {
    security_config_t config;
    pthread_mutex_t lock;
    struct {
        char **patterns;
        size_t count;
    } blacklist;
    uint64_t request_count;
    time_t start_time;
};

/* Known attack patterns to block */
static const char *attack_patterns[] = {
    "../",              /* Directory traversal */
    "<?",              /* PHP injection */
    "<script",         /* XSS */
    "UNION SELECT",    /* SQL injection */
    "eval(",           /* Code injection */
    ".htaccess",       /* Config access */
    "/etc/passwd",     /* System file access */
    "cmd=",            /* Command injection */
    NULL
};

/* Initialize security patterns */
static bool init_security_patterns(security_ctx_t *ctx) {
    size_t count = 0;
    while (attack_patterns[count]) count++;

    ctx->blacklist.patterns = calloc(count, sizeof(char*));
    if (!ctx->blacklist.patterns) return false;

    for (size_t i = 0; i < count; i++) {
        ctx->blacklist.patterns[i] = strdup(attack_patterns[i]);
        if (!ctx->blacklist.patterns[i]) {
            for (size_t j = 0; j < i; j++) {
                free(ctx->blacklist.patterns[j]);
            }
            free(ctx->blacklist.patterns);
            return false;
        }
    }

    ctx->blacklist.count = count;
    return true;
}

/* Check if IP matches CIDR */
static bool ip_matches_cidr(const char *ip_str, const char *cidr_str,
                          uint32_t mask) {
    struct in_addr ip, cidr;
    if (inet_pton(AF_INET, ip_str, &ip) != 1 ||
        inet_pton(AF_INET, cidr_str, &cidr) != 1) {
        return false;
    }

    uint32_t ip_bits = ntohl(ip.s_addr);
    uint32_t cidr_bits = ntohl(cidr.s_addr);
    return (ip_bits & mask) == (cidr_bits & mask);
}

/* Check access control list */
static bool check_acl(security_ctx_t *ctx, const char *ip) {
    time_t now = time(NULL);
    bool default_allow = (ctx->config.level <= SECURITY_MEDIUM);

    for (size_t i = 0; i < ctx->config.acl.count; i++) {
        acl_entry_t *entry = &ctx->config.acl.entries[i];
        
        /* Skip expired entries */
        if (entry->expires && entry->expires < now) continue;

        /* Check if IP matches */
        if (ip_matches_cidr(ip, entry->ip, entry->mask)) {
            return entry->allow;
        }
    }

    return default_allow;
}

/* Sanitize and validate input */
static bool is_input_safe(const char *input, size_t max_len) {
    if (!input || strlen(input) > max_len) return false;

    /* Check for control characters and non-ASCII */
    for (const char *p = input; *p; p++) {
        if (iscntrl(*p) || !isascii(*p)) return false;
    }

    return true;
}

/* Check for attack patterns */
static bool contains_attack_pattern(security_ctx_t *ctx, const char *input) {
    char *lower = strdup(input);
    if (!lower) return true;  /* If in doubt, reject */

    /* Convert to lowercase for comparison */
    for (char *p = lower; *p; p++) {
        *p = tolower(*p);
    }

    bool found = false;
    for (size_t i = 0; i < ctx->blacklist.count; i++) {
        if (strstr(lower, ctx->blacklist.patterns[i])) {
            found = true;
            break;
        }
    }

    free(lower);
    return found;
}

/* Create security context */
security_ctx_t *security_create(const security_config_t *config) {
    security_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    /* Copy configuration */
    ctx->config = *config;

    /* Initialize mutex */
    if (pthread_mutex_init(&ctx->lock, NULL) != 0) {
        free(ctx);
        return NULL;
    }

    /* Initialize security patterns */
    if (!init_security_patterns(ctx)) {
        pthread_mutex_destroy(&ctx->lock);
        free(ctx);
        return NULL;
    }

    ctx->start_time = time(NULL);
    return ctx;
}

/* Check security of HTTP request */
bool security_check_request(security_ctx_t *ctx, const char *ip,
                          const char *method, const char *uri,
                          const char *headers) {
    if (!ctx || !ip || !method || !uri || !headers) return false;

    pthread_mutex_lock(&ctx->lock);
    ctx->request_count++;
    pthread_mutex_unlock(&ctx->lock);

    /* Check ACL first */
    if (!check_acl(ctx, ip)) {
        return false;
    }

    /* Basic input validation */
    if (!is_input_safe(method, 16) ||
        !is_input_safe(uri, ctx->config.limits.max_uri_length) ||
        !is_input_safe(headers, ctx->config.limits.max_header_size)) {
        return false;
    }

    /* Check for attack patterns */
    if (contains_attack_pattern(ctx, uri) ||
        contains_attack_pattern(ctx, headers)) {
        return false;
    }

    /* Method validation */
    if (strcasecmp(method, "GET") != 0 &&
        strcasecmp(method, "HEAD") != 0) {
        return ctx->config.level < SECURITY_HIGH;
    }

    return true;
}

/* Add security headers to response */
void security_add_response_headers(security_ctx_t *ctx, char *headers,
                                 size_t size) {
    size_t pos = 0;

    /* Add standard security headers */
    pos += snprintf(headers + pos, size - pos,
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "X-XSS-Protection: 1; mode=block\r\n"
        "Content-Security-Policy: default-src 'self'\r\n");

    /* Add optional headers based on configuration */
    if (ctx->config.headers.enable_hsts) {
        pos += snprintf(headers + pos, size - pos,
            "Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains; preload\r\n");
    }

    if (ctx->config.headers.allowed_origins) {
        pos += snprintf(headers + pos, size - pos,
            "Access-Control-Allow-Origin: %s\r\n",
            ctx->config.headers.allowed_origins);
    }

    /* Add server statistics for debugging if in low security mode */
    if (ctx->config.level == SECURITY_LOW) {
        pthread_mutex_lock(&ctx->lock);
        pos += snprintf(headers + pos, size - pos,
            "X-Request-Count: %lu\r\n"
            "X-Uptime: %ld\r\n",
            ctx->request_count,
            time(NULL) - ctx->start_time);
        pthread_mutex_unlock(&ctx->lock);
    }
}

/* Clean up security context */
void security_destroy(security_ctx_t *ctx) {
    if (!ctx) return;

    /* Free blacklist patterns */
    for (size_t i = 0; i < ctx->blacklist.count; i++) {
        free(ctx->blacklist.patterns[i]);
    }
    free(ctx->blacklist.patterns);

    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
}