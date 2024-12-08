#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Security levels */
typedef enum {
    SECURITY_LOW,
    SECURITY_MEDIUM,
    SECURITY_HIGH,
    SECURITY_PARANOID
} security_level_t;

/* Access control entry */
typedef struct {
    char ip[16];               /* IP address or CIDR */
    uint32_t mask;            /* Network mask */
    bool allow;               /* Allow or deny */
    time_t expires;           /* Expiration time (0 = never) */
} acl_entry_t;

/* Security configuration */
typedef struct {
    security_level_t level;
    struct {
        size_t max_header_size;
        size_t max_request_size;
        size_t max_uri_length;
        int max_headers;
    } limits;
    struct {
        bool enable_xss_protection;
        bool enable_csrf_protection;
        bool enable_clickjacking_protection;
        bool enable_hsts;
        char *allowed_origins;
    } headers;
    struct {
        acl_entry_t *entries;
        size_t count;
    } acl;
    struct {
        char *cert_file;
        char *key_file;
        bool verify_peer;
        int min_version;      /* Minimum TLS version */
    } tls;
} security_config_t;

/* Security context */
typedef struct security_ctx security_ctx_t;

/* Function prototypes */
security_ctx_t *security_create(const security_config_t *config);
void security_destroy(security_ctx_t *ctx);
bool security_check_request(security_ctx_t *ctx, const char *ip,
                          const char *method, const char *uri,
                          const char *headers);
void security_add_response_headers(security_ctx_t *ctx, char *headers,
                                 size_t size);

#endif /* SECURITY_H */