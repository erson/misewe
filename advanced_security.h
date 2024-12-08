#ifndef ADVANCED_SECURITY_H
#define ADVANCED_SECURITY_H

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

/* Attack types for monitoring */
typedef enum {
    ATTACK_NONE,
    ATTACK_SQL_INJECTION,
    ATTACK_XSS,
    ATTACK_TRAVERSAL,
    ATTACK_COMMAND_INJECTION,
    ATTACK_DOS,
    ATTACK_SCAN,
    ATTACK_PROTOCOL
} attack_type_t;

/* Security context */
typedef struct {
    security_level_t level;
    struct {
        uint32_t max_requests;
        uint32_t window_seconds;
        size_t max_body_size;
        int connection_timeout;
    } limits;
    struct {
        char **patterns;
        size_t count;
    } blacklist;
    bool log_attacks;
    void (*alert_callback)(attack_type_t, const char *ip, const char *details);
} security_config_t;

typedef struct security_ctx security_ctx_t;

/* Function prototypes */
security_ctx_t *security_create(const security_config_t *config);
void security_destroy(security_ctx_t *ctx);

bool security_check_request(security_ctx_t *ctx,
                          const char *client_ip,
                          const char *method,
                          const char *uri,
                          const char *headers,
                          const char *body,
                          size_t body_length);

void security_log_attack(security_ctx_t *ctx,
                        const char *client_ip,
                        attack_type_t type,
                        const char *details);

#endif /* ADVANCED_SECURITY_H */