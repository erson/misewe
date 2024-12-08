#ifndef SECURITY_AUDIT_H
#define SECURITY_AUDIT_H

#include <time.h>
#include <stdint.h>

/* Audit event types */
typedef enum {
    AUDIT_ACCESS_ATTEMPT = 1,
    AUDIT_AUTH_FAILURE,
    AUDIT_RATE_LIMIT_HIT,
    AUDIT_INVALID_REQUEST,
    AUDIT_MEMORY_CORRUPTION,
    AUDIT_FILE_ACCESS,
    AUDIT_CONFIG_CHANGE,
    AUDIT_SERVER_START,
    AUDIT_SERVER_STOP,
    AUDIT_SECURITY_BREACH
} audit_event_t;

/* Audit record structure */
typedef struct {
    time_t timestamp;
    audit_event_t event_type;
    char client_ip[16];
    char resource[256];
    char details[512];
    uint32_t sequence;
    int severity;
} audit_record_t;

/* Audit context */
typedef struct audit_ctx audit_ctx_t;

/* Function prototypes */
audit_ctx_t *audit_init(const char *audit_file);
void audit_log_event(audit_ctx_t *ctx, audit_event_t event,
                     const char *client_ip, const char *resource,
                     const char *details, int severity);
void audit_cleanup(audit_ctx_t *ctx);
void audit_rotate_logs(audit_ctx_t *ctx);
int audit_verify_integrity(audit_ctx_t *ctx);

#endif /* SECURITY_AUDIT_H */