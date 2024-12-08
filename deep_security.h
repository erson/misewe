#ifndef DEEP_SECURITY_H
#define DEEP_SECURITY_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Protocol states */
typedef enum {
    STATE_INIT,
    STATE_HEADERS,
    STATE_BODY,
    STATE_COMPLETE,
    STATE_ERROR
} proto_state_t;

/* Security levels */
typedef enum {
    SECURITY_MINIMAL,    /* Basic checks only */
    SECURITY_STANDARD,   /* Standard security features */
    SECURITY_HIGH,       /* Enhanced security */
    SECURITY_PARANOID    /* Maximum security */
} security_level_t;

/* Behavioral analysis flags */
typedef enum {
    BEHAVIOR_NORMAL      = 0,
    BEHAVIOR_SUSPICIOUS  = 1 << 0,
    BEHAVIOR_AUTOMATED   = 1 << 1,
    BEHAVIOR_AGGRESSIVE  = 1 << 2,
    BEHAVIOR_MALICIOUS   = 1 << 3
} behavior_flags_t;

/* Security context */
typedef struct deep_security deep_security_t;

/* Configuration */
typedef struct {
    security_level_t level;
    size_t max_request_size;
    size_t max_header_count;
    size_t max_uri_length;
    uint32_t rate_limit;
    uint32_t burst_limit;
    bool enable_behavior_analysis;
    const char *whitelist_file;
    const char *blacklist_file;
} security_config_t;

/* Function prototypes */
deep_security_t *security_create(const security_config_t *config);
void security_destroy(deep_security_t *sec);

bool security_check_request(
    deep_security_t *sec,
    const char *client_ip,
    const void *data,
    size_t length
);

void security_update_state(
    deep_security_t *sec,
    const char *client_ip,
    proto_state_t new_state
);

behavior_flags_t security_analyze_behavior(
    deep_security_t *sec,
    const char *client_ip
);

#endif /* DEEP_SECURITY_H */