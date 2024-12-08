#ifndef DOS_PROTECTION_H
#define DOS_PROTECTION_H

#include <stdint.h>
#include <time.h>
#include <stdbool.h>

/* Connection tracking entry */
typedef struct {
    char ip[16];
    uint32_t count;
    time_t first_seen;
    time_t last_seen;
    uint32_t banned_until;
} connection_entry_t;

/* DOS protection configuration */
typedef struct {
    uint32_t max_connections_per_ip;
    uint32_t max_requests_per_second;
    uint32_t ban_threshold;
    uint32_t ban_time;
    size_t max_tracked_ips;
} dos_config_t;

/* DOS protection context */
typedef struct dos_ctx dos_ctx_t;

/* Function prototypes */
dos_ctx_t *dos_protection_create(const dos_config_t *config);
void dos_protection_destroy(dos_ctx_t *ctx);
bool dos_check_ip(dos_ctx_t *ctx, const char *ip);
void dos_cleanup_expired(dos_ctx_t *ctx);

#endif /* DOS_PROTECTION_H */