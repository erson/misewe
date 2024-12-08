#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    /* Network settings */
    uint16_t port;
    char bind_addr[16];

    /* Security settings */
    uint32_t max_requests_per_minute;
    size_t max_request_size;
    int timeout_seconds;

    /* File settings */
    char root_dir[256];
    char allowed_extensions[16][8];
    size_t ext_count;

    /* Logging settings */
    char access_log[256];
    char error_log[256];
    bool log_requests;
} server_config_t;

server_config_t *config_load(const char *filename);
void config_destroy(server_config_t *config);

#endif /* CONFIG_H */