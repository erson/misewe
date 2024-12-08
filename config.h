#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdbool.h>

/* Server configuration */
typedef struct {
    /* Network settings */
    uint16_t port;
    char bind_addr[16];
    int backlog;
    
    /* Security settings */
    struct {
        uint32_t max_requests_per_min;
        uint32_t max_connections;
        size_t max_request_size;
        size_t max_header_size;
        int timeout_seconds;
    } limits;
    
    /* File settings */
    char root_dir[256];
    struct {
        char allowed_exts[16][8];
        size_t ext_count;
    } files;
    
    /* Logging settings */
    char access_log[256];
    char error_log[256];
    bool log_requests;
    bool log_errors;
} server_config_t;

/* Function prototypes */
server_config_t *config_load(const char *filename);
void config_free(server_config_t *config);
bool config_validate(const server_config_t *config);

#endif /* CONFIG_H */