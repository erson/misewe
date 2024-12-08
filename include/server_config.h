#ifndef SERVER_CONFIG_H
#define SERVER_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

/* Security levels */
typedef enum {
    SECURITY_LOW,
    SECURITY_MEDIUM,
    SECURITY_HIGH,
    SECURITY_PARANOID
} security_level_t;

/* Server configuration */
typedef struct {
    /* Network settings */
    uint16_t port;
    char bind_addr[16];
    int backlog;

    /* Security settings */
    security_level_t security_level;
    struct {
        uint32_t max_requests_per_min;
        uint32_t max_connections;
        size_t max_request_size;
        int timeout_seconds;
    } limits;

    /* File settings */
    char root_dir[256];
    struct {
        char allowed_exts[16][8];  /* Allowed file extensions */
        size_t ext_count;
    } files;

    /* Authentication settings */
    bool auth_enabled;
    char auth_file[256];

    /* Logging settings */
    char access_log[256];
    char error_log[256];
    bool log_requests;
    bool log_errors;
} server_config_t;

/* Function prototypes */
server_config_t *config_create(void);
void config_destroy(server_config_t *config);
bool config_load(server_config_t *config, const char *filename);

#endif /* SERVER_CONFIG_H */