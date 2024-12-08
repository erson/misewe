#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

typedef struct {
    uint16_t port;
    char bind_addr[16];
    size_t max_request_size;
    size_t max_clients;
    int requests_per_second;
    int timeout_seconds;
    char log_file[256];
    struct {
        int enabled;
        char cert_file[256];
        char key_file[256];
    } ssl;
    struct {
        char allowed_extensions[16][16];
        size_t count;
    } security;
} server_config_t;

server_config_t *config_load(const char *filename);
void config_free(server_config_t *config);

#endif /* CONFIG_H */