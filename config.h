#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdbool.h>

/* Server configuration */
typedef struct {
    uint16_t port;              /* Server port */
    char bind_addr[16];         /* Bind address */
    char root_dir[256];         /* Web root directory */
    size_t max_clients;         /* Maximum concurrent clients */
    size_t max_request_size;    /* Maximum request size in bytes */
    int timeout_sec;           /* Client timeout in seconds */
    struct {
        char allowed_exts[16][8];  /* Allowed file extensions */
        size_t ext_count;
    } security;
    bool daemon;               /* Run as daemon */
} config_t;

/* Function prototypes */
config_t *config_load(const char *filename);
void config_free(config_t *cfg);
bool config_validate(const config_t *cfg);

#endif /* CONFIG_H */