#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>

typedef struct server server_t;

typedef struct {
    uint16_t port;
    const char *root_dir;
} server_config_t;

server_t *server_create(const server_config_t *config);
void server_destroy(server_t *server);
void server_run(server_t *server);

#endif /* SERVER_H */