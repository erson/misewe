#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>
#include <stdbool.h>

/* Server context */
typedef struct server server_t;

/* Server configuration */
typedef struct {
    uint16_t port;              /* Server port */
    char root_dir[256];         /* Web root directory */
    bool auth_enabled;          /* Enable authentication */
    char auth_file[256];        /* Authentication file path */
} server_config_t;

/* Function prototypes */
server_t *server_create(const server_config_t *config);
void server_destroy(server_t *server);
bool server_run(server_t *server);
void server_stop(server_t *server);

#endif /* SERVER_H */