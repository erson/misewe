#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>
#include <stdbool.h>
#include "security_config.h"

/* Server context */
typedef struct server server_t;

/* Function prototypes */
server_t *server_create(const security_config_t *config);
void server_destroy(server_t *server);
bool server_run(server_t *server);
void server_stop(server_t *server);

#endif /* SERVER_H */