#include <stdio.h>
#include <stdlib.h>
#include "server.h"
#include "security_config.h"

int main(void) {
    /* Create default configuration */
    security_config_t *config = security_config_create();
    if (!config) {
        fprintf(stderr, "Failed to create configuration\n");
        return 1;
    }

    /* Create server */
    server_t *server = server_create(config);
    if (!server) {
        fprintf(stderr, "Failed to create server\n");
        security_config_destroy(config);
        return 1;
    }

    /* Run server */
    if (!server_run(server)) {
        fprintf(stderr, "Server failed to run\n");
    }

    /* Cleanup */
    server_destroy(server);
    security_config_destroy(config);
    return 0;
}