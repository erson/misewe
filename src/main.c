#include <stdio.h>
#include <stdlib.h>
#include "server.h"

int main(void) {
    /* Create server configuration */
    server_config_t config = {
        .port = 8000,
        .root_dir = "www",
        .auth_enabled = false
    };

    /* Create server */
    server_t *server = server_create(&config);
    if (!server) {
        fprintf(stderr, "Failed to create server\n");
        return 1;
    }

    /* Run server */
    if (!server_run(server)) {
        fprintf(stderr, "Failed to run server\n");
        server_destroy(server);
        return 1;
    }

    /* Clean up */
    server_destroy(server);
    return 0;
}