#include <stdio.h>
#include <stdlib.h>
#include "server.h"

int main(void) {
    /* Server configuration */
    server_config_t config = {
        .port = 8000,
        .bind_addr = "127.0.0.1",
        .root_dir = "www",
        .max_requests = 60
    };

    /* Create and run server */
    server_t *server = server_create(&config);
    if (!server) {
        fprintf(stderr, "Failed to create server\n");
        return 1;
    }

    if (!server_run(server)) {
        fprintf(stderr, "Failed to run server\n");
        server_destroy(server);
        return 1;
    }

    server_destroy(server);
    return 0;
}