#include <stdio.h>
#include <stdlib.h>
#include "server.h"

int main(void) {
    server_config_t config = {
        .port = 8000,
        .root_dir = "."
    };

    server_t *server = server_create(&config);
    if (!server) {
        fprintf(stderr, "Failed to create server\n");
        return 1;
    }

    printf("Server running on port %d\n", config.port);
    server_run(server);
    server_destroy(server);

    return 0;
}