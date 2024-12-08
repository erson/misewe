#include <stdio.h>
#include "server.h"

int main(void) {
    server_ctx_t *server;
    server_err_t err;

    /* Create server context */
    server = server_create(SERVER_PORT);
    if (!server) {
        fprintf(stderr, "Failed to create server\n");
        return 1;
    }

    /* Run server */
    err = server_run(server);
    if (err != SERVER_OK) {
        fprintf(stderr, "Server error: %d\n", err);
    }

    /* Cleanup */
    server_destroy(server);
    return err == SERVER_OK ? 0 : 1;
}