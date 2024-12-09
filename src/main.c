#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "server.h"
#include "logger.h"

/* Get formatted timestamp */
static char* get_timestamp(void) {
    static char buffer[32];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    return buffer;
}

int main(void) {
    printf("\n=== Misewe Secure Web Server ===\n");
    printf("[%s] Server starting up\n\n", get_timestamp());

    /* Server configuration */
    server_config_t config = {
        .port = 8000,
        .bind_addr = "127.0.0.1",
        .root_dir = "www",
        .max_requests = 60
    };

    /* Show configuration */
    printf("[%s] Server Configuration:\n", get_timestamp());
    printf("- Listening on: http://%s:%d\n", config.bind_addr, config.port);
    printf("- Web root: %s\n", config.root_dir);
    printf("- Rate limit: %d requests/minute\n", config.max_requests);
    printf("\n[%s] Initializing server...\n", get_timestamp());

    /* Create and run server */
    server_t *server = server_create(&config);
    if (!server) {
        fprintf(stderr, "[%s] Error: Failed to create server\n", get_timestamp());
        return 1;
    }
    printf("[%s] Server created successfully\n", get_timestamp());

    printf("\n[%s] Starting server...\n", get_timestamp());
    if (!server_run(server)) {
        fprintf(stderr, "[%s] Error: Failed to run server\n", get_timestamp());
        server_destroy(server);
        return 1;
    }

    /* This point is reached when server is stopped */
    printf("\n[%s] Server shutting down...\n", get_timestamp());
    server_destroy(server);
    printf("[%s] Server stopped\n", get_timestamp());
    return 0;
}