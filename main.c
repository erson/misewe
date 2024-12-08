#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "server.h"
#include "config.h"

static void print_usage(const char *program) {
    printf("Usage: %s [config_file]\n", program);
    printf("\nOptions:\n");
    printf("  config_file  Path to configuration file (optional)\n");
    printf("\nDefaults:\n");
    printf("  Port: 8000\n");
    printf("  Address: 127.0.0.1\n");
    printf("  Root directory: ./www\n");
}

int main(int argc, char *argv[]) {
    const char *config_file = NULL;
    
    /* Parse command line */
    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || 
            strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        config_file = argv[1];
    }
    
    /* Load configuration */
    server_config_t *config = config_load(config_file);
    if (!config) {
        fprintf(stderr, "Failed to load configuration\n");
        return 1;
    }
    
    /* Validate configuration */
    if (!config_validate(config)) {
        fprintf(stderr, "Invalid configuration\n");
        config_free(config);
        return 1;
    }
    
    /* Create server */
    server_t *server = server_create(config);
    if (!server) {
        fprintf(stderr, "Failed to create server\n");
        config_free(config);
        return 1;
    }
    
    printf("Server starting on %s:%d\n", 
           config->bind_addr, config->port);
    printf("Root directory: %s\n", config->root_dir);
    printf("Max connections: %u\n", config->limits.max_connections);
    printf("Request limit: %u per minute\n", 
           config->limits.max_requests_per_min);
    
    /* Run server */
    server_run(server);
    
    /* Cleanup */
    server_destroy(server);
    config_free(config);
    
    return 0;
}