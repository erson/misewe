#include <stdio.h>
#include <stdlib.h>
#include "server.h"
#include "config.h"

/* Alert callback for security events */
void handle_security_alert(const char *ip, const char *message) {
    printf("SECURITY ALERT: [%s] %s\n", ip, message);
}

int main(int argc, char *argv[]) {
    const char *config_file = argc > 1 ? argv[1] : "server.conf";
    
    /* Load configuration */
    server_config_t *config = config_load(config_file);
    if (!config) {
        fprintf(stderr, "Failed to load configuration\n");
        return 1;
    }

    /* Create server */
    server_t *server = server_create(config);
    if (!server) {
        fprintf(stderr, "Failed to create server\n");
        config_free(config);
        return 1;
    }

    printf("Server starting...\n");
    printf("Port: %d\n", config->port);
    printf("Root directory: %s\n", config->root_dir);
    printf("Security level: %s\n", 
           config->security_level == SECURITY_HIGH ? "High" :
           config->security_level == SECURITY_MEDIUM ? "Medium" : "Low");

    /* Run server */
    server_run(server);

    /* Cleanup */
    server_destroy(server);
    config_free(config);
    return 0;
}