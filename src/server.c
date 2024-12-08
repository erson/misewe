#include "server.h"
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>

/* Server context structure */
struct server {
    int sock_fd;
    server_config_t config;
    bool running;
};

/* Check if file type is allowed */
static bool is_allowed_file_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return false;

    const char *allowed_exts[] = {
        ".html", ".css", ".js", ".txt", ".ico",
        NULL
    };

    for (const char **allowed = allowed_exts; *allowed; allowed++) {
        if (strcasecmp(ext, *allowed) == 0) {
            return true;
        }
    }

    return false;
}

/* Create server instance */
server_t *server_create(const server_config_t *config) {
    if (!config) return NULL;

    server_t *server = calloc(1, sizeof(*server));
    if (!server) return NULL;

    /* Copy configuration */
    server->config = *config;
    
    /* Create socket */
    server->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->sock_fd < 0) {
        free(server);
        return NULL;
    }

    /* Set socket options */
    int opt = 1;
    if (setsockopt(server->sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(server->sock_fd);
        free(server);
        return NULL;
    }

    /* Bind socket */
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(config->port),
        .sin_addr.s_addr = inet_addr(config->bind_addr)
    };

    if (bind(server->sock_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(server->sock_fd);
        free(server);
        return NULL;
    }

    /* Start listening */
    if (listen(server->sock_fd, SOMAXCONN) < 0) {
        close(server->sock_fd);
        free(server);
        return NULL;
    }

    return server;
}

/* Clean up server */
void server_destroy(server_t *server) {
    if (server) {
        server->running = false;
        if (server->sock_fd >= 0) {
            close(server->sock_fd);
        }
        free(server);
    }
}

/* Handle client connection */
static void *handle_client(void *arg) {
    int client_fd = *(int*)arg;
    free(arg);

    /* TODO: Implement request handling */
    
    close(client_fd);
    return NULL;
}

/* Run server */
bool server_run(server_t *server) {
    if (!server || server->sock_fd < 0) return false;

    server->running = true;
    
    while (server->running) {
        /* Accept client connection */
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int *client_fd = malloc(sizeof(int));
        if (!client_fd) continue;

        *client_fd = accept(server->sock_fd, (struct sockaddr*)&client_addr, &client_len);
        if (*client_fd < 0) {
            free(client_fd);
            continue;
        }

        /* Create thread to handle client */
        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, client_fd) != 0) {
            close(*client_fd);
            free(client_fd);
            continue;
        }
        pthread_detach(thread);
    }

    return true;
}