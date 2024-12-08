#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

struct server {
    int fd;
    uint16_t port;
    const char *root_dir;
    volatile sig_atomic_t running;
};

static void handle_signal(int sig) {
    (void)sig;
}

server_t *server_create(const server_config_t *config) {
    server_t *server = calloc(1, sizeof(*server));
    if (!server) return NULL;

    server->port = config->port;
    server->root_dir = config->root_dir;
    server->running = 1;

    /* Set up signal handling */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    return server;
}

void server_run(server_t *server) {
    struct sockaddr_in addr = {0};
    
    /* Create socket */
    server->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->fd < 0) {
        perror("socket");
        return;
    }

    /* Set up address */
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server->port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    /* Bind socket */
    if (bind(server->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server->fd);
        return;
    }

    /* Listen for connections */
    if (listen(server->fd, 10) < 0) {
        perror("listen");
        close(server->fd);
        return;
    }

    /* Main loop */
    while (server->running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        int client_fd = accept(server->fd, 
                             (struct sockaddr*)&client_addr,
                             &addr_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        /* Handle connection */
        char buffer[1024];
        ssize_t n = read(client_fd, buffer, sizeof(buffer) - 1);
        if (n > 0) {
            buffer[n] = '\0';
            printf("Received request:\n%s\n", buffer);

            /* Send simple response */
            const char *response = 
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 13\r\n"
                "\r\n"
                "Hello, World!";
            write(client_fd, response, strlen(response));
        }

        close(client_fd);
    }
}

void server_destroy(server_t *server) {
    if (!server) return;
    if (server->fd > 0) close(server->fd);
    free(server);
}