#include "server.h"
#include "http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

struct server {
    int fd;                     /* Server socket */
    server_config_t config;     /* Server configuration */
    volatile sig_atomic_t running;  /* Server running flag */
};

/* Handle client connection */
static void handle_client(server_t *server, int client_fd) {
    char buffer[8192];
    ssize_t bytes_read;
    http_request_t request;

    /* Read request */
    bytes_read = read(client_fd, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0) return;
    buffer[bytes_read] = '\0';

    /* Parse request */
    if (!http_parse_request(buffer, bytes_read, &request)) {
        http_send_error(client_fd, 400, "Bad Request");
        return;
    }

    /* Build file path */
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/%s",
             server->config.root_dir,
             request.path[0] == '/' ? request.path + 1 : request.path);

    /* Open and read file */
    int fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        http_send_error(client_fd, 404, "Not Found");
        return;
    }

    /* Get file size */
    off_t size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    /* Read file content */
    char *content = malloc(size);
    if (!content) {
        close(fd);
        http_send_error(client_fd, 500, "Internal Error");
        return;
    }

    if (read(fd, content, size) != size) {
        free(content);
        close(fd);
        http_send_error(client_fd, 500, "Read Error");
        return;
    }

    close(fd);

    /* Send response */
    http_send_response(client_fd, 200, "text/html", content, size);
    free(content);
}

/* Create server */
server_t *server_create(const server_config_t *config) {
    server_t *server = calloc(1, sizeof(*server));
    if (server) {
        server->config = *config;
        server->running = 1;
    }
    return server;
}

/* Run server */
bool server_run(server_t *server) {
    struct sockaddr_in addr = {0};

    /* Create socket */
    server->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->fd < 0) {
        perror("socket");
        return false;
    }

    /* Set socket options */
    int opt = 1;
    setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Bind socket */
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, server->config.bind_addr, &addr.sin_addr);
    addr.sin_port = htons(server->config.port);

    if (bind(server->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server->fd);
        return false;
    }

    /* Listen for connections */
    if (listen(server->fd, 10) < 0) {
        perror("listen");
        close(server->fd);
        return false;
    }

    printf("Server running on %s:%d\n", 
           server->config.bind_addr, server->config.port);

    /* Main server loop */
    while (server->running) {
        int client_fd = accept(server->fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno != EINTR) {
                perror("accept");
            }
            continue;
        }

        handle_client(server, client_fd);
        close(client_fd);
    }

    return true;
}

/* Clean up server */
void server_destroy(server_t *server) {
    if (server) {
        if (server->fd >= 0) {
            close(server->fd);
        }
        free(server);
    }
}