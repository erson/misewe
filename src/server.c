#include "server.h"
#include "http.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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
    if (bytes_read <= 0) {
        log_write(LOG_ERROR, "Failed to read request");
        return;
    }
    buffer[bytes_read] = '\0';

    /* Parse request */
    if (!http_parse_request(buffer, bytes_read, &request)) {
        http_send_error(client_fd, 400, "Bad Request");
        return;
    }

    /* Log request */
    log_write(LOG_INFO, "%s %s", 
             request.method == HTTP_GET ? "GET" : "OTHER",
             request.path);

    /* Build file path */
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/%s",
             server->config.root_dir,
             request.path[0] == '/' ? request.path + 1 : request.path);

    /* Open file */
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        http_send_error(client_fd, 404, "Not Found");
        return;
    }

    /* Get file size */
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    /* Read file content */
    char *content = malloc(size);
    if (!content) {
        fclose(file);
        http_send_error(client_fd, 500, "Internal Error");
        return;
    }

    if (fread(content, 1, size, file) != (size_t)size) {
        free(content);
        fclose(file);
        http_send_error(client_fd, 500, "Read Error");
        return;
    }

    fclose(file);

    /* Send response */
    http_response_t response = {
        .status_code = 200,
        .content_type = "text/html",
        .body = content,
        .body_length = size
    };

    http_send_response(client_fd, &response);
    free(content);
}

/* Create server */
server_t *server_create(const server_config_t *config) {
    server_t *server = calloc(1, sizeof(*server));
    if (!server) return NULL;

    /* Copy configuration */
    server->config = *config;
    server->running = 1;

    /* Initialize logging */
    log_init("logs/access.log", "logs/error.log");

    return server;
}

/* Run server */
bool server_run(server_t *server) {
    struct sockaddr_in addr = {0};

    /* Create socket */
    server->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->fd < 0) {
        log_write(LOG_ERROR, "Failed to create socket: %s", strerror(errno));
        return false;
    }

    /* Set socket options */
    int opt = 1;
    setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Bind socket */
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(server->config.port);

    if (bind(server->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_write(LOG_ERROR, "Failed to bind: %s", strerror(errno));
        close(server->fd);
        return false;
    }

    /* Listen for connections */
    if (listen(server->fd, 10) < 0) {
        log_write(LOG_ERROR, "Failed to listen: %s", strerror(errno));
        close(server->fd);
        return false;
    }

    log_write(LOG_INFO, "Server running on port %d", server->config.port);

    /* Main server loop */
    while (server->running) {
        int client_fd = accept(server->fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno != EINTR) {
                log_write(LOG_ERROR, "Accept failed: %s", strerror(errno));
            }
            continue;
        }

        handle_client(server, client_fd);
        close(client_fd);
    }

    return true;
}

/* Stop server */
void server_stop(server_t *server) {
    if (server) {
        server->running = 0;
    }
}

/* Clean up server */
void server_destroy(server_t *server) {
    if (!server) return;
    
    if (server->fd >= 0) {
        close(server->fd);
    }
    
    log_cleanup();
    free(server);
}