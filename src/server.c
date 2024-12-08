#include "server.h"
#include "http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>

#define BUFFER_SIZE 8192

struct server {
    int fd;                     /* Server socket */
    security_config_t config;   /* Server configuration */
    volatile sig_atomic_t running;  /* Server running flag */
};

/* Signal handler */
static void handle_signal(int sig) {
    (void)sig;  /* Unused parameter */
}

/* Create server */
server_t *server_create(const security_config_t *config) {
    server_t *server = calloc(1, sizeof(*server));
    if (!server) return NULL;

    /* Copy configuration */
    server->config = *config;
    server->running = 1;

    /* Set up signal handling */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    return server;
}

/* Handle client connection */
static void handle_client(server_t *server, int client_fd) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    http_request_t request;
    char file_path[512];
    int file_fd;

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
    snprintf(file_path, sizeof(file_path), "www%s", request.path);

    /* Open file */
    file_fd = open(file_path, O_RDONLY);
    if (file_fd < 0) {
        http_send_error(client_fd, 404, "Not Found");
        return;
    }

    /* Get file size */
    off_t size = lseek(file_fd, 0, SEEK_END);
    lseek(file_fd, 0, SEEK_SET);

    /* Read file */
    char *content = malloc(size);
    if (!content) {
        close(file_fd);
        http_send_error(client_fd, 500, "Internal Error");
        return;
    }

    if (read(file_fd, content, size) != size) {
        free(content);
        close(file_fd);
        http_send_error(client_fd, 500, "Read Error");
        return;
    }

    close(file_fd);

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

/* Run server */
bool server_run(server_t *server) {
    struct sockaddr_in addr = {0};

    /* Create socket */
    server->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->fd < 0) {
        perror("socket");
        return false;
    }

    /* Allow address reuse */
    int opt = 1;
    setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Bind socket */
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8000);  /* Default port 8000 */
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  /* Listen on localhost */

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

    printf("Server listening on port 8000\n");

    /* Main server loop */
    while (server->running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int client_fd = accept(server->fd, (struct sockaddr*)&client_addr,
                             &addr_len);
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
    free(server);
}