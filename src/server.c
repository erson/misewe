#include "server.h"
#include "http.h"
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
#include <fcntl.h>
#include <sys/stat.h>

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

    char buffer[4096];
    ssize_t bytes = read(client_fd, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        close(client_fd);
        return NULL;
    }
    buffer[bytes] = '\0';

    /* Parse HTTP request */
    http_request_t req;
    if (!http_parse_request(buffer, bytes, &req)) {
        http_send_error(client_fd, 400, "Bad Request");
        close(client_fd);
        return NULL;
    }

    /* Validate file type */
    if (!is_allowed_file_type(req.path)) {
        http_send_error(client_fd, 403, "Forbidden");
        close(client_fd);
        return NULL;
    }

    /* Build file path */
    char filepath[512] = "www";  // Assuming 'www' is the web root
    strncat(filepath, req.path, sizeof(filepath) - 4);  // -4 for "www" and null terminator

    /* Open and send file */
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        http_send_error(client_fd, 404, "Not Found");
        close(client_fd);
        return NULL;
    }

    /* Get file size */
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        http_send_error(client_fd, 500, "Internal Server Error");
        close(client_fd);
        return NULL;
    }

    /* Read and send file */
    char *content = malloc(st.st_size);
    if (!content) {
        close(fd);
        http_send_error(client_fd, 500, "Internal Server Error");
        close(client_fd);
        return NULL;
    }

    if (read(fd, content, st.st_size) != st.st_size) {
        free(content);
        close(fd);
        http_send_error(client_fd, 500, "Internal Server Error");
        close(client_fd);
        return NULL;
    }

    /* Send response */
    http_send_response(client_fd, 200, "text/html", content, st.st_size);

    /* Clean up */
    free(content);
    close(fd);
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