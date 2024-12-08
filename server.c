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
#define MAX_REQUEST_SIZE (1024 * 1024)  /* 1MB */

/* Handle client connection */
static void handle_client(server_t *server, int client_fd) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    size_t total_read = 0;

    /* Set timeout */
    struct timeval tv = {
        .tv_sec = 30,  /* 30 second timeout */
        .tv_usec = 0
    };
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Read request */
    while ((bytes_read = read(client_fd, buffer + total_read,
                             sizeof(buffer) - total_read - 1)) > 0) {
        total_read += bytes_read;

        /* Check size limit */
        if (total_read >= MAX_REQUEST_SIZE) {
            http_send_error(client_fd, 413, "Request too large");
            return;
        }

        /* Check for end of headers */
        if (strstr(buffer, "\r\n\r\n")) break;
    }

    if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            http_send_error(client_fd, 408, "Request timeout");
        }
        return;
    }

    buffer[total_read] = '\0';

    /* Parse request */
    http_request_t request;
    if (!http_parse_request(buffer, total_read, &request)) {
        http_send_error(client_fd, 400, "Bad request");
        return;
    }

    /* Security checks */
    if (strstr(request.path, "..")) {
        http_send_error(client_fd, 403, "Path traversal not allowed");
        return;
    }

    /* Build file path */
    char file_path[1024];
    snprintf(file_path, sizeof(file_path), "%s/%s",
             server->root_dir,
             request.path[0] == '/' ? request.path + 1 : request.path);

    /* Open file */
    int fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        http_send_error(client_fd, 404, "File not found");
        return;
    }

    /* Get file size */
    off_t size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    /* Read file */
    char *content = malloc(size);
    if (!content) {
        close(fd);
        http_send_error(client_fd, 500, "Internal error");
        return;
    }

    if (read(fd, content, size) != size) {
        free(content);
        close(fd);
        http_send_error(client_fd, 500, "Read error");
        return;
    }

    close(fd);

    /* Send response */
    http_response_t response = {
        .status_code = 200,
        .content_type = "text/html",  /* TODO: detect content type */
        .body = content,
        .body_length = size
    };

    http_send_response(client_fd, &response);
    free(content);
}

/* Rest of server.c implementation... */