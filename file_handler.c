#include "file_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <errno.h>

#define MAX_PATH_LEN 256
#define MAX_FILE_SIZE (10 * 1024 * 1024)  /* 10MB */

struct file_handler {
    char root_dir[MAX_PATH_LEN];
};

/* Create file handler */
file_handler_t *file_handler_create(const char *root_dir) {
    file_handler_t *handler = malloc(sizeof(*handler));
    if (!handler) return NULL;

    strncpy(handler->root_dir, root_dir, MAX_PATH_LEN - 1);
    return handler;
}

/* Serve file */
bool file_handler_serve(file_handler_t *handler, const char *path, int client_fd) {
    char full_path[MAX_PATH_LEN];
    struct stat st;
    int fd;
    
    /* Build full path */
    if (snprintf(full_path, sizeof(full_path), "%s/%s",
                handler->root_dir, path + 1) >= sizeof(full_path)) {
        http_send_error(client_fd, HTTP_URI_TOO_LONG, "Path too long");
        return false;
    }

    /* Open file */
    fd = open(full_path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        if (errno == ENOENT) {
            http_send_error(client_fd, HTTP_NOT_FOUND, "File not found");
        } else {
            http_send_error(client_fd, HTTP_FORBIDDEN, "Access denied");
        }
        return false;
    }

    /* Get file info */
    if (fstat(fd, &st) < 0) {
        close(fd);
        http_send_error(client_fd, HTTP_INTERNAL_ERROR, "Failed to stat file");
        return false;
    }

    /* Security checks */
    if (!S_ISREG(st.st_mode) ||    /* Must be regular file */
        st.st_size > MAX_FILE_SIZE) /* Size limit */
    {
        close(fd);
        http_send_error(client_fd, HTTP_FORBIDDEN, "Access denied");
        return false;
    }

    /* Send response headers */
    http_response_t res = {
        .status = HTTP_OK,
        .body_length = st.st_size
    };

    /* Add headers */
    strncpy(res.headers[res.header_count].name, "Content-Type",
            MAX_HEADER_NAME - 1);
    strncpy(res.headers[res.header_count].value,
            http_get_mime_type(full_path), MAX_HEADER_VALUE - 1);
    res.header_count++;

    /* Add security headers */
    strncpy(res.headers[res.header_count].name, "X-Content-Type-Options",
            MAX_HEADER_NAME - 1);
    strncpy(res.headers[res.header_count].value, "nosniff",
            MAX_HEADER_VALUE - 1);
    res.header_count++;

    http_send_response(client_fd, &res);

    /* Send file using sendfile() */
    off_t offset = 0;
    while (offset < st.st_size) {
        ssize_t sent = sendfile(client_fd, fd, &offset, st.st_size - offset);
        if (sent <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            break;
        }
    }

    close(fd);
    return true;
}

/* Clean up file handler */
void file_handler_destroy(file_handler_t *handler) {
    free(handler);
}