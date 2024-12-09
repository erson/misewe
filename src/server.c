#include "server.h"
#include "http.h"
#include <stdio.h>
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
#include <time.h>

/* Get formatted timestamp */
static char* get_timestamp(void) {
    static char buffer[32];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    return buffer;
}

/* Server context structure */
struct server {
    int sock_fd;
    server_config_t config;
    bool running;
};

/* Check if path contains traversal attempts */
static bool has_path_traversal(const char *path) {
    /* Check for basic traversal patterns */
    if (strstr(path, "..") || strstr(path, "//") || strstr(path, "\\"))
        return true;

    /* Check for encoded traversal */
    if (strstr(path, "%2e%2e") || strstr(path, "%2E%2E"))
        return true;

    /* Check for absolute paths */
    if (path[0] == '/')
        path++;  /* Skip leading slash for root-relative paths */
    else
        return true;  /* Reject non-root-relative paths */

    /* Normalize and check path components */
    char normalized[512];
    const char *src = path;
    char *dst = normalized;
    
    while (*src) {
        if (*src == '.' && (src[1] == '/' || src[1] == '\0'))
            return true;  /* Reject current directory marker */
        if (*src == '/' && src[1] == '/')
            return true;  /* Reject double slashes */
        *dst++ = *src++;
        if (dst - normalized >= (ptrdiff_t)sizeof(normalized) - 1)
            return true;  /* Path too long */
    }
    *dst = '\0';

    return false;
}

/* Check if file type is allowed */
static bool is_allowed_file_type(const char *path) {
    /* Allow root path */
    if (strcmp(path, "/") == 0) {
        return true;
    }

    /* Get file extension */
    const char *ext = strrchr(path, '.');
    if (!ext) {
        /* No extension - only allow if it's a directory */
        struct stat st;
        char fullpath[512] = "www";
        strncat(fullpath, path, sizeof(fullpath) - 4);
        if (stat(fullpath, &st) == 0 && S_ISDIR(st.st_mode))
            return true;
        return false;
    }

    /* List of allowed extensions */
    const char *allowed_exts[] = {
        ".html", ".htm",  /* HTML files */
        ".css",          /* Stylesheets */
        ".js",           /* JavaScript */
        ".txt",          /* Text files */
        ".ico",          /* Favicon */
        ".png", ".jpg", ".jpeg", ".gif",  /* Images */
        NULL
    };

    /* Check against allowed extensions */
    for (const char **allowed = allowed_exts; *allowed; allowed++) {
        if (strcasecmp(ext, *allowed) == 0) {
            return true;
        }
    }

    return false;
}

/* Build file path with security checks */
static bool build_file_path(const char *request_path, char *filepath, size_t filepath_size) {
    /* Basic sanity check */
    if (!request_path || !filepath || filepath_size < 5)
        return false;

    /* Check for path traversal */
    if (has_path_traversal(request_path))
        return false;

    /* Initialize with web root */
    strncpy(filepath, "www", filepath_size);
    filepath[filepath_size - 1] = '\0';

    /* Handle root path */
    if (strcmp(request_path, "/") == 0) {
        strncat(filepath, "/index.html", filepath_size - strlen(filepath) - 1);
        return true;
    }

    /* Append request path */
    if (strlen(filepath) + strlen(request_path) + 1 > filepath_size)
        return false;  /* Path would be too long */

    strncat(filepath, request_path, filepath_size - strlen(filepath) - 1);
    return true;
}

/* Add security headers to response */
static void add_security_headers(char *headers, size_t size) {
    strncat(headers, 
        "X-Frame-Options: DENY\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-XSS-Protection: 1; mode=block\r\n"
        "Content-Security-Policy: default-src 'self'\r\n"
        "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n",
        size - strlen(headers) - 1);
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

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(client_fd, (struct sockaddr*)&addr, &addr_len);
    
    printf("[%s] New connection from %s\n", get_timestamp(), inet_ntoa(addr.sin_addr));

    char buffer[4096];
    ssize_t bytes = read(client_fd, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        printf("[%s] Connection closed by %s\n", get_timestamp(), inet_ntoa(addr.sin_addr));
        close(client_fd);
        return NULL;
    }
    buffer[bytes] = '\0';

    /* Parse HTTP request */
    http_request_t req;
    if (!http_parse_request(buffer, bytes, &req)) {
        printf("[%s] Bad request from %s\n", get_timestamp(), inet_ntoa(addr.sin_addr));
        http_send_error(client_fd, 400, "Bad Request");
        close(client_fd);
        return NULL;
    }

    printf("[%s] Request: %s %s from %s\n", 
           get_timestamp(),
           req.method == HTTP_GET ? "GET" :
           req.method == HTTP_POST ? "POST" :
           req.method == HTTP_HEAD ? "HEAD" : "UNKNOWN",
           req.path,
           inet_ntoa(addr.sin_addr));

    /* Validate file type */
    if (!is_allowed_file_type(req.path)) {
        printf("[%s] Forbidden request for %s from %s\n", 
               get_timestamp(), req.path, inet_ntoa(addr.sin_addr));
        http_send_error(client_fd, 403, "Forbidden");
        close(client_fd);
        return NULL;
    }

    /* Build file path */
    char filepath[512];
    if (!build_file_path(req.path, filepath, sizeof(filepath))) {
        printf("[%s] Invalid path: %s from %s\n", 
               get_timestamp(), req.path, inet_ntoa(addr.sin_addr));
        http_send_error(client_fd, 400, "Bad Request");
        close(client_fd);
        return NULL;
    }

    /* Open and send file */
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        printf("[%s] File not found: %s (requested by %s)\n", 
               get_timestamp(), filepath, inet_ntoa(addr.sin_addr));
        http_send_error(client_fd, 404, "Not Found");
        close(client_fd);
        return NULL;
    }

    /* Get file size */
    struct stat st;
    if (fstat(fd, &st) < 0) {
        printf("[%s] Error reading file: %s\n", get_timestamp(), filepath);
        close(fd);
        http_send_error(client_fd, 500, "Internal Server Error");
        close(client_fd);
        return NULL;
    }

    /* Read and send file */
    char *content = malloc(st.st_size);
    if (!content) {
        printf("[%s] Memory allocation failed for file: %s\n", get_timestamp(), filepath);
        close(fd);
        http_send_error(client_fd, 500, "Internal Server Error");
        close(client_fd);
        return NULL;
    }

    if (read(fd, content, st.st_size) != st.st_size) {
        printf("[%s] Error reading file: %s\n", get_timestamp(), filepath);
        free(content);
        close(fd);
        http_send_error(client_fd, 500, "Internal Server Error");
        close(client_fd);
        return NULL;
    }

    /* Send response */
    char headers[4096];
    add_security_headers(headers, sizeof(headers));
    http_send_response(client_fd, 200, "text/html", content, st.st_size, headers);
    printf("[%s] Sent %s (%ld bytes) to %s\n", 
           get_timestamp(), filepath, (long)st.st_size, inet_ntoa(addr.sin_addr));

    /* Clean up */
    free(content);
    close(fd);
    close(client_fd);
    printf("[%s] Connection closed: %s\n", get_timestamp(), inet_ntoa(addr.sin_addr));
    return NULL;
}

/* Run server */
bool server_run(server_t *server) {
    if (!server || server->sock_fd < 0) return false;

    server->running = true;
    printf("[%s] Server is running and ready for connections\n", get_timestamp());
    
    while (server->running) {
        /* Accept client connection */
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int *client_fd = malloc(sizeof(int));
        if (!client_fd) {
            printf("[%s] Memory allocation failed for new connection\n", get_timestamp());
            continue;
        }

        *client_fd = accept(server->sock_fd, (struct sockaddr*)&client_addr, &client_len);
        if (*client_fd < 0) {
            printf("[%s] Failed to accept connection\n", get_timestamp());
            free(client_fd);
            continue;
        }

        /* Create thread to handle client */
        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, client_fd) != 0) {
            printf("[%s] Failed to create thread for client: %s\n", 
                   get_timestamp(), inet_ntoa(client_addr.sin_addr));
            close(*client_fd);
            free(client_fd);
            continue;
        }
        pthread_detach(thread);
    }

    return true;
}