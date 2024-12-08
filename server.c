#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include "server.h"

/* HTTP status codes */
#define HTTP_OK          200
#define HTTP_BAD_REQ     400
#define HTTP_FORBIDDEN   403
#define HTTP_NOT_FOUND   404
#define HTTP_RATE_LIMIT  429
#define HTTP_ERROR       500

/* Rate limiter implementation */
struct rate_limiter {
    struct {
        char addr[16];
        time_t hits[REQ_PER_SEC];
        size_t count;
    } clients[MAX_CLIENTS];
    size_t count;
};

/* HTTP request structure */
struct http_request {
    char method[8];
    char path[256];
    char version[16];
};

/* Static function declarations */
static server_err_t setup_socket(uint16_t port);
static server_err_t accept_client(server_ctx_t *ctx);
static server_err_t handle_client(client_ctx_t *client);
static void send_response(int fd, int status, const char *content_type, const void *body, size_t len);
static void send_error(int fd, int status, const char *message);
static int check_rate_limit(rate_limiter_t *limiter, const char *addr);
static int is_valid_path(const char *path);
static const char *get_content_type(const char *path);
static void cleanup_client(client_ctx_t *client);

/* Global server instance for signal handling */
static server_ctx_t *g_server = NULL;

/* Signal handler */
static void handle_signal(int sig) {
    (void)sig;  /* Unused parameter */
    if (g_server) {
        g_server->running = 0;
    }
}

/* Create server context */
server_ctx_t *server_create(uint16_t port) {
    server_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        return NULL;
    }

    ctx->port = port;
    ctx->running = 1;
    ctx->limiter = calloc(1, sizeof(*ctx->limiter));
    if (!ctx->limiter) {
        free(ctx);
        return NULL;
    }

    /* Set up signal handlers */
    g_server = ctx;
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    return ctx;
}

/* Destroy server context */
void server_destroy(server_ctx_t *ctx) {
    if (!ctx) return;
    
    if (ctx->fd > 0) {
        close(ctx->fd);
    }
    free(ctx->limiter);
    free(ctx);
    g_server = NULL;
}

/* Set up server socket */
static server_err_t setup_socket(uint16_t port) {
    int fd;
    struct sockaddr_in addr = {0};
    int opt = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return SERVER_ERROR;
    }

    /* Set socket options */
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Set receive/send timeouts */
    struct timeval tv = {
        .tv_sec = TIMEOUT_SEC,
        .tv_usec = 0
    };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Bind to localhost only */
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return SERVER_ERROR;
    }

    if (listen(fd, SERVER_BACKLOG) < 0) {
        close(fd);
        return SERVER_ERROR;
    }

    return fd;
}

/* Check rate limit for client */
static int check_rate_limit(rate_limiter_t *limiter, const char *addr) {
    time_t now = time(NULL);
    size_t i;

    /* Find existing client */
    for (i = 0; i < limiter->count; i++) {
        if (strcmp(limiter->clients[i].addr, addr) == 0) {
            size_t valid = 0;
            
            /* Count valid hits within last second */
            for (size_t j = 0; j < limiter->clients[i].count; j++) {
                if (now - limiter->clients[i].hits[j] <= 1) {
                    limiter->clients[i].hits[valid++] = limiter->clients[i].hits[j];
                }
            }
            
            limiter->clients[i].count = valid;
            
            /* Check if limit exceeded */
            if (valid >= REQ_PER_SEC) {
                return 0;
            }

            /* Add new hit */
            limiter->clients[i].hits[valid] = now;
            limiter->clients[i].count++;
            return 1;
        }
    }

    /* Add new client if space available */
    if (limiter->count < MAX_CLIENTS) {
        i = limiter->count++;
        strncpy(limiter->clients[i].addr, addr, sizeof(limiter->clients[i].addr) - 1);
        limiter->clients[i].hits[0] = now;
        limiter->clients[i].count = 1;
        return 1;
    }

    return 0;
}

/* Validate request path */
static int is_valid_path(const char *path) {
    static const char *allowed_ext[] = {".html", ".txt", ".css", ".js"};
    const char *ext;
    size_t i;

    /* Check for path traversal */
    if (strstr(path, "..") || path[0] == '/') {
        return 0;
    }

    /* Get file extension */
    ext = strrchr(path, '.');
    if (!ext) {
        return 0;
    }

    /* Check if extension is allowed */
    for (i = 0; i < sizeof(allowed_ext)/sizeof(allowed_ext[0]); i++) {
        if (strcmp(ext, allowed_ext[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

/* Get content type based on file extension */
static const char *get_content_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "text/plain";

    if (strcmp(ext, ".html") == 0) return "text/html";
    if (strcmp(ext, ".css") == 0) return "text/css";
    if (strcmp(ext, ".js") == 0) return "application/javascript";
    return "text/plain";
}

/* Send HTTP response */
static void send_response(int fd, int status, const char *content_type, 
                         const void *body, size_t len) {
    char header[BUF_SIZE];
    int header_len;

    header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "Content-Security-Policy: default-src 'self'\r\n"
        "\r\n",
        status,
        status == HTTP_OK ? "OK" : "Error",
        content_type,
        len);

    write(fd, header, header_len);
    if (body && len) {
        write(fd, body, len);
    }
}

/* Send HTTP error response */
static void send_error(int fd, int status, const char *message) {
    send_response(fd, status, "text/plain", message, strlen(message));
}

/* Handle client connection */
static server_err_t handle_client(client_ctx_t *client) {
    char buffer[BUF_SIZE];
    ssize_t bytes;
    int fd;
    struct stat st;
    char *content;

    /* Read request */
    bytes = read(client->fd, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        return SERVER_ERROR;
    }
    buffer[bytes] = '\0';

    /* Parse request */
    if (sscanf(buffer, "%7s %255s %15s",
               client->request->method,
               client->request->path,
               client->request->version) != 3) {
        send_error(client->fd, HTTP_BAD_REQ, "Bad Request");
        return SERVER_ERROR;
    }

    /* Only allow GET method */
    if (strcmp(client->request->method, "GET") != 0) {
        send_error(client->fd, HTTP_BAD_REQ, "Method Not Allowed");
        return SERVER_ERROR;
    }

    /* Validate path */
    if (!is_valid_path(client->request->path)) {
        send_error(client->fd, HTTP_FORBIDDEN, "Forbidden");
        return SERVER_ERROR;
    }

    /* Open and read file */
    fd = open(client->request->path, O_RDONLY);
    if (fd < 0) {
        send_error(client->fd, HTTP_NOT_FOUND, "Not Found");
        return SERVER_ERROR;
    }

    /* Get file size */
    if (fstat(fd, &st) < 0) {
        close(fd);
        send_error(client->fd, HTTP_ERROR, "Internal Error");
        return SERVER_ERROR;
    }

    /* Allocate buffer for file content */
    content = malloc(st.st_size);
    if (!content) {
        close(fd);
        send_error(client->fd, HTTP_ERROR, "Internal Error");
        return SERVER_ERROR;
    }

    /* Read file content */
    if (read(fd, content, st.st_size) != st.st_size) {
        free(content);
        close(fd);
        send_error(client->fd, HTTP_ERROR, "Internal Error");
        return SERVER_ERROR;
    }
    close(fd);

    /* Send response */
    send_response(client->fd, HTTP_OK, 
                 get_content_type(client->request->path),
                 content, st.st_size);
    free(content);

    return SERVER_OK;
}

/* Accept and handle client connection */
static server_err_t accept_client(server_ctx_t *ctx) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    client_ctx_t client = {0};
    http_request_t request = {0};

    /* Accept connection */
    client.fd = accept(ctx->fd, (struct sockaddr*)&addr, &addr_len);
    if (client.fd < 0) {
        return SERVER_ERROR;
    }

    /* Get client IP address */
    inet_ntop(AF_INET, &addr.sin_addr, client.addr, sizeof(client.addr));

    /* Check rate limit */
    if (!check_rate_limit(ctx->limiter, client.addr)) {
        send_error(client.fd, HTTP_RATE_LIMIT, "Rate Limit Exceeded");
        close(client.fd);
        return SERVER_ERROR;
    }

    /* Set client context */
    client.timestamp = time(NULL);
    client.request = &request;

    /* Handle client request */
    handle_client(&client);
    close(client.fd);

    return SERVER_OK;
}

/* Run server */
server_err_t server_run(server_ctx_t *ctx) {
    if (!ctx) {
        return SERVER_INVALID;
    }

    /* Set up server socket */
    ctx->fd = setup_socket(ctx->port);
    if (ctx->fd < 0) {
        return SERVER_ERROR;
    }

    printf("Server running on port %d\n", ctx->port);

    /* Main server loop */
    while (ctx->running) {
        accept_client(ctx);
    }

    return SERVER_OK;
}

/* Stop server */
void server_stop(server_ctx_t *ctx) {
    if (ctx) {
        ctx->running = 0;
    }
}