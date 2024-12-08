#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>
#include <time.h>

/* Configuration */
#define SERVER_PORT     8000
#define SERVER_BACKLOG  10
#define MAX_CLIENTS     1000
#define TIMEOUT_SEC     30
#define REQ_PER_SEC     10
#define BUF_SIZE        4096

/* Custom types */
typedef struct server_ctx server_ctx_t;
typedef struct client_ctx client_ctx_t;
typedef struct http_request http_request_t;
typedef struct rate_limiter rate_limiter_t;

/* Error codes */
typedef enum {
    SERVER_OK = 0,
    SERVER_ERROR = -1,
    SERVER_NOMEM = -2,
    SERVER_INVALID = -3
} server_err_t;

/* Server context */
struct server_ctx {
    int fd;                     /* Server socket fd */
    uint16_t port;             /* Listen port */
    volatile int running;       /* Server running flag */
    rate_limiter_t *limiter;   /* Rate limiter */
};

/* Client context */
struct client_ctx {
    int fd;                     /* Client socket fd */
    char addr[16];             /* Client IP address */
    time_t timestamp;          /* Connection timestamp */
    http_request_t *request;   /* HTTP request */
};

/* Function prototypes */
server_ctx_t *server_create(uint16_t port);
void server_destroy(server_ctx_t *ctx);
server_err_t server_run(server_ctx_t *ctx);
void server_stop(server_ctx_t *ctx);

#endif /* SERVER_H */