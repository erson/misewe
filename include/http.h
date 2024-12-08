#ifndef HTTP_H
#define HTTP_H

#include <stddef.h>
#include <stdbool.h>

/* HTTP Methods */
typedef enum {
    HTTP_GET,
    HTTP_HEAD,
    HTTP_POST,
    HTTP_UNSUPPORTED
} http_method_t;

/* HTTP Request */
typedef struct {
    http_method_t method;
    char path[256];
    char version[16];
    size_t content_length;
} http_request_t;

/* HTTP Response */
typedef struct {
    int status_code;
    const char *content_type;
    const void *body;
    size_t body_length;
} http_response_t;

/* Function prototypes */
bool http_parse_request(const char *buffer, size_t length, http_request_t *req);
void http_send_response(int client_fd, const http_response_t *resp);
void http_send_error(int client_fd, int status_code, const char *message);

#endif /* HTTP_H */