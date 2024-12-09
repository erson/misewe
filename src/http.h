#ifndef HTTP_H
#define HTTP_H

#include <stdbool.h>
#include <stddef.h>

/* HTTP methods */
typedef enum {
    HTTP_GET,
    HTTP_HEAD,
    HTTP_POST,
    HTTP_UNSUPPORTED
} http_method_t;

/* HTTP request structure */
typedef struct {
    http_method_t method;
    char path[256];
    char version[16];
} http_request_t;

/* Function prototypes */
bool http_parse_request(const char *buffer, size_t length, http_request_t *req);
void http_send_response(int client_fd, int status_code, 
                       const char *content_type, 
                       const void *body, size_t body_length,
                       const char *extra_headers);
void http_send_error(int client_fd, int status_code, const char *message);

#endif /* HTTP_H */ 