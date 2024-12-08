#ifndef HTTP_H
#define HTTP_H

#include <stddef.h>
#include <stdbool.h>
#include <time.h>

/* HTTP Methods */
typedef enum {
    HTTP_GET,
    HTTP_HEAD,
    HTTP_UNSUPPORTED
} http_method_t;

/* HTTP Status Codes */
typedef enum {
    HTTP_OK = 200,
    HTTP_BAD_REQUEST = 400,
    HTTP_FORBIDDEN = 403,
    HTTP_NOT_FOUND = 404,
    HTTP_METHOD_NOT_ALLOWED = 405,
    HTTP_REQUEST_TIMEOUT = 408,
    HTTP_ENTITY_TOO_LARGE = 413,
    HTTP_URI_TOO_LONG = 414,
    HTTP_INTERNAL_ERROR = 500
} http_status_t;

/* HTTP Request */
typedef struct {
    http_method_t method;
    char path[256];
    char query[256];
    struct {
        char name[32];
        char value[128];
    } headers[32];
    size_t header_count;
    time_t timestamp;
    size_t content_length;
} http_request_t;

/* HTTP Response */
typedef struct {
    http_status_t status;
    struct {
        char name[32];
        char value[128];
    } headers[32];
    size_t header_count;
    const char *body;
    size_t body_length;
} http_response_t;

/* Function prototypes */
bool http_parse_request(int fd, http_request_t *req, size_t max_size);
void http_send_response(int fd, const http_response_t *res);
void http_send_error(int fd, http_status_t status, const char *message);
const char *http_status_message(http_status_t status);
const char *http_get_mime_type(const char *path);

#endif /* HTTP_H */