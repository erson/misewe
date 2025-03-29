#ifndef HTTP_H
#define HTTP_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

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

/* Get MIME type from file extension */
const char *http_get_mime_type(const char *path);

/* Generate a simple ETag from file mtime and size */
char *http_generate_etag(time_t mtime, size_t size);

/* Check if client's If-None-Match header matches our ETag */
bool http_check_etag_match(const char *request, const char *etag);

void http_send_response(int client_fd, int status_code, 
                       const char *content_type, 
                       const void *body, size_t body_length,
                       const char *extra_headers);
                       
void http_send_error(int client_fd, int status_code, const char *message);

#endif /* HTTP_H */