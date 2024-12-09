#include "http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

bool http_parse_request(const char *buffer, __attribute__((unused)) size_t length, http_request_t *req) {
    char method[16];
    
    /* Parse request line */
    if (sscanf(buffer, "%15s %255s %15s", method, req->path, req->version) != 3) {
        return false;
    }

    /* Parse method */
    if (strcmp(method, "GET") == 0) {
        req->method = HTTP_GET;
    } else if (strcmp(method, "HEAD") == 0) {
        req->method = HTTP_HEAD;
    } else if (strcmp(method, "POST") == 0) {
        req->method = HTTP_POST;
    } else {
        req->method = HTTP_UNSUPPORTED;
        return false;
    }

    return true;
}

void http_send_response(int client_fd, int status_code, 
                       const char *content_type, 
                       const void *body, size_t body_length) {
    char headers[1024];
    int header_len;

    /* Format headers */
    header_len = snprintf(headers, sizeof(headers),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        status_code,
        status_code == 200 ? "OK" : "Error",
        content_type,
        body_length);

    /* Send headers */
    write(client_fd, headers, header_len);

    /* Send body */
    if (body && body_length > 0) {
        write(client_fd, body, body_length);
    }
}

void http_send_error(int client_fd, int status_code, const char *message) {
    http_send_response(client_fd, status_code, "text/plain", 
                      message, strlen(message));
}