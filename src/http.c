#include "http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Parse HTTP request */
bool http_parse_request(const char *buffer, size_t length, http_request_t *req) {
    char method[16];

    /* Parse request line */
    if (sscanf(buffer, "%15s %255s %15s", method, req->path,
               req->version) != 3) {
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

/* Send HTTP response */
void http_send_response(int client_fd, const http_response_t *resp) {
    char headers[1024];
    int header_len;

    /* Format response headers */
    header_len = snprintf(headers, sizeof(headers),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        resp->status_code,
        resp->status_code == 200 ? "OK" : "Error",
        resp->content_type,
        resp->body_length);

    /* Send headers */
    write(client_fd, headers, header_len);

    /* Send body */
    if (resp->body && resp->body_length > 0) {
        write(client_fd, resp->body, resp->body_length);
    }
}

/* Send HTTP error response */
void http_send_error(int client_fd, int status_code, const char *message) {
    http_response_t response = {
        .status_code = status_code,
        .content_type = "text/plain",
        .body = message,
        .body_length = strlen(message)
    };
    http_send_response(client_fd, &response);
}