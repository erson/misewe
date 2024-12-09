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
                       const void *body, size_t body_length,
                       const char *extra_headers) {
    char headers[4096];
    int header_len;

    /* Format headers */
    header_len = snprintf(headers, sizeof(headers),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n",
        status_code,
        status_code == 200 ? "OK" : "Error",
        content_type,
        body_length);

    /* Add extra headers if provided */
    if (extra_headers) {
        strncat(headers, extra_headers, sizeof(headers) - header_len - 1);
        header_len = strlen(headers);
    }

    /* Add final CRLF */
    strncat(headers, "\r\n", sizeof(headers) - header_len - 1);
    header_len = strlen(headers);

    /* Send headers */
    write(client_fd, headers, header_len);

    /* Send body */
    if (body && body_length > 0) {
        write(client_fd, body, body_length);
    }
}

void http_send_error(int client_fd, int status_code, const char *message) {
    /* Add security headers for error responses too */
    const char *security_headers = 
        "X-Frame-Options: DENY\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-XSS-Protection: 1; mode=block\r\n"
        "Content-Security-Policy: default-src 'self'\r\n"
        "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n";

    http_send_response(client_fd, status_code, "text/plain", 
                      message, strlen(message), security_headers);
}