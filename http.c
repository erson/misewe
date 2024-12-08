#include "http.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Parse HTTP request */
bool http_parse_request(const char *buffer, size_t length, http_request_t *req) {
    char method[16];
    char uri[512];

    /* Parse request line */
    if (sscanf(buffer, "%15s %511s %15s", method, uri, req->version) != 3) {
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

    /* Split URI into path and query */
    char *query = strchr(uri, '?');
    if (query) {
        *query++ = '\0';
        strncpy(req->query, query, sizeof(req->query) - 1);
    }

    /* Copy path */
    strncpy(req->path, uri, sizeof(req->path) - 1);

    return true;
}

/* Send HTTP response */
void http_send_response(int client_fd, const http_response_t *resp) {
    char headers[1024];
    int header_len;

    /* Format headers */
    header_len = snprintf(headers, sizeof(headers),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Server: SecureServer\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "X-XSS-Protection: 1; mode=block\r\n"
        "\r\n",
        resp->status_code,
        resp->status_code == 200 ? "OK" :
        resp->status_code == 404 ? "Not Found" : "Error",
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
    http_response_t resp = {
        .status_code = status_code,
        .content_type = "text/plain",
        .body = message,
        .body_length = strlen(message)
    };
    http_send_response(client_fd, &resp);
}