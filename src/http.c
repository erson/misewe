#include "http.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* Parse HTTP request line */
static bool parse_request_line(const char *line, http_request_t *req) {
    char method[16];

    /* Parse request line (e.g., "GET /path HTTP/1.1") */
    if (sscanf(line, "%15s %255s %15s", method, req->path, req->version) != 3) {
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

/* Parse HTTP headers */
static bool parse_headers(const char *buffer, size_t length, http_request_t *req) {
    const char *line = buffer;
    const char *end = buffer + length;
    size_t line_length;
    
    /* Skip first line (already parsed) */
    while (line < end && *line != '\n') line++;
    if (line >= end) return false;
    line++; /* skip \n */

    /* Parse headers */
    req->header_count = 0;
    while (line < end && req->header_count < 32) {
        /* Find end of line */
        const char *eol = memchr(line, '\n', end - line);
        if (!eol) break;
        line_length = eol - line;

        /* Empty line marks end of headers */
        if (line_length == 0 || (line_length == 1 && line[0] == '\r')) {
            return true;
        }

        /* Parse header line */
        const char *colon = memchr(line, ':', line_length);
        if (colon) {
            /* Copy header name */
            size_t name_length = colon - line;
            if (name_length >= sizeof(req->headers[0].name)) {
                name_length = sizeof(req->headers[0].name) - 1;
            }
            memcpy(req->headers[req->header_count].name, line, name_length);
            req->headers[req->header_count].name[name_length] = '\0';

            /* Skip colon and whitespace */
            const char *value = colon + 1;
            while (value < eol && isspace(*value)) value++;

            /* Copy header value */
            size_t value_length = eol - value;
            if (value_length > 0 && value[value_length-1] == '\r') {
                value_length--;
            }
            if (value_length >= sizeof(req->headers[0].value)) {
                value_length = sizeof(req->headers[0].value) - 1;
            }
            memcpy(req->headers[req->header_count].value, value, value_length);
            req->headers[req->header_count].value[value_length] = '\0';

            req->header_count++;
        }

        line = eol + 1;
    }

    return true;
}

/* Parse complete HTTP request */
bool http_parse_request(const char *buffer, size_t length, http_request_t *req) {
    const char *end_of_line;
    char first_line[512];
    size_t line_length;

    /* Validate input */
    if (!buffer || !req || length == 0) {
        return false;
    }

    /* Find end of first line */
    end_of_line = memchr(buffer, '\n', length);
    if (!end_of_line) {
        return false;
    }

    /* Copy and parse first line */
    line_length = end_of_line - buffer;
    if (line_length >= sizeof(first_line)) {
        line_length = sizeof(first_line) - 1;
    }
    memcpy(first_line, buffer, line_length);
    first_line[line_length] = '\0';

    if (!parse_request_line(first_line, req)) {
        return false;
    }

    /* Parse headers */
    return parse_headers(buffer, length, req);
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
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "X-XSS-Protection: 1; mode=block\r\n"
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