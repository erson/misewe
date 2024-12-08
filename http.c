#include "http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>

/* Security: Maximum sizes for various components */
#define MAX_METHOD_LEN      16
#define MAX_PATH_LEN       256
#define MAX_QUERY_LEN      256
#define MAX_HEADER_NAME     32
#define MAX_HEADER_VALUE   128
#define MAX_HEADERS        32
#define MAX_LINE_LEN      512

/* Static function declarations */
static bool parse_request_line(char *line, http_request_t *req);
static bool parse_header_line(char *line, http_request_t *req);
static bool validate_path(const char *path);
static void trim(char *str);

/* Parse HTTP request from socket */
bool http_parse_request(int fd, http_request_t *req, size_t max_size) {
    char line[MAX_LINE_LEN];
    size_t total_size = 0;
    ssize_t bytes_read;
    int line_pos = 0;
    bool first_line = true;
    bool headers_done = false;

    memset(req, 0, sizeof(*req));
    req->timestamp = time(NULL);

    /* Read request line by line */
    while ((bytes_read = read(fd, line + line_pos, 1)) == 1) {
        total_size++;
        if (total_size > max_size) {
            return false;  /* Request too large */
        }

        /* Check for line end */
        if (line[line_pos] == '\n') {
            line[line_pos] = '\0';
            if (line_pos > 0 && line[line_pos - 1] == '\r') {
                line[line_pos - 1] = '\0';
            }

            /* Empty line marks end of headers */
            if (line_pos <= 1) {
                headers_done = true;
                break;
            }

            /* Parse line */
            if (first_line) {
                if (!parse_request_line(line, req)) {
                    return false;
                }
                first_line = false;
            } else {
                if (!parse_header_line(line, req)) {
                    return false;
                }
            }

            line_pos = 0;
        } else {
            if (line_pos >= MAX_LINE_LEN - 1) {
                return false;  /* Line too long */
            }
            line_pos++;
        }
    }

    return headers_done && bytes_read >= 0;
}

/* Parse the request line (GET /path HTTP/1.1) */
static bool parse_request_line(char *line, http_request_t *req) {
    char method[MAX_METHOD_LEN];
    char uri[MAX_PATH_LEN + MAX_QUERY_LEN];
    char protocol[16];

    /* Parse request line */
    if (sscanf(line, "%15s %255s %15s", method, uri, protocol) != 3) {
        return false;
    }

    /* Validate HTTP protocol version */
    if (strcmp(protocol, "HTTP/1.1") != 0) {
        return false;
    }

    /* Parse method */
    if (strcmp(method, "GET") == 0) {
        req->method = HTTP_GET;
    } else if (strcmp(method, "HEAD") == 0) {
        req->method = HTTP_HEAD;
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

    /* Validate and copy path */
    if (!validate_path(uri)) {
        return false;
    }
    strncpy(req->path, uri, sizeof(req->path) - 1);

    return true;
}

/* Parse a header line */
static bool parse_header_line(char *line, http_request_t *req) {
    char *value = strchr(line, ':');
    if (!value) {
        return false;
    }

    *value++ = '\0';
    trim(line);   /* Header name */
    trim(value);  /* Header value */

    /* Validate header name and value lengths */
    if (strlen(line) >= MAX_HEADER_NAME || strlen(value) >= MAX_HEADER_VALUE) {
        return false;
    }

    /* Check if we have room for another header */
    if (req->header_count >= MAX_HEADERS) {
        return false;
    }

    /* Store header */
    strncpy(req->headers[req->header_count].name, line, MAX_HEADER_NAME - 1);
    strncpy(req->headers[req->header_count].value, value, MAX_HEADER_VALUE - 1);
    req->header_count++;

    /* Parse special headers */
    if (strcasecmp(line, "Content-Length") == 0) {
        req->content_length = atol(value);
    }

    return true;
}

/* Validate request path */
static bool validate_path(const char *path) {
    /* Path must start with / */
    if (path[0] != '/') {
        return false;
    }

    /* Check for directory traversal attempts */
    if (strstr(path, "..") || strstr(path, "//")) {
        return false;
    }

    /* Check for suspicious characters */
    const char *p = path;
    while (*p) {
        if (!isalnum(*p) && !strchr("/_-.", *p)) {
            return false;
        }
        p++;
    }

    return true;
}

/* Send HTTP response */
void http_send_response(int fd, const http_response_t *res) {
    char buffer[MAX_LINE_LEN];
    int len;

    /* Send status line */
    len = snprintf(buffer, sizeof(buffer), "HTTP/1.1 %d %s\r\n",
                  res->status, http_status_message(res->status));
    write(fd, buffer, len);

    /* Send headers */
    for (size_t i = 0; i < res->header_count; i++) {
        len = snprintf(buffer, sizeof(buffer), "%s: %s\r\n",
                      res->headers[i].name, res->headers[i].value);
        write(fd, buffer, len);
    }

    /* Send content length */
    len = snprintf(buffer, sizeof(buffer), "Content-Length: %zu\r\n",
                  res->body_length);
    write(fd, buffer, len);

    /* End headers */
    write(fd, "\r\n", 2);

    /* Send body */
    if (res->body && res->body_length > 0) {
        write(fd, res->body, res->body_length);
    }
}

/* Send error response */
void http_send_error(int fd, http_status_t status, const char *message) {
    http_response_t res = {
        .status = status,
        .body = message,
        .body_length = strlen(message)
    };

    /* Add security headers */
    strncpy(res.headers[res.header_count].name, "Content-Type",
            MAX_HEADER_NAME - 1);
    strncpy(res.headers[res.header_count].value, "text/plain",
            MAX_HEADER_VALUE - 1);
    res.header_count++;

    strncpy(res.headers[res.header_count].name, "X-Content-Type-Options",
            MAX_HEADER_NAME - 1);
    strncpy(res.headers[res.header_count].value, "nosniff",
            MAX_HEADER_VALUE - 1);
    res.header_count++;

    http_send_response(fd, &res);
}

/* Get HTTP status message */
const char *http_status_message(http_status_t status) {
    switch (status) {
        case HTTP_OK:                  return "OK";
        case HTTP_BAD_REQUEST:         return "Bad Request";
        case HTTP_FORBIDDEN:           return "Forbidden";
        case HTTP_NOT_FOUND:           return "Not Found";
        case HTTP_METHOD_NOT_ALLOWED:  return "Method Not Allowed";
        case HTTP_REQUEST_TIMEOUT:     return "Request Timeout";
        case HTTP_ENTITY_TOO_LARGE:    return "Request Entity Too Large";
        case HTTP_URI_TOO_LONG:        return "URI Too Long";
        case HTTP_INTERNAL_ERROR:      return "Internal Server Error";
        default:                       return "Unknown";
    }
}

/* Get MIME type for file */
const char *http_get_mime_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";

    if (strcasecmp(ext, ".html") == 0) return "text/html";
    if (strcasecmp(ext, ".css") == 0)  return "text/css";
    if (strcasecmp(ext, ".js") == 0)   return "application/javascript";
    if (strcasecmp(ext, ".txt") == 0)  return "text/plain";
    if (strcasecmp(ext, ".ico") == 0)  return "image/x-icon";

    return "application/octet-stream";
}

/* Trim whitespace from string */
static void trim(char *str) {
    char *start = str;
    char *end;

    /* Trim leading space */
    while (isspace(*start)) start++;
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }

    /* Trim trailing space */
    end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) end--;
    *(end + 1) = '\0';
}