#include "security_validator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Maximum sizes */
#define MAX_LINE_LENGTH 8192
#define MAX_HEADER_COUNT 100
#define MAX_URL_LENGTH 2000

/* Validation flags */
#define FLAG_DECODED       0x0001
#define FLAG_NORMALIZED   0x0002
#define FLAG_SUSPICIOUS   0x0004
#define FLAG_MALFORMED    0x0008

/* HTTP method validation */
static const char *valid_methods[] = {
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE",
    NULL
};

/* Known dangerous patterns */
static const char *dangerous_patterns[] = {
    "%00",          /* Null byte injection */
    "../../",       /* Directory traversal */
    "<script",      /* XSS */
    "UNION SELECT", /* SQL injection */
    "|",            /* Command injection */
    "eval(",        /* Code injection */
    NULL
};

/* Unicode normalization map */
static const struct {
    const char *encoded;
    char decoded;
} unicode_map[] = {
    {"%20", ' '},
    {"%22", '"'},
    {"%27", '\''},
    {"%2F", '/'},
    {"%5C", '\\'},
    {NULL, 0}
};

/* Validator context */
struct validator {
    validator_config_t config;
    char *decode_buffer;
    size_t buffer_size;
};

/* Create validator */
validator_t *validator_create(const validator_config_t *config) {
    validator_t *v = calloc(1, sizeof(*v));
    if (!v) return NULL;

    /* Copy configuration */
    v->config = *config;

    /* Allocate decode buffer */
    v->buffer_size = MAX_LINE_LENGTH;
    v->decode_buffer = malloc(v->buffer_size);
    if (!v->decode_buffer) {
        free(v);
        return NULL;
    }

    return v;
}

/* URL decode string */
static bool url_decode(const char *input, char *output, size_t outsize) {
    size_t i = 0, j = 0;

    while (input[i] && j < outsize - 1) {
        if (input[i] == '%') {
            if (isxdigit(input[i + 1]) && isxdigit(input[i + 2])) {
                char hex[3] = {input[i + 1], input[i + 2], 0};
                output[j] = strtol(hex, NULL, 16);
                i += 3;
            } else {
                return false;  /* Invalid encoding */
            }
        } else if (input[i] == '+') {
            output[j] = ' ';
            i++;
        } else {
            output[j] = input[i];
            i++;
        }
        j++;
    }

    output[j] = '\0';
    return i == strlen(input);
}

/* Normalize path */
static bool normalize_path(char *path) {
    char *src = path;
    char *dst = path;
    char *segment_start = path;
    int depth = 0;

    while (*src) {
        if (*src == '/') {
            /* Handle consecutive slashes */
            if (src == segment_start) {
                src++;
                segment_start++;
                continue;
            }

            /* Handle "." and ".." */
            size_t segment_len = src - segment_start;
            if (segment_len == 1 && *segment_start == '.') {
                /* Skip "." segment */
                dst = segment_start;
            } else if (segment_len == 2 && 
                      segment_start[0] == '.' && 
                      segment_start[1] == '.') {
                /* Handle ".." */
                depth--;
                if (depth < 0) return false;  /* Too many ".." */
                
                /* Find previous segment */
                while (dst > path && *--dst != '/');
            } else {
                depth++;
                if (dst != segment_start) {
                    memmove(dst, segment_start, segment_len);
                    dst += segment_len;
                } else {
                    dst += segment_len;
                }
                *dst++ = '/';
            }
            segment_start = src + 1;
        }
        src++;
    }

    /* Handle last segment */
    if (segment_start < src) {
        size_t segment_len = src - segment_start;
        if (segment_len == 1 && *segment_start == '.') {
            /* Skip "." segment */
        } else if (segment_len == 2 && 
                  segment_start[0] == '.' && 
                  segment_start[1] == '.') {
            depth--;
            if (depth < 0) return false;
            while (dst > path && *--dst != '/');
        } else {
            if (dst != segment_start) {
                memmove(dst, segment_start, segment_len);
                dst += segment_len;
            } else {
                dst += segment_len;
            }
        }
    }

    /* Null terminate */
    *dst = '\0';
    return true;
}

/* Check for dangerous patterns */
static bool check_dangerous_patterns(const char *str) {
    for (const char **pattern = dangerous_patterns; *pattern; pattern++) {
        if (strstr(str, *pattern)) {
            return false;
        }
    }
    return true;
}

/* Validate HTTP request */
static bool validate_http_request(
    validator_t *v,
    const char *data,
    size_t length,
    validation_result_t *result) {

    char line[MAX_LINE_LENGTH];
    char method[16], uri[MAX_URL_LENGTH], proto[16];
    size_t pos = 0;
    int line_len = 0;

    /* Parse request line */
    while (pos < length && data[pos] != '\n' && line_len < MAX_LINE_LENGTH - 1) {
        line[line_len++] = data[pos++];
    }
    line[line_len] = '\0';

    /* Parse method, URI, and protocol */
    if (sscanf(line, "%15s %1999s %15s", method, uri, proto) != 3) {
        snprintf(result->error, sizeof(result->error),
                "Invalid request line format");
        result->error_offset = 0;
        return false;
    }

    /* Validate method */
    bool valid_method = false;
    for (const char **m = valid_methods; *m; m++) {
        if (strcmp(method, *m) == 0) {
            valid_method = true;
            break;
        }
    }
    if (!valid_method) {
        snprintf(result->error, sizeof(result->error),
                "Invalid HTTP method: %s", method);
        result->error_offset = 0;
        return false;
    }

    /* Decode URI if configured */
    if (v->config.decode_payload) {
        if (!url_decode(uri, v->decode_buffer, v->buffer_size)) {
            snprintf(result->error, sizeof(result->error),
                    "Invalid URI encoding");
            result->error_offset = strlen(method) + 1;
            return false;
        }
        result->flags |= FLAG_DECODED;
        strcpy(uri, v->decode_buffer);
    }

    /* Normalize path if configured */
    if (v->config.normalize_path) {
        if (!normalize_path(uri)) {
            snprintf(result->error, sizeof(result->error),
                    "Invalid path (directory traversal attempt)");
            result->error_offset = strlen(method) + 1;
            return false;
        }
        result->flags |= FLAG_NORMALIZED;
    }

    /* Check for dangerous patterns */
    if (!check_dangerous_patterns(uri)) {
        snprintf(result->error, sizeof(result->error),
                "Dangerous pattern detected in URI");
        result->error_offset = strlen(method) + 1;
        return false;
    }

    /* Validate protocol */
    if (strcmp(proto, "HTTP/1.1") != 0 && strcmp(proto, "HTTP/1.0") != 0) {
        snprintf(result->error, sizeof(result->error),
                "Invalid HTTP protocol version");
        result->error_offset = strlen(method) + strlen(uri) + 2;
        return false;
    }

    /* Parse headers */
    int header_count = 0;
    while (pos < length && header_count < MAX_HEADER_COUNT) {
        /* Read header line */
        line_len = 0;
        while (pos < length && data[pos] != '\n' && 
               line_len < MAX_LINE_LENGTH - 1) {
            line[line_len++] = data[pos++];
        }
        line[line_len] = '\0';
        pos++;

        /* Check for end of headers */
        if (line_len == 0) break;

        /* Validate header format */
        char *colon = strchr(line, ':');
        if (!colon) {
            snprintf(result->error, sizeof(result->error),
                    "Invalid header format");
            result->error_offset = pos - line_len;
            return false;
        }

        header_count++;
    }

    /* Validate header count */
    if (header_count >= MAX_HEADER_COUNT) {
        snprintf(result->error, sizeof(result->error),
                "Too many headers");
        return false;
    }

    return true;
}

/* Main validation function */
bool validator_check_request(
    validator_t *v,
    const char *data,
    size_t length,
    validation_result_t *result) {

    if (!v || !data || !result) return false;

    /* Initialize result */
    memset(result, 0, sizeof(*result));

    /* Validate based on protocol */
    switch (v->config.protocol) {
        case PROTO_HTTP:
            result->valid = validate_http_request(v, data, length, result);
            break;

        case PROTO_WEBSOCKET:
            /* TODO: Implement WebSocket validation */
            snprintf(result->error, sizeof(result->error),
                    "WebSocket validation not implemented");
            result->valid = false;
            break;

        case PROTO_TLS:
            /* TODO: Implement TLS validation */
            snprintf(result->error, sizeof(result->error),
                    "TLS validation not implemented");
            result->valid = false;
            break;

        default:
            snprintf(result->error, sizeof(result->error),
                    "Unknown protocol type");
            result->valid = false;
            break;
    }

    return result->valid;
}

/* Clean up validator */
void validator_destroy(validator_t *v) {
    if (!v) return;
    free(v->decode_buffer);
    free(v);
}