#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "security.h"
#include "logger.h"

/* Default security headers */
static const char *default_headers[] = {
    "X-Content-Type-Options: nosniff",
    "X-Frame-Options: DENY",
    "X-XSS-Protection: 1; mode=block",
    "Content-Security-Policy: default-src 'self'",
    "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    "Referrer-Policy: no-referrer",
    "Permissions-Policy: geolocation=(), microphone=()",
    "Cache-Control: no-store, no-cache, must-revalidate",
    NULL
};

/* Initialize security context with safe defaults */
security_ctx_t *security_init(void) {
    security_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    /* Set conservative limits */
    ctx->max_request_size = 4096;
    ctx->max_response_size = 1048576;  /* 1MB */
    ctx->max_requests_per_window = 10;
    ctx->window_seconds = 1;
    ctx->timeout_seconds = 30;
    ctx->max_header_count = 50;

    /* Allow only GET method by default */
    strncpy(ctx->allowed_methods[0], "GET", 15);
    ctx->method_count = 1;

    /* Set allowed file extensions */
    strncpy(ctx->allowed_extensions[0], ".html", 15);
    strncpy(ctx->allowed_extensions[1], ".txt", 15);
    strncpy(ctx->allowed_extensions[2], ".css", 15);
    strncpy(ctx->allowed_extensions[3], ".js", 15);
    ctx->extension_count = 4;

    /* Copy security headers */
    size_t i;
    for (i = 0; default_headers[i]; i++) {
        ctx->security_headers = realloc(ctx->security_headers, 
                                      (i + 1) * sizeof(char *));
        ctx->security_headers[i] = strdup(default_headers[i]);
        ctx->header_count++;
    }

    return ctx;
}

/* Input sanitization */
int sanitize_input(char *buf, size_t size) {
    size_t i;
    int modified = 0;

    for (i = 0; i < size && buf[i]; i++) {
        /* Remove control characters */
        if (iscntrl(buf[i]) && buf[i] != '\r' && buf[i] != '\n') {
            buf[i] = ' ';
            modified = 1;
            continue;
        }

        /* Remove potential SQL injection characters */
        if (buf[i] == '\'' || buf[i] == '"' || buf[i] == ';') {
            buf[i] = ' ';
            modified = 1;
            continue;
        }

        /* Remove potential command injection characters */
        if (buf[i] == '|' || buf[i] == '&' || buf[i] == '`') {
            buf[i] = ' ';
            modified = 1;
            continue;
        }

        /* URL encode special characters */
        if (!isalnum(buf[i]) && !strchr(".-_/", buf[i])) {
            /* Basic characters are allowed through */
            if (!strchr(" @,()[]{}+=", buf[i])) {
                buf[i] = '_';
                modified = 1;
            }
        }
    }

    /* Ensure null termination */
    if (size > 0) {
        buf[size - 1] = '\0';
    }

    return modified;
}

/* Path validation with extended security checks */
static int is_path_valid(const char *path) {
    /* Check for NULL or empty path */
    if (!path || !*path) return 0;

    /* Check path length */
    if (strlen(path) > 255) return 0;

    /* Check for directory traversal */
    if (strstr(path, "..")) return 0;
    if (strstr(path, "//")) return 0;

    /* Check for hidden files */
    if (path[0] == '.') return 0;

    /* Check for suspicious patterns */
    const char *suspicious[] = {
        "exec", "eval", "system", "cmd", "script",
        "passwd", "shadow", "config", "php", "asp",
        NULL
    };

    for (const char **s = suspicious; *s; s++) {
        if (strcasestr(path, *s)) return 0;
    }

    return 1;
}

/* Validate HTTP request */
validation_result_t validate_request(security_ctx_t *ctx, const char *method,
                                   const char *path, const char *headers) {
    size_t i;
    
    /* Validate method */
    int method_valid = 0;
    for (i = 0; i < ctx->method_count; i++) {
        if (strcasecmp(method, ctx->allowed_methods[i]) == 0) {
            method_valid = 1;
            break;
        }
    }
    if (!method_valid) {
        ERROR_LOG("Invalid method attempt: %s", method);
        return INVALID_METHOD;
    }

    /* Validate path */
    if (!is_path_valid(path)) {
        ERROR_LOG("Invalid path attempt: %s", path);
        return INVALID_PATH;
    }

    /* Validate file extension */
    const char *ext = strrchr(path, '.');
    if (!ext) return INVALID_PATH;

    int ext_valid = 0;
    for (i = 0; i < ctx->extension_count; i++) {
        if (strcasecmp(ext, ctx->allowed_extensions[i]) == 0) {
            ext_valid = 1;
            break;
        }
    }
    if (!ext_valid) {
        ERROR_LOG("Invalid extension attempt: %s", ext);
        return INVALID_PATH;
    }

    /* Count headers */
    size_t header_count = 0;
    const char *ptr = headers;
    while ((ptr = strchr(ptr, '\n'))) {
        header_count++;
        ptr++;
        if (header_count > ctx->max_header_count) {
            ERROR_LOG("Too many headers: %zu", header_count);
            return INVALID_HEADERS;
        }
    }

    return VALID_REQUEST;
}

/* Add security headers to response */
void add_security_headers(char *response, size_t size) {
    size_t pos = strlen(response);
    size_t remaining = size - pos;

    /* Add all security headers */
    const char **header = default_headers;
    while (*header && remaining > 0) {
        int written = snprintf(response + pos, remaining, "%s\r\n", *header);
        if (written > 0) {
            pos += written;
            remaining -= written;
        }
        header++;
    }

    /* Add extra protection headers */
    if (remaining > 0) {
        snprintf(response + pos, remaining,
                "Feature-Policy: "
                "camera 'none'; "
                "microphone 'none'; "
                "geolocation 'none'; "
                "payment 'none'\r\n");
    }
}

/* Clean up security context */
void security_cleanup(security_ctx_t *ctx) {
    if (!ctx) return;

    /* Free security headers */
    for (size_t i = 0; i < ctx->header_count; i++) {
        free(ctx->security_headers[i]);
    }
    free(ctx->security_headers);

    /* Free blocked IPs */
    for (size_t i = 0; i < ctx->blocked_count; i++) {
        free(ctx->blocked_ips[i]);
    }
    free(ctx->blocked_ips);

    free(ctx);
}