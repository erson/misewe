#include "request_validator.h"
#include <string.h>
#include <ctype.h>

/* Known dangerous patterns */
static const char *dangerous_patterns[] = {
    "..", "//", "\\", "%2e", "%2f",
    "<?", "<%", "<script", "eval(",
    NULL
};

/* Allowed file extensions */
static const char *allowed_extensions[] = {
    ".html", ".css", ".js", ".txt", ".ico",
    NULL
};

/* Check if file extension is allowed */
static bool is_extension_allowed(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return false;

    for (const char **allowed = allowed_extensions; *allowed; allowed++) {
        if (strcasecmp(ext, *allowed) == 0) {
            return true;
        }
    }
    return false;
}

/* Validate path */
bool is_path_safe(const char *path) {
    /* Check for NULL or empty path */
    if (!path || !*path) return false;

    /* Check path length */
    if (strlen(path) > 255) return false;

    /* Check for dangerous patterns */
    for (const char **pattern = dangerous_patterns; *pattern; pattern++) {
        if (strstr(path, *pattern)) return false;
    }

    /* Check characters */
    for (const char *p = path; *p; p++) {
        if (!isalnum(*p) && !strchr("/-_.", *p)) {
            return false;
        }
    }

    return is_extension_allowed(path);
}

/* Check if method is allowed */
bool is_method_allowed(http_method_t method) {
    return method == HTTP_GET || method == HTTP_HEAD;
}

/* Validate entire request */
validation_result_t validate_request(const http_request_t *request) {
    validation_result_t result = {true, NULL};

    /* Check method */
    if (!is_method_allowed(request->method)) {
        result.valid = false;
        result.error = "Method not allowed";
        return result;
    }

    /* Check path */
    if (!is_path_safe(request->path)) {
        result.valid = false;
        result.error = "Invalid path";
        return result;
    }

    /* Add more validation as needed */

    return result;
}