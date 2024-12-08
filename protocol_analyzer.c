#include "protocol_analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* HTTP methods we recognize */
static const char *http_methods[] = {
    "GET", "POST", "HEAD", "PUT", "DELETE",
    "CONNECT", "OPTIONS", "TRACE", "PATCH",
    NULL
};

/* Known HTTP versions */
static const char *http_versions[] = {
    "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3",
    NULL
};

/* Suspicious patterns */
static const char *suspicious_patterns[] = {
    "base64", "eval", "fromCharCode",
    "\\x", "\\u", "%u", "chr(",
    NULL
};

/* Initialize analyzer */
analyzer_t *analyzer_create(void) {
    return calloc(1, sizeof(analyzer_t));
}

/* Check if string is base64 encoded */
static bool is_base64(const char *str, size_t len) {
    size_t i;
    int pad = 0;

    if (len % 4 != 0) return false;

    for (i = 0; i < len; i++) {
        char c = str[i];
        if (c == '=') {
            pad++;
        } else if (!isalnum(c) && c != '+' && c != '/') {
            return false;
        }
    }

    return pad <= 2;
}

/* Check for protocol violations */
static uint32_t check_violations(const void *data, size_t length) {
    uint32_t score = 0;
    const unsigned char *bytes = data;

    /* Check for control characters in unexpected places */
    for (size_t i = 0; i < length; i++) {
        if (bytes[i] < 32 && bytes[i] != '\r' && bytes[i] != '\n' && bytes[i] != '\t') {
            score += 10;
        }
    }

    /* Check for unusually long lines */
    size_t line_length = 0;
    for (size_t i = 0; i < length; i++) {
        if (bytes[i] == '\n') {
            if (line_length > 4096) score += 20;
            line_length = 0;
        } else {
            line_length++;
        }
    }

    /* Check for invalid characters in headers */
    bool in_headers = true;
    for (size_t i = 0; i < length && in_headers; i++) {
        if (i > 0 && bytes[i] == '\n' && bytes[i-1] == '\n') {
            in_headers = false;
        }
        if (in_headers && bytes[i] > 127) {
            score += 5;
        }
    }

    return score;
}

/* Parse HTTP request */
static bool parse_http(const char *data, size_t length,
                      analysis_result_t *result) {
    char line[4096];
    size_t pos = 0;
    size_t line_len = 0;

    /* Parse first line */
    while (pos < length && data[pos] != '\n' && line_len < sizeof(line) - 1) {
        line[line_len++] = data[pos++];
    }
    line[line_len] = '\0';

    /* Parse method, path, version */
    char method[16], path[256], version[16];
    if (sscanf(line, "%15s %255s %15s", method, path, version) != 3) {
        return false;
    }

    /* Validate method */
    bool valid_method = false;
    for (const char **m = http_methods; *m; m++) {
        if (strcmp(method, *m) == 0) {
            valid_method = true;
            break;
        }
    }
    if (!valid_method) {
        return false;
    }

    /* Validate version */
    bool valid_version = false;
    for (const char **v = http_versions; *v; v++) {
        if (strcmp(version, *v) == 0) {
            valid_version = true;
            break;
        }
    }
    if (!valid_version) {
        return false;
    }

    /* Store results */
    strncpy(result->http.method, method, sizeof(result->http.method) - 1);
    strncpy(result->http.path, path, sizeof(result->http.path) - 1);
    strncpy(result->http.version, version, sizeof(result->http.version) - 1);

    return true;
}

/* Check for obfuscation */
static bool check_obfuscation(const char *data, size_t length,
                            analysis_result_t *result) {
    /* Check for common obfuscation patterns */
    for (const char **pattern = suspicious_patterns; *pattern; pattern++) {
        if (memmem(data, length, *pattern, strlen(*pattern))) {
            return true;
        }
    }

    /* Check for high entropy (possible encryption) */
    unsigned char counts[256] = {0};
    float entropy = 0;

    for (size_t i = 0; i < length; i++) {
        counts[(unsigned char)data[i]]++;
    }

    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            float p = (float)counts[i] / length;
            entropy -= p * log2f(p);
        }
    }

    /* Entropy threshold for encrypted/compressed data */
    if (entropy > 7.5) {
        result->flags |= ANALYSIS_ENCRYPTED;
        return true;
    }

    /* Check for base64 encoded sections */
    const char *b64_start = strstr(data, "base64,");
    if (b64_start) {
        b64_start += 7;
        size_t b64_len = strcspn(b64_start, "\r\n;");
        if (is_base64(b64_start, b64_len)) {
            return true;
        }
    }

    return false;
}

/* Analyze packet */
bool analyzer_check_packet(analyzer_t *analyzer,
                         const void *data,
                         size_t length,
                         analysis_result_t *result) {
    if (!analyzer || !data || !result || length == 0) {
        return false;
    }

    /* Initialize result */
    memset(result, 0, sizeof(*result));
    result->protocol = PROTO_UNKNOWN;

    /* Try to identify protocol */
    const char *str_data = (const char *)data;
    
    /* Check for HTTP */
    for (const char **method = http_methods; *method; method++) {
        size_t len = strlen(*method);
        if (length > len && memcmp(data, *method, len) == 0 &&
            str_data[len] == ' ') {
            result->protocol = PROTO_HTTP_1;
            if (!parse_http(str_data, length, result)) {
                result->flags |= ANALYSIS_MALFORMED;
            }
            break;
        }
    }

    /* Check for HTTP/2 preface */
    if (length >= 24 && memcmp(data, "PRI * HTTP/2.0\r\n\r\n", 16) == 0) {
        result->protocol = PROTO_HTTP_2;
    }

    /* Check for WebSocket */
    if (length >= 4 && str_data[0] == '\x81') {
        result->protocol = PROTO_WEBSOCKET;
    }

    /* Check for TLS */
    if (length >= 5 && str_data[0] == '\x16' && str_data[1] == '\x03') {
        result->protocol = PROTO_TLS;
    }

    /* Check for protocol violations */
    result->anomaly_score = check_violations(data, length);
    if (result->anomaly_score > 50) {
        result->flags |= ANALYSIS_SUSPICIOUS;
    }

    /* Check for obfuscation/encoding */
    if (check_obfuscation(str_data, length, result)) {
        result->flags |= ANALYSIS_OBFUSCATED;
    }

    /* Generate details */
    char *p = result->details;
    size_t remaining = sizeof(result->details);
    int written;

    /* Protocol info */
    written = snprintf(p, remaining, "Protocol: %s, ",
                      result->protocol == PROTO_HTTP_1 ? "HTTP/1.x" :
                      result->protocol == PROTO_HTTP_2 ? "HTTP/2" :
                      result->protocol == PROTO_WEBSOCKET ? "WebSocket" :
                      result->protocol == PROTO_TLS ? "TLS" : "Unknown");
    p += written;
    remaining -= written;

    /* Flags */
    if (result->flags & ANALYSIS_SUSPICIOUS)
        written = snprintf(p, remaining, "SUSPICIOUS ");
    if (result->flags & ANALYSIS_MALFORMED)
        written = snprintf(p, remaining, "MALFORMED ");
    if (result->flags & ANALYSIS_OBFUSCATED)
        written = snprintf(p, remaining, "OBFUSCATED ");
    if (result->flags & ANALYSIS_ENCRYPTED)
        written = snprintf(p, remaining, "ENCRYPTED ");
    
    /* Anomaly score */
    snprintf(p, remaining, "(Score: %u)", result->anomaly_score);

    return true;
}

/* Clean up */
void analyzer_destroy(analyzer_t *analyzer) {
    free(analyzer);
}