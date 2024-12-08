#include "request_filter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Known attack patterns */
static const char *attack_patterns[] = {
    /* XSS Patterns */
    "<script",
    "javascript:",
    "onerror=",
    "onload=",
    "eval(",
    
    /* SQL Injection */
    "UNION SELECT",
    "SELECT FROM",
    "DROP TABLE",
    "1=1--",
    "' OR '1'='1",
    
    /* Path Traversal */
    "../",
    "..\\",
    "%2e%2e%2f",
    "..%2f",
    
    /* Command Injection */
    "|",
    "&&",
    ";",
    "`",
    "$(", 
    
    /* File Inclusion */
    "php://",
    "file://",
    "data://",
    
    /* NULL terminator */
    NULL
};

/* Initialize request filter with default settings */
request_filter_t *request_filter_create(void) {
    request_filter_t *filter = calloc(1, sizeof(*filter));
    if (!filter) return NULL;

    /* Set conservative defaults */
    filter->limits.max_uri_length = 2048;
    filter->limits.max_header_length = 4096;
    filter->limits.max_headers = 50;
    filter->limits.max_body_size = 1024 * 1024; /* 1MB */

    /* Count patterns */
    size_t pattern_count = 0;
    while (attack_patterns[pattern_count]) {
        pattern_count++;
    }

    /* Allocate and copy patterns */
    filter->blacklist.patterns = calloc(pattern_count, sizeof(char *));
    if (!filter->blacklist.patterns) {
        free(filter);
        return NULL;
    }

    for (size_t i = 0; i < pattern_count; i++) {
        filter->blacklist.patterns[i] = strdup(attack_patterns[i]);
        if (!filter->blacklist.patterns[i]) {
            for (size_t j = 0; j < i; j++) {
                free(filter->blacklist.patterns[j]);
            }
            free(filter->blacklist.patterns);
            free(filter);
            return NULL;
        }
    }
    filter->blacklist.count = pattern_count;

    /* Enable logging by default */
    filter->log_attacks = true;

    return filter;
}

/* Check for attack patterns */
static bool check_patterns(request_filter_t *filter, const char *input, 
                         attack_type_t *attack_type) {
    if (!input) return false;

    /* Convert to lowercase for case-insensitive matching */
    char *lower = strdup(input);
    if (!lower) return false;
    
    for (char *p = lower; *p; p++) {
        *p = tolower(*p);
    }

    /* Check each pattern */
    bool found = false;
    for (size_t i = 0; i < filter->blacklist.count; i++) {
        if (strstr(lower, filter->blacklist.patterns[i])) {
            /* Determine attack type based on pattern */
            if (strstr(filter->blacklist.patterns[i], "script") ||
                strstr(filter->blacklist.patterns[i], "javascript")) {
                *attack_type = ATTACK_XSS;
            } else if (strstr(filter->blacklist.patterns[i], "SELECT") ||
                      strstr(filter->blacklist.patterns[i], "UNION")) {
                *attack_type = ATTACK_SQL_INJECTION;
            } else if (strstr(filter->blacklist.patterns[i], "../")) {
                *attack_type = ATTACK_PATH_TRAVERSAL;
            } else if (strchr("|;&`", filter->blacklist.patterns[i][0])) {
                *attack_type = ATTACK_COMMAND_INJECTION;
            }
            found = true;
            break;
        }
    }

    free(lower);
    return found;
}

/* Validate URI encoding */
static bool validate_uri_encoding(const char *uri) {
    while (*uri) {
        if (*uri == '%') {
            /* Need at least 2 more characters */
            if (!uri[1] || !uri[2]) return false;
            
            /* Check hex digits */
            if (!isxdigit(uri[1]) || !isxdigit(uri[2])) return false;
            
            uri += 3;
        } else {
            uri++;
        }
    }
    return true;
}

/* Main request validation function */
bool request_filter_check(request_filter_t *filter,
                        const char *method,
                        const char *uri,
                        const char *headers,
                        const char *body,
                        size_t body_length) {
    if (!filter || !method || !uri || !headers) return false;

    attack_type_t attack_type;

    /* Check sizes */
    if (strlen(uri) > filter->limits.max_uri_length) {
        if (filter->alert_callback) {
            filter->alert_callback(ATTACK_OVERSIZE_PAYLOAD, "URI", uri);
        }
        return false;
    }

    if (strlen(headers) > filter->limits.max_header_length) {
        if (filter->alert_callback) {
            filter->alert_callback(ATTACK_OVERSIZE_PAYLOAD, "Headers", headers);
        }
        return false;
    }

    if (body && body_length > filter->limits.max_body_size) {
        if (filter->alert_callback) {
            filter->alert_callback(ATTACK_OVERSIZE_PAYLOAD, "Body", 
                                 "Request body too large");
        }
        return false;
    }

    /* Validate method */
    if (strcmp(method, "GET") != 0 && 
        strcmp(method, "HEAD") != 0 && 
        strcmp(method, "POST") != 0) {
        if (filter->alert_callback) {
            filter->alert_callback(ATTACK_INVALID_METHOD, method, 
                                 "Invalid HTTP method");
        }
        return false;
    }

    /* Check URI encoding */
    if (!validate_uri_encoding(uri)) {
        if (filter->alert_callback) {
            filter->alert_callback(ATTACK_INVALID_ENCODING, uri, 
                                 "Invalid URI encoding");
        }
        return false;
    }

    /* Check for attack patterns */
    if (check_patterns(filter, uri, &attack_type) ||
        check_patterns(filter, headers, &attack_type) ||
        (body && check_patterns(filter, body, &attack_type))) {
        
        if (filter->alert_callback) {
            filter->alert_callback(attack_type, uri, 
                                 "Attack pattern detected");
        }
        return false;
    }

    return true;
}

/* Clean up request filter */
void request_filter_destroy(request_filter_t *filter) {
    if (!filter) return;

    for (size_t i = 0; i < filter->blacklist.count; i++) {
        free(filter->blacklist.patterns[i]);
    }
    free(filter->blacklist.patterns);
    free(filter);
}