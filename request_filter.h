#ifndef REQUEST_FILTER_H
#define REQUEST_FILTER_H

#include <stddef.h>
#include <stdbool.h>
#include <time.h>

/* Attack types for logging */
typedef enum {
    ATTACK_XSS,
    ATTACK_SQL_INJECTION,
    ATTACK_PATH_TRAVERSAL,
    ATTACK_COMMAND_INJECTION,
    ATTACK_INVALID_ENCODING,
    ATTACK_OVERSIZE_PAYLOAD,
    ATTACK_INVALID_METHOD
} attack_type_t;

/* Request validation context */
typedef struct {
    struct {
        size_t max_uri_length;
        size_t max_header_length;
        size_t max_headers;
        size_t max_body_size;
    } limits;
    
    struct {
        char **patterns;
        size_t count;
    } blacklist;

    bool log_attacks;
    void (*alert_callback)(attack_type_t, const char *, const char *);
} request_filter_t;

/* Function prototypes */
request_filter_t *request_filter_create(void);
void request_filter_destroy(request_filter_t *filter);
bool request_filter_check(request_filter_t *filter, 
                        const char *method,
                        const char *uri,
                        const char *headers,
                        const char *body,
                        size_t body_length);

#endif /* REQUEST_FILTER_H */