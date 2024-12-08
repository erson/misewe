#ifndef SECURITY_H
#define SECURITY_H

#include <stdbool.h>
#include <time.h>

/* Rate limiting context */
typedef struct {
    char ip[16];
    time_t *requests;
    size_t count;
    time_t window_start;
} rate_limit_t;

/* Content type mapping */
typedef struct {
    const char *ext;
    const char *mime_type;
} mime_type_t;

/* Security checks */
bool check_rate_limit(const char *ip);
const char *get_mime_type(const char *path);
bool is_path_safe(const char *path);
void log_access(const char *ip, const char *method, const char *path, int status);
void log_error(const char *ip, const char *message);

#endif /* SECURITY_H */