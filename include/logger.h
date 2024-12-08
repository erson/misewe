#ifndef LOGGER_H
#define LOGGER_H

#include <stddef.h>

typedef enum {
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_SECURITY
} log_level_t;

void log_init(const char *access_log, const char *error_log);
void log_write(log_level_t level, const char *format, ...);
void log_cleanup(void);

#endif /* LOGGER_H */