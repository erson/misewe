#ifndef LOGGER_H
#define LOGGER_H

#include <stddef.h>

/* Log levels */
typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_SECURITY
} log_level_t;

/* Logger context */
typedef struct logger logger_t;

/* Function prototypes */
logger_t *logger_create(const char *access_log, const char *error_log);
void logger_destroy(logger_t *logger);
void logger_log(logger_t *logger, log_level_t level, const char *format, ...);

#endif /* LOGGER_H */