#ifndef LOGGER_H
#define LOGGER_H

#include <stdarg.h>

/* Log levels */
typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} log_level_t;

/* Function prototypes */
void log_init(const char *log_file);
void log_write(log_level_t level, const char *fmt, ...);
void log_close(void);

#endif /* LOGGER_H */ 