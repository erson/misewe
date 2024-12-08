#ifndef LOGGER_H
#define LOGGER_H

#include <stdarg.h>

typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} log_level_t;

void logger_init(const char *filename);
void logger_log(log_level_t level, const char *fmt, ...);
void logger_cleanup(void);

#ifdef DEBUG
#define DEBUG_LOG(...) logger_log(LOG_DEBUG, __VA_ARGS__)
#else
#define DEBUG_LOG(...) ((void)0)
#endif

#define INFO_LOG(...) logger_log(LOG_INFO, __VA_ARGS__)
#define WARN_LOG(...) logger_log(LOG_WARN, __VA_ARGS__)
#define ERROR_LOG(...) logger_log(LOG_ERROR, __VA_ARGS__)

#endif /* LOGGER_H */