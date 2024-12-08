#ifndef SECURE_LOG_H
#define SECURE_LOG_H

#include <stdarg.h>
#include <stdbool.h>

/* Log levels */
typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_SECURITY
} log_level_t;

/* Log context */
typedef struct secure_log secure_log_t;

/* Log configuration */
typedef struct {
    const char *log_dir;        /* Directory for log files */
    size_t max_file_size;       /* Maximum size per log file */
    size_t max_files;           /* Maximum number of rotation files */
    bool sync_writes;           /* Whether to sync writes immediately */
    bool encrypt_security;      /* Whether to encrypt security logs */
} log_config_t;

/* Function prototypes */
secure_log_t *secure_log_create(const log_config_t *config);
void secure_log_destroy(secure_log_t *log);
void secure_log(secure_log_t *log, log_level_t level,
                const char *file, int line, const char *fmt, ...);

/* Convenience macros */
#define LOG_DEBUG(log, ...) \
    secure_log(log, LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(log, ...) \
    secure_log(log, LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARN(log, ...) \
    secure_log(log, LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(log, ...) \
    secure_log(log, LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_SECURITY(log, ...) \
    secure_log(log, LOG_SECURITY, __FILE__, __LINE__, __VA_ARGS__)

#endif /* SECURE_LOG_H */