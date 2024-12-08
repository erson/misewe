#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>

struct logger {
    FILE *access_file;
    FILE *error_file;
    pthread_mutex_t lock;
};

/* Create logger */
logger_t *logger_create(const char *access_log, const char *error_log) {
    logger_t *logger = calloc(1, sizeof(*logger));
    if (!logger) return NULL;

    /* Open log files */
    logger->access_file = fopen(access_log, "a");
    logger->error_file = fopen(error_log, "a");

    if (!logger->access_file || !logger->error_file) {
        if (logger->access_file) fclose(logger->access_file);
        if (logger->error_file) fclose(logger->error_file);
        free(logger);
        return NULL;
    }

    /* Initialize mutex */
    if (pthread_mutex_init(&logger->lock, NULL) != 0) {
        fclose(logger->access_file);
        fclose(logger->error_file);
        free(logger);
        return NULL;
    }

    /* Disable buffering */
    setbuf(logger->access_file, NULL);
    setbuf(logger->error_file, NULL);

    return logger;
}

/* Log message */
void logger_log(logger_t *logger, log_level_t level, const char *format, ...) {
    if (!logger) return;

    time_t now = time(NULL);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S",
             localtime(&now));

    /* Select output file based on level */
    FILE *out = (level == LOG_INFO) ? logger->access_file : logger->error_file;

    pthread_mutex_lock(&logger->lock);

    /* Write timestamp and level */
    fprintf(out, "[%s] [%s] ", timestamp,
            level == LOG_DEBUG ? "DEBUG" :
            level == LOG_INFO ? "INFO" :
            level == LOG_WARNING ? "WARNING" :
            level == LOG_ERROR ? "ERROR" : "SECURITY");

    /* Write message */
    va_list args;
    va_start(args, format);
    vfprintf(out, format, args);
    va_end(args);

    fprintf(out, "\n");

    pthread_mutex_unlock(&logger->lock);
}

/* Clean up logger */
void logger_destroy(logger_t *logger) {
    if (!logger) return;

    pthread_mutex_lock(&logger->lock);
    if (logger->access_file) fclose(logger->access_file);
    if (logger->error_file) fclose(logger->error_file);
    pthread_mutex_unlock(&logger->lock);

    pthread_mutex_destroy(&logger->lock);
    free(logger);
}