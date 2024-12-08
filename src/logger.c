#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

/* Logger state */
static FILE *log_file = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Level strings */
static const char *level_strings[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR"
};

/* Initialize logger */
void log_init(const char *filename) {
    pthread_mutex_lock(&log_mutex);
    if (log_file) {
        fclose(log_file);
    }
    log_file = fopen(filename, "a");
    pthread_mutex_unlock(&log_mutex);
}

/* Write log message */
void log_write(log_level_t level, const char *fmt, ...) {
    if (!log_file) {
        log_file = stderr;
    }

    /* Get current time */
    time_t now = time(NULL);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

    /* Format message */
    char message[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    /* Write log entry */
    pthread_mutex_lock(&log_mutex);
    fprintf(log_file, "[%s] %s: %s\n", time_str, level_strings[level], message);
    fflush(log_file);
    pthread_mutex_unlock(&log_mutex);
}

/* Close logger */
void log_close(void) {
    pthread_mutex_lock(&log_mutex);
    if (log_file && log_file != stderr) {
        fclose(log_file);
        log_file = NULL;
    }
    pthread_mutex_unlock(&log_mutex);
} 