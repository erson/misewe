#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "logger.h"

static FILE *log_file = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char *level_strings[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR"
};

void logger_init(const char *filename) {
    log_file = fopen(filename, "a");
    if (!log_file) {
        fprintf(stderr, "Failed to open log file: %s\n", filename);
        exit(1);
    }
    setvbuf(log_file, NULL, _IOLBF, 0);  // Line buffered
}

void logger_log(log_level_t level, const char *fmt, ...) {
    va_list args;
    time_t now;
    char timestamp[32];
    struct tm *tm_info;

    if (!log_file) return;

    time(&now);
    tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    pthread_mutex_lock(&log_mutex);

    fprintf(log_file, "[%s] [%s] ", timestamp, level_strings[level]);
    
    va_start(args, fmt);
    vfprintf(log_file, fmt, args);
    va_end(args);
    
    fprintf(log_file, "\n");

    pthread_mutex_unlock(&log_mutex);
}

void logger_cleanup(void) {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}