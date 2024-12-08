#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>

static struct {
    FILE *access_file;
    FILE *error_file;
    pthread_mutex_t lock;
} logger = {0};

void log_init(const char *access_log, const char *error_log) {
    logger.access_file = fopen(access_log, "a");
    logger.error_file = fopen(error_log, "a");
    
    if (logger.access_file) setbuf(logger.access_file, NULL);
    if (logger.error_file) setbuf(logger.error_file, NULL);
    
    pthread_mutex_init(&logger.lock, NULL);
}

void log_write(log_level_t level, const char *format, ...) {
    time_t now = time(NULL);
    char timestamp[64];
    va_list args;
    
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    pthread_mutex_lock(&logger.lock);
    
    FILE *out = (level == LOG_INFO) ? logger.access_file : logger.error_file;
    if (out) {
        fprintf(out, "[%s] [%s] ", timestamp,
                level == LOG_INFO ? "INFO" :
                level == LOG_WARN ? "WARN" :
                level == LOG_ERROR ? "ERROR" : "SECURITY");
                
        va_start(args, format);
        vfprintf(out, format, args);
        va_end(args);
        
        fprintf(out, "\n");
    }
    
    pthread_mutex_unlock(&logger.lock);
}

void log_cleanup(void) {
    pthread_mutex_lock(&logger.lock);
    if (logger.access_file) fclose(logger.access_file);
    if (logger.error_file) fclose(logger.error_file);
    pthread_mutex_unlock(&logger.lock);
    pthread_mutex_destroy(&logger.lock);
}