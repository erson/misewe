#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

static FILE *log_file = NULL;

void log_init(void) {
    log_file = fopen("logs/server.log", "a");
    if (log_file) {
        setbuf(log_file, NULL);  /* Disable buffering */
    }
}

void log_write(log_level_t level, const char *format, ...) {
    if (!log_file) return;

    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S",
             localtime(&now));

    /* Write log header */
    fprintf(log_file, "[%s] [%s] ", timestamp,
            level == LOG_INFO ? "INFO" :
            level == LOG_WARN ? "WARN" : "ERROR");

    /* Write message */
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);

    fprintf(log_file, "\n");
}

void log_cleanup(void) {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}