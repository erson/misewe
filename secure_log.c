#include "secure_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <pthread.h>
#include <errno.h>

/* Maximum sizes */
#define MAX_LOG_LINE 1024
#define MAX_TIME_STR 32

/* Log file structure */
typedef struct {
    char *path;
    FILE *fp;
    size_t size;
    pthread_mutex_t lock;
} log_file_t;

/* Log context structure */
struct secure_log {
    log_config_t config;
    log_file_t files[LOG_SECURITY + 1];  /* One file per level */
};

/* Level names */
static const char *level_names[] = {
    "DEBUG", "INFO", "WARN", "ERROR", "SECURITY"
};

/* Safe string copy with escaping */
static void safe_strcpy(char *dst, const char *src, size_t size) {
    size_t i, j;
    for (i = 0, j = 0; src[i] && j < size - 1; i++) {
        if (src[i] == '\n' || src[i] == '\r') {
            if (j < size - 2) {
                dst[j++] = '\\';
                dst[j++] = 'n';
            }
        } else if (!iscntrl(src[i])) {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

/* Create log file */
static bool create_log_file(log_file_t *file, const char *dir,
                           const char *level) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s.log", dir, level);

    /* Allocate path */
    file->path = strdup(path);
    if (!file->path) return false;

    /* Open file */
    file->fp = fopen(path, "a");
    if (!file->fp) {
        free(file->path);
        return false;
    }

    /* Set permissions */
    fchmod(fileno(file->fp), S_IRUSR | S_IWUSR);

    /* Initialize mutex */
    if (pthread_mutex_init(&file->lock, NULL) != 0) {
        fclose(file->fp);
        free(file->path);
        return false;
    }

    /* Get current size */
    fseek(file->fp, 0, SEEK_END);
    file->size = ftell(file->fp);

    return true;
}

/* Rotate log file */
static void rotate_log(secure_log_t *log, log_file_t *file) {
    char old_path[PATH_MAX], new_path[PATH_MAX];
    
    /* Close current file */
    fclose(file->fp);

    /* Rotate existing files */
    for (int i = log->config.max_files - 1; i >= 0; i--) {
        if (i == 0) {
            snprintf(old_path, sizeof(old_path), "%s", file->path);
        } else {
            snprintf(old_path, sizeof(old_path), "%s.%d", file->path, i);
        }
        snprintf(new_path, sizeof(new_path), "%s.%d", file->path, i + 1);
        rename(old_path, new_path);
    }

    /* Open new file */
    file->fp = fopen(file->path, "a");
    if (file->fp) {
        fchmod(fileno(file->fp), S_IRUSR | S_IWUSR);
        file->size = 0;
    }
}

/* Create logging system */
secure_log_t *secure_log_create(const log_config_t *config) {
    secure_log_t *log = calloc(1, sizeof(*log));
    if (!log) return NULL;

    /* Copy configuration */
    log->config = *config;

    /* Create log directory if needed */
    mkdir(config->log_dir, S_IRWXU);

    /* Create log files */
    for (int i = 0; i <= LOG_SECURITY; i++) {
        if (!create_log_file(&log->files[i], config->log_dir,
                            level_names[i])) {
            secure_log_destroy(log);
            return NULL;
        }
    }

    return log;
}

/* Write to log */
void secure_log(secure_log_t *log, log_level_t level,
                const char *file, int line, const char *fmt, ...) {
    if (!log || level < 0 || level > LOG_SECURITY) return;

    char message[MAX_LOG_LINE];
    char time_str[MAX_TIME_STR];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    va_list args;

    /* Format time */
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

    /* Format message */
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    /* Sanitize message */
    char safe_message[MAX_LOG_LINE];
    safe_strcpy(safe_message, message, sizeof(safe_message));

    /* Get log file */
    log_file_t *log_file = &log->files[level];

    /* Lock file */
    pthread_mutex_lock(&log_file->lock);

    /* Check if rotation needed */
    if (log_file->size >= log->config.max_file_size) {
        rotate_log(log, log_file);
    }

    /* Write log entry */
    if (log_file->fp) {
        int written = fprintf(log_file->fp, "[%s] [%s] %s:%d %s\n",
                            time_str, level_names[level],
                            file, line, safe_message);
        if (written > 0) {
            log_file->size += written;
        }

        /* Sync if requested */
        if (log->config.sync_writes) {
            fflush(log_file->fp);
            fsync(fileno(log_file->fp));
        }
    }

    pthread_mutex_unlock(&log_file->lock);
}

/* Clean up logging system */
void secure_log_destroy(secure_log_t *log) {
    if (!log) return;

    /* Close all log files */
    for (int i = 0; i <= LOG_SECURITY; i++) {
        if (log->files[i].fp) {
            fclose(log->files[i].fp);
        }
        free(log->files[i].path);
        pthread_mutex_destroy(&log->files[i].lock);
    }

    free(log);
}