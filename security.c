#include "security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <ctype.h>

#define MAX_CLIENTS 10000
#define RATE_WINDOW 60  /* 1 minute */
#define MAX_REQUESTS 60 /* requests per minute */

/* Rate limiting state */
static struct {
    rate_limit_t *clients;
    size_t count;
    pthread_mutex_t lock;
} rate_limiter = {0};

/* MIME type mappings */
static const mime_type_t mime_types[] = {
    {".html", "text/html"},
    {".htm",  "text/html"},
    {".css",  "text/css"},
    {".js",   "application/javascript"},
    {".json", "application/json"},
    {".txt",  "text/plain"},
    {".png",  "image/png"},
    {".jpg",  "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".gif",  "image/gif"},
    {NULL,    "application/octet-stream"}
};

/* Initialize rate limiter */
static void init_rate_limiter(void) {
    static bool initialized = false;
    if (!initialized) {
        rate_limiter.clients = calloc(MAX_CLIENTS, sizeof(rate_limit_t));
        if (rate_limiter.clients) {
            pthread_mutex_init(&rate_limiter.lock, NULL);
            initialized = true;
        }
    }
}

/* Check if request should be allowed */
bool check_rate_limit(const char *ip) {
    init_rate_limiter();
    bool allowed = true;
    time_t now = time(NULL);

    pthread_mutex_lock(&rate_limiter.lock);

    /* Find or create client entry */
    rate_limit_t *client = NULL;
    for (size_t i = 0; i < rate_limiter.count; i++) {
        if (strcmp(rate_limiter.clients[i].ip, ip) == 0) {
            client = &rate_limiter.clients[i];
            break;
        }
    }

    if (!client && rate_limiter.count < MAX_CLIENTS) {
        client = &rate_limiter.clients[rate_limiter.count++];
        strncpy(client->ip, ip, sizeof(client->ip) - 1);
        client->requests = calloc(MAX_REQUESTS, sizeof(time_t));
        client->count = 0;
        client->window_start = now;
    }

    if (client && client->requests) {
        /* Reset window if needed */
        if (now - client->window_start >= RATE_WINDOW) {
            client->count = 0;
            client->window_start = now;
        }

        /* Check rate limit */
        if (client->count >= MAX_REQUESTS) {
            allowed = false;
        } else {
            client->requests[client->count++] = now;
        }
    }

    pthread_mutex_unlock(&rate_limiter.lock);
    return allowed;
}

/* Get MIME type for file */
const char *get_mime_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (ext) {
        for (const mime_type_t *m = mime_types; m->ext; m++) {
            if (strcasecmp(ext, m->ext) == 0) {
                return m->mime_type;
            }
        }
    }
    return "application/octet-stream";
}

/* Validate path */
bool is_path_safe(const char *path) {
    /* Check for NULL or empty path */
    if (!path || !*path) return false;

    /* Check length */
    if (strlen(path) > 255) return false;

    /* Check for path traversal */
    if (strstr(path, "..")) return false;
    if (strstr(path, "//")) return false;

    /* Check for suspicious patterns */
    static const char *suspicious[] = {
        "php", "asp", "cgi", "pl", "py",
        "exec", "bin", "sh", "cmd",
        NULL
    };

    for (const char **s = suspicious; *s; s++) {
        if (strstr(path, *s)) return false;
    }

    /* Check characters */
    for (const char *p = path; *p; p++) {
        if (!isalnum(*p) && !strchr("/-_.", *p)) {
            return false;
        }
    }

    return true;
}

/* Log access */
void log_access(const char *ip, const char *method, const char *path, int status) {
    static FILE *log_file = NULL;
    static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&log_mutex);

    if (!log_file) {
        log_file = fopen("access.log", "a");
        if (log_file) {
            setbuf(log_file, NULL);  /* Disable buffering */
        }
    }

    if (log_file) {
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S",
                localtime(&now));

        fprintf(log_file, "[%s] %s %s %s %d\n",
                timestamp, ip, method, path, status);
    }

    pthread_mutex_unlock(&log_mutex);
}

/* Log error */
void log_error(const char *ip, const char *message) {
    static FILE *log_file = NULL;
    static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&log_mutex);

    if (!log_file) {
        log_file = fopen("error.log", "a");
        if (log_file) {
            setbuf(log_file, NULL);  /* Disable buffering */
        }
    }

    if (log_file) {
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S",
                localtime(&now));

        fprintf(log_file, "[%s] %s %s\n", timestamp, ip, message);
    }

    pthread_mutex_unlock(&log_mutex);
}