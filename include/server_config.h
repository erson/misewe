```c
#ifndef SERVER_CONFIG_H
#define SERVER_CONFIG_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Server configuration */
typedef struct {
    uint16_t port;              /* Server port */
    char bind_addr[16];         /* Bind address */
    char root_dir[256];         /* Web root directory */
    struct {
        size_t max_request_size;    /* Maximum request size */
        int timeout_seconds;        /* Connection timeout */
        uint32_t max_requests;      /* Rate limit: max requests */
        uint32_t window_seconds;    /* Rate limit: time window */
    } limits;
    struct {
        char access_log[256];       /* Access log path */
        char error_log[256];        /* Error log path */
        bool log_requests;          /* Enable request logging */
    } logging;
} server_config_t;

/* Function prototypes */
server_config_t *config_create(void);
void config_destroy(server_config_t *config);
bool config_load(server_config_t *config, const char *filename);

#endif /* SERVER_CONFIG_H */
```

3. Add simple logging:

<file fileName="include/logger.h">
```c
#ifndef LOGGER_H
#define LOGGER_H

typedef enum {
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} log_level_t;

void log_init(const char *access_log, const char *error_log);
void log_write(log_level_t level, const char *format, ...);
void log_cleanup(void);

#endif /* LOGGER_H */
```

<file fileName="src/logger.c">
```c
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
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

    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", 
            localtime(&now));

    pthread_mutex_lock(&logger.lock);
    
    FILE *out = (level == LOG_INFO) ? logger.access_file : logger.error_file;
    if (out) {
        fprintf(out, "[%s] [%s] ", timestamp,
                level == LOG_INFO ? "INFO" :
                level == LOG_WARN ? "WARN" : "ERROR");
        
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
```

4. Add rate limiting:

<file fileName="include/rate_limiter.h">
```c
#ifndef RATE_LIMITER_H
#define RATE_LIMITER_H

#include <stdbool.h>

typedef struct rate_limiter rate_limiter_t;

rate_limiter_t *rate_limiter_create(unsigned int max_requests, 
                                   unsigned int window_seconds);
void rate_limiter_destroy(rate_limiter_t *limiter);
bool rate_limiter_check(rate_limiter_t *limiter, const char *ip);

#endif /* RATE_LIMITER_H */
```

<file fileName="src/rate_limiter.c">
```c
#include "rate_limiter.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#define MAX_CLIENTS 10000

typedef struct {
    char ip[16];
    unsigned int count;
    time_t window_start;
} client_entry_t;

struct rate_limiter {
    unsigned int max_requests;
    unsigned int window_seconds;
    client_entry_t *clients;
    size_t client_count;
    pthread_mutex_t lock;
};

rate_limiter_t *rate_limiter_create(unsigned int max_requests, 
                                   unsigned int window_seconds) {
    rate_limiter_t *limiter = calloc(1, sizeof(*limiter));
    if (!limiter) return NULL;

    limiter->max_requests = max_requests;
    limiter->window_seconds = window_seconds;
    limiter->clients = calloc(MAX_CLIENTS, sizeof(client_entry_t));
    
    if (!limiter->clients) {
        free(limiter);
        return NULL;
    }

    pthread_mutex_init(&limiter->lock, NULL);
    return limiter;
}

bool rate_limiter_check(rate_limiter_t *limiter, const char *ip) {
    bool allowed = true;
    time_t now = time(NULL);

    pthread_mutex_lock(&limiter->lock);

    /* Find or create client entry */
    client_entry_t *client = NULL;
    for (size_t i = 0; i < limiter->client_count; i++) {
        if (strcmp(limiter->clients[i].ip, ip) == 0) {
            client = &limiter->clients[i];
            break;
        }
    }

    if (!client && limiter->client_count < MAX_CLIENTS) {
        client = &limiter->clients[limiter->client_count++];
        strncpy(client->ip, ip, sizeof(client->ip) - 1);
        client->window_start = now;
    }

    if (client) {
        /* Reset window if needed */
        if (now - client->window_start >= limiter->window_seconds) {
            client->count = 0;
            client->window_start = now;
        }

        /* Check rate limit */
        if (client->count >= limiter->max_requests) {
            allowed = false;
        } else {
            client->count++;
        }
    }

    pthread_mutex_unlock(&limiter->lock);
    return allowed;
}

void rate_limiter_destroy(rate_limiter_t *limiter) {
    if (limiter) {
        pthread_mutex_destroy(&limiter->lock);
        free(limiter->clients);
        free(limiter);
    }
}
```

5. Add a test script:

<file fileName="tests/test_server.sh">
```bash
#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Base URL
BASE_URL="http://localhost:8000"

echo "Testing server security..."

# Test basic access
echo -n "Testing basic access... "
if curl -s "$BASE_URL/index.html" > /dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Test path traversal
echo -n "Testing path traversal prevention... "
if curl -s "$BASE_URL/../etc/passwd" > /dev/null; then
    echo -e "${RED}VULNERABLE${NC}"
else
    echo -e "${GREEN}PROTECTED${NC}"
fi

# Test rate limiting
echo -n "Testing rate limiting... "
count=0
for i in {1..100}; do
    if curl -s "$BASE_URL/" > /dev/null; then
        ((count++))
    else
        break
    fi
done
if [ $count -lt 100 ]; then
    echo -e "${GREEN}WORKING${NC}"
else
    echo -e "${RED}NOT WORKING${NC}"
fi

echo "Tests complete."
```