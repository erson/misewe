#include "security_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define MAX_EVENTS 1000
#define MAX_IPS 10000
#define WINDOW_SIZE 3600  /* 1 hour */

/* IP tracking entry */
typedef struct {
    char ip[16];
    struct {
        uint32_t requests;
        uint32_t errors;
        uint32_t attacks;
    } counts;
    time_t first_seen;
    time_t last_seen;
    bool blocked;
} ip_entry_t;

/* Monitor context */
struct security_monitor {
    security_event_t *events;
    size_t event_count;
    ip_entry_t *ips;
    size_t ip_count;
    pthread_mutex_t lock;
    FILE *log_file;
};

/* Known attack patterns */
static const struct {
    const char *pattern;
    attack_type_t type;
} attack_patterns[] = {
    /* SQL Injection */
    {"'", ATTACK_INJECTION},
    {"UNION SELECT", ATTACK_INJECTION},
    {"OR 1=1", ATTACK_INJECTION},
    
    /* XSS */
    {"<script", ATTACK_XSS},
    {"javascript:", ATTACK_XSS},
    {"onerror=", ATTACK_XSS},
    
    /* Path Traversal */
    {"../", ATTACK_TRAVERSAL},
    {"..\\", ATTACK_TRAVERSAL},
    {"%2e%2e%2f", ATTACK_TRAVERSAL},
    
    /* Command Injection */
    {";", ATTACK_INJECTION},
    {"|", ATTACK_INJECTION},
    {"$(", ATTACK_INJECTION},
    
    /* Scanner Detection */
    {".php", ATTACK_SCAN},
    {"wp-admin", ATTACK_SCAN},
    {"admin.asp", ATTACK_SCAN},
    
    {NULL, ATTACK_NONE}
};

/* Create security monitor */
security_monitor_t *monitor_create(void) {
    security_monitor_t *monitor = calloc(1, sizeof(*monitor));
    if (!monitor) return NULL;

    /* Allocate event buffer */
    monitor->events = calloc(MAX_EVENTS, sizeof(security_event_t));
    if (!monitor->events) {
        free(monitor);
        return NULL;
    }

    /* Allocate IP tracking */
    monitor->ips = calloc(MAX_IPS, sizeof(ip_entry_t));
    if (!monitor->ips) {
        free(monitor->events);
        free(monitor);
        return NULL;
    }

    /* Initialize mutex */
    if (pthread_mutex_init(&monitor->lock, NULL) != 0) {
        free(monitor->ips);
        free(monitor->events);
        free(monitor);
        return NULL;
    }

    /* Open log file */
    monitor->log_file = fopen("security.log", "a");
    if (monitor->log_file) {
        setbuf(monitor->log_file, NULL);  /* Disable buffering */
    }

    return monitor;
}

/* Find or create IP entry */
static ip_entry_t *get_ip_entry(security_monitor_t *monitor,
                               const char *ip) {
    time_t now = time(NULL);

    /* Look for existing entry */
    for (size_t i = 0; i < monitor->ip_count; i++) {
        if (strcmp(monitor->ips[i].ip, ip) == 0) {
            monitor->ips[i].last_seen = now;
            return &monitor->ips[i];
        }
    }

    /* Add new entry if space available */
    if (monitor->ip_count < MAX_IPS) {
        ip_entry_t *entry = &monitor->ips[monitor->ip_count++];
        strncpy(entry->ip, ip, sizeof(entry->ip) - 1);
        entry->first_seen = entry->last_seen = now;
        return entry;
    }

    return NULL;
}

/* Log security event */
static void log_event(security_monitor_t *monitor,
                     const security_event_t *event) {
    /* Add to circular buffer */
    size_t pos = monitor->event_count % MAX_EVENTS;
    monitor->events[pos] = *event;
    monitor->event_count++;

    /* Write to log file */
    if (monitor->log_file) {
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp),
                "%Y-%m-%d %H:%M:%S",
                localtime(&now));

        fprintf(monitor->log_file,
                "[%s] [%s] %s: %s\n",
                timestamp,
                event->level == ALERT_CRITICAL ? "CRITICAL" :
                event->level == ALERT_WARNING ? "WARNING" : "INFO",
                event->source_ip,
                event->details);
    }
}

/* Check request for attacks */
static attack_type_t detect_attack(const char *method,
                                 const char *path,
                                 const char *query,
                                 const char *headers) {
    /* Check each pattern */
    for (size_t i = 0; attack_patterns[i].pattern; i++) {
        if (strstr(path, attack_patterns[i].pattern) ||
            (query && strstr(query, attack_patterns[i].pattern)) ||
            strstr(headers, attack_patterns[i].pattern)) {
            return attack_patterns[i].type;
        }
    }

    return ATTACK_NONE;
}

/* Monitor request */
void monitor_request(security_monitor_t *monitor,
                    const char *ip,
                    const char *method,
                    const char *path,
                    const char *query,
                    const char *headers) {
    pthread_mutex_lock(&monitor->lock);

    /* Get IP tracking */
    ip_entry_t *entry = get_ip_entry(monitor, ip);
    if (!entry) {
        pthread_mutex_unlock(&monitor->lock);
        return;
    }

    /* Update request count */
    entry->counts.requests++;

    /* Check for attacks */
    attack_type_t attack = detect_attack(method, path, query, headers);
    if (attack != ATTACK_NONE) {
        entry->counts.attacks++;

        /* Create security event */
        security_event_t event = {
            .type = attack,
            .level = entry->counts.attacks > 5 ? ALERT_CRITICAL :
                    entry->counts.attacks > 2 ? ALERT_WARNING : ALERT_INFO,
            .timestamp = time(NULL)
        };
        strncpy(event.source_ip, ip, sizeof(event.source_ip) - 1);
        snprintf(event.details, sizeof(event.details),
                "Attack detected in %s: %s",
                method, path);

        /* Log event */
        log_event(monitor, &event);

        /* Block IP if too many attacks */
        if (entry->counts.attacks > 10) {
            entry->blocked = true;
        }
    }

    pthread_mutex_unlock(&monitor->lock);
}

/* Check if IP is allowed */
bool monitor_check_ip(security_monitor_t *monitor, const char *ip) {
    bool allowed = true;
    pthread_mutex_lock(&monitor->lock);

    ip_entry_t *entry = get_ip_entry(monitor, ip);
    if (entry && entry->blocked) {
        allowed = false;
    }

    pthread_mutex_unlock(&monitor->lock);
    return allowed;
}

/* Clean up monitor */
void monitor_destroy(security_monitor_t *monitor) {
    if (!monitor) return;

    pthread_mutex_lock(&monitor->lock);

    if (monitor->log_file) {
        fclose(monitor->log_file);
    }

    free(monitor->events);
    free(monitor->ips);

    pthread_mutex_unlock(&monitor->lock);
    pthread_mutex_destroy(&monitor->lock);

    free(monitor);
}