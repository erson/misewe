#include "security_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define MAX_EVENTS 1000
#define MAX_IPS 10000

/* IP tracking entry */
typedef struct {
    char ip[16];
    uint32_t access_count;
    uint32_t attack_count;
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

    /* Allocate IP tracking array */
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
void monitor_log_event(security_monitor_t *monitor,
                      event_type_t type,
                      const char *ip,
                      const char *details) {
    pthread_mutex_lock(&monitor->lock);

    /* Update IP tracking */
    ip_entry_t *ip_entry = get_ip_entry(monitor, ip);
    if (ip_entry) {
        switch (type) {
            case EVENT_ACCESS:
                ip_entry->access_count++;
                break;
            case EVENT_ATTACK:
            case EVENT_DOS_ATTEMPT:
                ip_entry->attack_count++;
                /* Block IP after too many attacks */
                if (ip_entry->attack_count > 10) {
                    ip_entry->blocked = true;
                }
                break;
            default:
                break;
        }
    }

    /* Add to event buffer */
    size_t pos = monitor->event_count % MAX_EVENTS;
    security_event_t *event = &monitor->events[pos];

    event->type = type;
    strncpy(event->ip, ip, sizeof(event->ip) - 1);
    strncpy(event->details, details, sizeof(event->details) - 1);
    event->timestamp = time(NULL);

    monitor->event_count++;

    /* Log to file */
    if (monitor->log_file) {
        fprintf(monitor->log_file, "[%ld] [%s] %s: %s\n",
                (long)event->timestamp,
                event->type == EVENT_ACCESS ? "ACCESS" :
                event->type == EVENT_AUTH_FAILURE ? "AUTH" :
                event->type == EVENT_ATTACK ? "ATTACK" :
                event->type == EVENT_DOS_ATTEMPT ? "DOS" :
                "ANOMALY",
                event->ip,
                event->details);
    }

    pthread_mutex_unlock(&monitor->lock);
}

/* Check if IP is allowed */
bool monitor_check_ip(security_monitor_t *monitor,
                     const char *ip) {
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