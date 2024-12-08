#include "security_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>

/* Maximum number of tracked IPs */
#define MAX_TRACKED_IPS 10000

/* IP tracking structure */
typedef struct {
    char ip[16];
    struct {
        uint32_t auth_failures;
        uint32_t attacks;
        uint32_t dos_attempts;
    } counts;
    time_t first_seen;
    time_t last_seen;
    bool blocked;
} ip_track_t;

/* Circular event buffer */
typedef struct {
    security_event_t *events;
    size_t size;
    size_t head;
    size_t tail;
    uint32_t sequence;
} event_buffer_t;

/* Monitor context structure */
struct security_monitor {
    security_monitor_config_t config;
    event_buffer_t buffer;
    ip_track_t *tracked_ips;
    size_t ip_count;
    pthread_mutex_t lock;
    FILE *log_file;
    struct {
        uint32_t events_logged;
        uint32_t alerts_triggered;
        uint32_t ips_blocked;
    } stats;
};

/* Initialize event buffer */
static bool init_event_buffer(event_buffer_t *buffer, size_t size) {
    buffer->events = calloc(size, sizeof(security_event_t));
    if (!buffer->events) return false;
    
    buffer->size = size;
    buffer->head = buffer->tail = 0;
    buffer->sequence = 0;
    return true;
}

/* Add event to buffer */
static void buffer_add_event(event_buffer_t *buffer,
                           const security_event_t *event) {
    /* Store event */
    buffer->events[buffer->head] = *event;
    buffer->events[buffer->head].sequence = ++buffer->sequence;

    /* Update head */
    buffer->head = (buffer->head + 1) % buffer->size;

    /* Move tail if buffer full */
    if (buffer->head == buffer->tail) {
        buffer->tail = (buffer->tail + 1) % buffer->size;
    }
}

/* Get IP tracking entry */
static ip_track_t *get_ip_entry(security_monitor_t *monitor,
                               const char *ip) {
    time_t now = time(NULL);

    /* Look for existing entry */
    for (size_t i = 0; i < monitor->ip_count; i++) {
        if (strcmp(monitor->tracked_ips[i].ip, ip) == 0) {
            monitor->tracked_ips[i].last_seen = now;
            return &monitor->tracked_ips[i];
        }
    }

    /* Add new entry if space available */
    if (monitor->ip_count < MAX_TRACKED_IPS) {
        ip_track_t *entry = &monitor->tracked_ips[monitor->ip_count++];
        strncpy(entry->ip, ip, sizeof(entry->ip) - 1);
        memset(&entry->counts, 0, sizeof(entry->counts));
        entry->first_seen = entry->last_seen = now;
        entry->blocked = false;
        return entry;
    }

    return NULL;
}

/* Check if IP should be blocked */
static bool should_block_ip(security_monitor_t *monitor,
                          const ip_track_t *ip) {
    time_t now = time(NULL);
    time_t period_start = now - monitor->config.threshold_period;

    /* Only check events within threshold period */
    if (ip->first_seen > period_start) {
        if (ip->counts.auth_failures >= monitor->config.thresholds.auth_failures ||
            ip->counts.attacks >= monitor->config.thresholds.attacks ||
            ip->counts.dos_attempts >= monitor->config.thresholds.dos_attempts) {
            return true;
        }
    }

    return false;
}

/* Create security monitor */
security_monitor_t *security_monitor_create(
    const security_monitor_config_t *config) {
    security_monitor_t *monitor = calloc(1, sizeof(*monitor));
    if (!monitor) return NULL;

    /* Copy configuration */
    monitor->config = *config;

    /* Initialize event buffer */
    if (!init_event_buffer(&monitor->buffer, config->event_buffer_size)) {
        free(monitor);
        return NULL;
    }

    /* Allocate IP tracking array */
    monitor->tracked_ips = calloc(MAX_TRACKED_IPS, sizeof(ip_track_t));
    if (!monitor->tracked_ips) {
        free(monitor->buffer.events);
        free(monitor);
        return NULL;
    }

    /* Initialize mutex */
    if (pthread_mutex_init(&monitor->lock, NULL) != 0) {
        free(monitor->tracked_ips);
        free(monitor->buffer.events);
        free(monitor);
        return NULL;
    }

    /* Open log file if specified */
    if (config->log_file) {
        monitor->log_file = fopen(config->log_file, "a");
        if (monitor->log_file) {
            setbuf(monitor->log_file, NULL);  /* Disable buffering */
        }
    }

    return monitor;
}

/* Log security event */
void security_monitor_log(security_monitor_t *monitor,
                         security_event_type_t type,
                         severity_t severity,
                         const char *source_ip,
                         const char *target,
                         const char *fmt, ...) {
    va_list args;
    security_event_t event = {0};
    char timestamp[32];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);

    /* Format timestamp */
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    /* Initialize event */
    event.type = type;
    event.severity = severity;
    event.timestamp = now;
    strncpy(event.source_ip, source_ip, sizeof(event.source_ip) - 1);
    strncpy(event.target, target, sizeof(event.target) - 1);

    /* Format details */
    va_start(args, fmt);
    vsnprintf(event.details, sizeof(event.details), fmt, args);
    va_end(args);

    pthread_mutex_lock(&monitor->lock);

    /* Update IP tracking */
    ip_track_t *ip = get_ip_entry(monitor, source_ip);
    if (ip) {
        switch (type) {
            case EVENT_AUTH_FAILURE:
                ip->counts.auth_failures++;
                break;
            case EVENT_ATTACK:
            case EVENT_INJECTION:
            case EVENT_TRAVERSAL:
                ip->counts.attacks++;
                break;
            case EVENT_DOS_ATTEMPT:
                ip->counts.dos_attempts++;
                break;
            default:
                break;
        }

        /* Check if IP should be blocked */
        if (!ip->blocked && should_block_ip(monitor, ip)) {
            ip->blocked = true;
            monitor->stats.ips_blocked++;
        }
    }

    /* Add to event buffer */
    buffer_add_event(&monitor->buffer, &event);
    monitor->stats.events_logged++;

    /* Write to log file */
    if (monitor->log_file) {
        fprintf(monitor->log_file,
                "[%s] [%s] [%s] %s -> %s: %s\n",
                timestamp,
                severity >= SEV_HIGH ? "ALERT" : "INFO",
                source_ip,
                target,
                event.details);
    }

    /* Trigger alert if needed */
    if (monitor->config.enable_realtime_alerts &&
        monitor->config.alert_callback &&
        severity >= SEV_HIGH) {
        monitor->config.alert_callback(&event, monitor->config.alert_ctx);
        monitor->stats.alerts_triggered++;
    }

    pthread_mutex_unlock(&monitor->lock);
}

/* Check if IP is allowed */
bool security_monitor_check_ip(security_monitor_t *monitor,
                             const char *ip) {
    bool allowed = true;

    pthread_mutex_lock(&monitor->lock);

    ip_track_t *entry = get_ip_entry(monitor, ip);
    if (entry && entry->blocked) {
        allowed = false;
    }

    pthread_mutex_unlock(&monitor->lock);
    return allowed;
}

/* Get statistics */
void security_monitor_get_stats(security_monitor_t *monitor,
                              uint32_t *events_logged,
                              uint32_t *alerts_triggered,
                              uint32_t *ips_blocked) {
    pthread_mutex_lock(&monitor->lock);
    
    if (events_logged)
        *events_logged = monitor->stats.events_logged;
    if (alerts_triggered)
        *alerts_triggered = monitor->stats.alerts_triggered;
    if (ips_blocked)
        *ips_blocked = monitor->stats.ips_blocked;

    pthread_mutex_unlock(&monitor->lock);
}

/* Clean up monitor */
void security_monitor_destroy(security_monitor_t *monitor) {
    if (!monitor) return;

    pthread_mutex_lock(&monitor->lock);

    if (monitor->log_file) {
        fclose(monitor->log_file);
    }

    free(monitor->buffer.events);
    free(monitor->tracked_ips);

    pthread_mutex_unlock(&monitor->lock);
    pthread_mutex_destroy(&monitor->lock);
    
    free(monitor);
}