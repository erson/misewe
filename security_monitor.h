#ifndef SECURITY_MONITOR_H
#define SECURITY_MONITOR_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Security event types */
typedef enum {
    EVENT_ACCESS,          /* Normal access */
    EVENT_AUTH_FAILURE,    /* Authentication failure */
    EVENT_ATTACK,          /* Attack detected */
    EVENT_DOS_ATTEMPT,     /* DOS attempt */
    EVENT_INJECTION,       /* Injection attempt */
    EVENT_TRAVERSAL,       /* Path traversal attempt */
    EVENT_OVERFLOW,        /* Buffer overflow attempt */
    EVENT_PROTOCOL,        /* Protocol violation */
    EVENT_SYSTEM           /* System-level event */
} security_event_type_t;

/* Event severity levels */
typedef enum {
    SEV_INFO,
    SEV_LOW,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL
} severity_t;

/* Security event structure */
typedef struct {
    security_event_type_t type;
    severity_t severity;
    time_t timestamp;
    char source_ip[16];
    char target[256];
    char details[512];
    uint32_t sequence;
    uint32_t count;        /* For repeated events */
} security_event_t;

/* Alert callback function type */
typedef void (*alert_callback_t)(const security_event_t *event, void *ctx);

/* Monitor configuration */
typedef struct {
    size_t event_buffer_size;
    bool enable_realtime_alerts;
    alert_callback_t alert_callback;
    void *alert_ctx;
    char *log_file;
    uint32_t threshold_period;    /* In seconds */
    struct {
        uint32_t auth_failures;
        uint32_t attacks;
        uint32_t dos_attempts;
    } thresholds;
} security_monitor_config_t;

/* Monitor context */
typedef struct security_monitor security_monitor_t;

/* Function prototypes */
security_monitor_t *security_monitor_create(const security_monitor_config_t *config);
void security_monitor_destroy(security_monitor_t *monitor);
void security_monitor_log(security_monitor_t *monitor,
                         security_event_type_t type,
                         severity_t severity,
                         const char *source_ip,
                         const char *target,
                         const char *fmt, ...);
bool security_monitor_check_ip(security_monitor_t *monitor, const char *ip);
void security_monitor_get_stats(security_monitor_t *monitor,
                              uint32_t *events_logged,
                              uint32_t *alerts_triggered,
                              uint32_t *ips_blocked);

#endif /* SECURITY_MONITOR_H */