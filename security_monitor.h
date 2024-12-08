#ifndef SECURITY_MONITOR_H
#define SECURITY_MONITOR_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Security event types */
typedef enum {
    EVENT_ACCESS,          /* Normal access */
    EVENT_AUTH_FAILURE,    /* Authentication failure */
    EVENT_ATTACK,         /* Attack detected */
    EVENT_DOS_ATTEMPT,    /* Denial of Service attempt */
    EVENT_ANOMALY         /* Unusual behavior */
} event_type_t;

/* Security event structure */
typedef struct {
    event_type_t type;
    char ip[16];
    char details[256];
    time_t timestamp;
} security_event_t;

/* Monitor context */
typedef struct security_monitor security_monitor_t;

/* Function prototypes */
security_monitor_t *monitor_create(void);
void monitor_destroy(security_monitor_t *monitor);

void monitor_log_event(security_monitor_t *monitor,
                      event_type_t type,
                      const char *ip,
                      const char *details);

bool monitor_check_ip(security_monitor_t *monitor,
                     const char *ip);

#endif /* SECURITY_MONITOR_H */