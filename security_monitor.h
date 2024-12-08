#ifndef SECURITY_MONITOR_H
#define SECURITY_MONITOR_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Attack types */
typedef enum {
    ATTACK_NONE,
    ATTACK_DOS,          /* Denial of Service */
    ATTACK_INJECTION,    /* Command/SQL injection */
    ATTACK_XSS,         /* Cross-site scripting */
    ATTACK_TRAVERSAL,   /* Path traversal */
    ATTACK_SCAN         /* Port/vulnerability scan */
} attack_type_t;

/* Alert levels */
typedef enum {
    ALERT_INFO,
    ALERT_WARNING,
    ALERT_CRITICAL
} alert_level_t;

/* Security event */
typedef struct {
    attack_type_t type;
    alert_level_t level;
    char source_ip[16];
    char details[256];
    time_t timestamp;
} security_event_t;

/* Monitor context */
typedef struct security_monitor security_monitor_t;

/* Function prototypes */
security_monitor_t *monitor_create(void);
void monitor_destroy(security_monitor_t *monitor);

void monitor_request(security_monitor_t *monitor,
                    const char *ip,
                    const char *method,
                    const char *path,
                    const char *query,
                    const char *headers);

bool monitor_check_ip(security_monitor_t *monitor, const char *ip);

#endif /* SECURITY_MONITOR_H */