#ifndef INTRUSION_DETECTOR_H
#define INTRUSION_DETECTOR_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Attack types */
typedef enum {
    ATTACK_NONE = 0,
    ATTACK_DOS,             /* Denial of Service */
    ATTACK_INJECTION,       /* SQL/Command injection */
    ATTACK_XSS,            /* Cross-site scripting */
    ATTACK_TRAVERSAL,      /* Path traversal */
    ATTACK_PROTOCOL,       /* Protocol violation */
    ATTACK_FUZZING,        /* Fuzzing attempt */
    ATTACK_AUTOMATED,      /* Bot/automated attack */
    ATTACK_UNKNOWN         /* Unknown attack type */
} attack_type_t;

/* Confidence levels */
typedef enum {
    CONFIDENCE_LOW,        /* Possibly malicious */
    CONFIDENCE_MEDIUM,     /* Likely malicious */
    CONFIDENCE_HIGH,       /* Very likely malicious */
    CONFIDENCE_CERTAIN     /* Definitely malicious */
} confidence_t;

/* Alert levels */
typedef enum {
    ALERT_INFO,           /* Informational */
    ALERT_WARNING,        /* Warning */
    ALERT_CRITICAL,       /* Critical */
    ALERT_EMERGENCY       /* Emergency */
} alert_level_t;

/* Detection configuration */
typedef struct {
    bool enable_learning;          /* Enable ML-based learning */
    bool aggressive_mode;          /* More strict detection */
    uint32_t history_size;        /* Size of history buffer */
    float threshold;              /* Detection threshold */
    const char *ruleset_path;     /* Custom rules file */
} detector_config_t;

/* Detection result */
typedef struct {
    attack_type_t type;
    confidence_t confidence;
    alert_level_t level;
    char details[256];
    uint32_t rule_id;
    time_t timestamp;
} detection_result_t;

/* Detector context */
typedef struct intrusion_detector detector_t;

/* Alert callback function type */
typedef void (*alert_callback_t)(const detection_result_t *result,
                               void *user_data);

/* Function prototypes */
detector_t *detector_create(const detector_config_t *config);
void detector_destroy(detector_t *detector);

void detector_set_callback(detector_t *detector,
                         alert_callback_t callback,
                         void *user_data);

bool detector_check_request(detector_t *detector,
                          const void *data,
                          size_t length,
                          detection_result_t *result);

void detector_train(detector_t *detector,
                   const void *data,
                   size_t length,
                   bool is_attack);

void detector_update_rules(detector_t *detector,
                         const char *ruleset_path);

#endif /* INTRUSION_DETECTOR_H */