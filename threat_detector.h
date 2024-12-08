#ifndef THREAT_DETECTOR_H
#define THREAT_DETECTOR_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Threat types */
typedef enum {
    THREAT_SQL_INJECTION,
    THREAT_XSS,
    THREAT_CSRF,
    THREAT_PATH_TRAVERSAL,
    THREAT_COMMAND_INJECTION,
    THREAT_FILE_INCLUSION,
    THREAT_PROTOCOL_VIOLATION,
    THREAT_ABNORMAL_BEHAVIOR
} threat_type_t;

/* Confidence levels */
typedef enum {
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_HIGH,
    CONFIDENCE_CERTAIN
} confidence_t;

/* Threat details */
typedef struct {
    threat_type_t type;
    confidence_t confidence;
    char pattern[256];
    char context[512];
    uint32_t frequency;
    time_t first_seen;
    time_t last_seen;
} threat_info_t;

/* Detector configuration */
typedef struct {
    bool enable_behavioral;     /* Enable behavioral analysis */
    bool enable_ml;            /* Enable machine learning */
    bool aggressive_mode;      /* More strict detection */
    uint32_t history_size;     /* Number of requests to track */
    float threshold;           /* Detection threshold */
    const char *custom_rules;  /* Path to custom rules file */
} detector_config_t;

/* Detector context */
typedef struct threat_detector threat_detector_t;

/* Function prototypes */
threat_detector_t *threat_detector_create(const detector_config_t *config);
void threat_detector_destroy(threat_detector_t *detector);

bool threat_detector_check_request(
    threat_detector_t *detector,
    const char *method,
    const char *uri,
    const char *headers,
    const char *body,
    size_t body_length,
    threat_info_t *threat);

void threat_detector_learn(
    threat_detector_t *detector,
    const char *request_data,
    bool is_malicious);

uint32_t threat_detector_get_stats(
    threat_detector_t *detector,
    uint32_t *threats_detected,
    uint32_t *false_positives);

#endif /* THREAT_DETECTOR_H */