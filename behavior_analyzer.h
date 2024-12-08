#ifndef BEHAVIOR_ANALYZER_H
#define BEHAVIOR_ANALYZER_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Behavior patterns */
typedef enum {
    BEHAVIOR_NORMAL = 0,
    BEHAVIOR_BOT = 1 << 0,
    BEHAVIOR_ATTACK = 1 << 1,
    BEHAVIOR_ANOMALY = 1 << 2,
    BEHAVIOR_RECON = 1 << 3
} behavior_type_t;

/* Request features */
typedef struct {
    uint32_t request_rate;    /* Requests per minute */
    uint32_t error_rate;      /* Error responses per minute */
    uint32_t avg_size;        /* Average request size */
    uint32_t path_diversity;  /* Unique paths accessed */
    uint32_t method_diversity; /* Different HTTP methods used */
    float timing_regularity;  /* How regular are request intervals */
} request_features_t;

/* Analysis result */
typedef struct {
    behavior_type_t type;
    float confidence;
    char details[256];
    request_features_t features;
    time_t timestamp;
} behavior_result_t;

/* Analyzer context */
typedef struct behavior_analyzer behavior_analyzer_t;

/* Function prototypes */
behavior_analyzer_t *behavior_create(void);
void behavior_destroy(behavior_analyzer_t *analyzer);

void behavior_add_request(behavior_analyzer_t *analyzer,
                        const char *client_ip,
                        const char *method,
                        const char *path,
                        size_t size,
                        int status_code);

bool behavior_analyze(behavior_analyzer_t *analyzer,
                     const char *client_ip,
                     behavior_result_t *result);

#endif /* BEHAVIOR_ANALYZER_H */