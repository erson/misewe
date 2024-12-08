#ifndef CORRELATION_ENGINE_H
#define CORRELATION_ENGINE_H

#include "protocol_analyzer.h"
#include <stdint.h>
#include <time.h>

/* Correlation types */
typedef enum {
    CORR_NONE = 0,
    CORR_SCAN,          /* Port/vulnerability scanning */
    CORR_BRUTEFORCE,    /* Login attempts */
    CORR_DOS,           /* Denial of service */
    CORR_BACKDOOR,      /* Command & control */
    CORR_RECON          /* Reconnaissance */
} correlation_type_t;

/* Correlation result */
typedef struct {
    correlation_type_t type;
    uint32_t confidence;
    uint32_t event_count;
    time_t first_seen;
    time_t last_seen;
    char source[64];
    char details[512];
} correlation_result_t;

/* Engine context */
typedef struct correlation_engine corr_engine_t;

/* Function prototypes */
corr_engine_t *correlation_create(void);
void correlation_destroy(corr_engine_t *engine);

void correlation_add_event(corr_engine_t *engine,
                         const char *source,
                         const analysis_result_t *analysis);

bool correlation_check(corr_engine_t *engine,
                      const char *source,
                      correlation_result_t *result);

#endif /* CORRELATION_ENGINE_H */