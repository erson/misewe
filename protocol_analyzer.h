#ifndef PROTOCOL_ANALYZER_H
#define PROTOCOL_ANALYZER_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Protocol types */
typedef enum {
    PROTO_HTTP_1,
    PROTO_HTTP_2,
    PROTO_WEBSOCKET,
    PROTO_TLS,
    PROTO_UNKNOWN
} protocol_type_t;

/* Analysis flags */
typedef enum {
    ANALYSIS_NORMAL = 0,
    ANALYSIS_SUSPICIOUS = 1 << 0,
    ANALYSIS_MALFORMED = 1 << 1,
    ANALYSIS_OBFUSCATED = 1 << 2,
    ANALYSIS_TUNNELED = 1 << 3,
    ANALYSIS_ENCRYPTED = 1 << 4
} analysis_flags_t;

/* Analysis result */
typedef struct {
    protocol_type_t protocol;
    analysis_flags_t flags;
    struct {
        char method[16];
        char path[256];
        char version[16];
    } http;
    uint32_t anomaly_score;
    char details[512];
} analysis_result_t;

/* Analyzer context */
typedef struct protocol_analyzer analyzer_t;

/* Function prototypes */
analyzer_t *analyzer_create(void);
void analyzer_destroy(analyzer_t *analyzer);

bool analyzer_check_packet(analyzer_t *analyzer,
                         const void *data,
                         size_t length,
                         analysis_result_t *result);

#endif /* PROTOCOL_ANALYZER_H */