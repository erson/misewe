#include "threat_detector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <regex.h>

/* Maximum pattern length */
#define MAX_PATTERN_LEN 1024

/* Known attack patterns */
static const char *sql_injection_patterns[] = {
    "\\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)\\b.*\\bFROM\\b",
    "'\\s*OR\\s*'?\\s*'?\\s*\\d+\\s*'?\\s*=\\s*\\d+",
    "\\b(AND|OR)\\s+\\d+\\s*=\\s*\\d+\\s*--",
    NULL
};

static const char *xss_patterns[] = {
    "<script[^>]*>",
    "javascript:",
    "onload=",
    "onerror=",
    "\\b(eval|setTimeout|setInterval)\\s*\\(",
    NULL
};

static const char *path_traversal_patterns[] = {
    "\\.\\./",
    "%2e%2e/",
    "\\\\\\.\\.",
    NULL
};

static const char *command_injection_patterns[] = {
    "\\b(cat|grep|awk|sed|curl|wget)\\b",
    "[;&|`]",
    "\\$\\([^)]*\\)",
    NULL
};

/* Compiled regex patterns */
typedef struct {
    regex_t regex;
    threat_type_t type;
    confidence_t base_confidence;
} compiled_pattern_t;

/* Request history entry */
typedef struct {
    char *data;
    size_t length;
    bool malicious;
    time_t timestamp;
} history_entry_t;

/* Detector context */
struct threat_detector {
    detector_config_t config;
    compiled_pattern_t *patterns;
    size_t pattern_count;
    history_entry_t *history;
    size_t history_pos;
    pthread_mutex_t lock;
    struct {
        uint32_t threats_detected;
        uint32_t false_positives;
        uint32_t total_requests;
    } stats;
};

/* Compile regex patterns */
static bool compile_patterns(threat_detector_t *detector) {
    size_t count = 0;
    const char **pattern;

    /* Count patterns */
    for (pattern = sql_injection_patterns; *pattern; pattern++) count++;
    for (pattern = xss_patterns; *pattern; pattern++) count++;
    for (pattern = path_traversal_patterns; *pattern; pattern++) count++;
    for (pattern = command_injection_patterns; *pattern; pattern++) count++;

    /* Allocate pattern array */
    detector->patterns = calloc(count, sizeof(compiled_pattern_t));
    if (!detector->patterns) return false;

    size_t pos = 0;

    /* Compile SQL injection patterns */
    for (pattern = sql_injection_patterns; *pattern; pattern++) {
        if (regcomp(&detector->patterns[pos].regex, *pattern,
                   REG_EXTENDED | REG_ICASE) == 0) {
            detector->patterns[pos].type = THREAT_SQL_INJECTION;
            detector->patterns[pos].base_confidence = CONFIDENCE_HIGH;
            pos++;
        }
    }

    /* Compile XSS patterns */
    for (pattern = xss_patterns; *pattern; pattern++) {
        if (regcomp(&detector->patterns[pos].regex, *pattern,
                   REG_EXTENDED | REG_ICASE) == 0) {
            detector->patterns[pos].type = THREAT_XSS;
            detector->patterns[pos].base_confidence = CONFIDENCE_HIGH;
            pos++;
        }
    }

    /* Compile path traversal patterns */
    for (pattern = path_traversal_patterns; *pattern; pattern++) {
        if (regcomp(&detector->patterns[pos].regex, *pattern,
                   REG_EXTENDED) == 0) {
            detector->patterns[pos].type = THREAT_PATH_TRAVERSAL;
            detector->patterns[pos].base_confidence = CONFIDENCE_CERTAIN;
            pos++;
        }
    }

    /* Compile command injection patterns */
    for (pattern = command_injection_patterns; *pattern; pattern++) {
        if (regcomp(&detector->patterns[pos].regex, *pattern,
                   REG_EXTENDED) == 0) {
            detector->patterns[pos].type = THREAT_COMMAND_INJECTION;
            detector->patterns[pos].base_confidence = CONFIDENCE_HIGH;
            pos++;
        }
    }

    detector->pattern_count = pos;
    return pos > 0;
}

/* Create threat detector */
threat_detector_t *threat_detector_create(const detector_config_t *config) {
    threat_detector_t *detector = calloc(1, sizeof(*detector));
    if (!detector) return NULL;

    /* Copy configuration */
    detector->config = *config;

    /* Compile patterns */
    if (!compile_patterns(detector)) {
        free(detector);
        return NULL;
    }

    /* Initialize history if behavioral analysis enabled */
    if (config->enable_behavioral) {
        detector->history = calloc(config->history_size,
                                 sizeof(history_entry_t));
        if (!detector->history) {
            for (size_t i = 0; i < detector->pattern_count; i++) {
                regfree(&detector->patterns[i].regex);
            }
            free(detector->patterns);
            free(detector);
            return NULL;
        }
    }

    /* Initialize mutex */
    if (pthread_mutex_init(&detector->lock, NULL) != 0) {
        free(detector->history);
        for (size_t i = 0; i < detector->pattern_count; i++) {
            regfree(&detector->patterns[i].regex);
        }
        free(detector->patterns);
        free(detector);
        return NULL;
    }

    return detector;
}

/* Check for threats in request */
bool threat_detector_check_request(
    threat_detector_t *detector,
    const char *method,
    const char *uri,
    const char *headers,
    const char *body,
    size_t body_length,
    threat_info_t *threat) {

    char request_data[MAX_PATTERN_LEN];
    regmatch_t match;
    bool threat_found = false;

    /* Combine request components */
    snprintf(request_data, sizeof(request_data), "%s %s\n%s\n%.*s",
             method, uri, headers, (int)body_length, body);

    pthread_mutex_lock(&detector->lock);
    detector->stats.total_requests++;

    /* Check each pattern */
    for (size_t i = 0; i < detector->pattern_count; i++) {
        if (regexec(&detector->patterns[i].regex, request_data,
                    1, &match, 0) == 0) {
            /* Threat detected */
            if (threat) {
                threat->type = detector->patterns[i].type;
                threat->confidence = detector->patterns[i].base_confidence;
                
                /* Copy matching pattern */
                size_t len = match.rm_eo - match.rm_so;
                if (len >= sizeof(threat->pattern)) {
                    len = sizeof(threat->pattern) - 1;
                }
                memcpy(threat->pattern,
                       request_data + match.rm_so, len);
                threat->pattern[len] = '\0';

                /* Set timestamps */
                threat->first_seen = threat->last_seen = time(NULL);
                threat->frequency = 1;
            }

            detector->stats.threats_detected++;
            threat_found = true;
            break;
        }
    }

    /* Store in history if behavioral analysis enabled */
    if (detector->config.enable_behavioral && detector->history) {
        history_entry_t *entry = &detector->history[detector->history_pos];
        
        /* Free old entry if exists */
        free(entry->data);

        /* Store new entry */
        entry->data = strdup(request_data);
        entry->length = strlen(request_data);
        entry->malicious = threat_found;
        entry->timestamp = time(NULL);

        detector->history_pos = (detector->history_pos + 1) %
                              detector->config.history_size;
    }

    pthread_mutex_unlock(&detector->lock);
    return threat_found;
}

/* Add request to learning dataset */
void threat_detector_learn(
    threat_detector_t *detector,
    const char *request_data,
    bool is_malicious) {
    
    if (!detector->config.enable_ml) return;

    pthread_mutex_lock(&detector->lock);

    /* Add to history for learning */
    if (detector->history) {
        history_entry_t *entry = &detector->history[detector->history_pos];
        
        free(entry->data);
        entry->data = strdup(request_data);
        entry->length = strlen(request_data);
        entry->malicious = is_malicious;
        entry->timestamp = time(NULL);

        detector->history_pos = (detector->history_pos + 1) %
                              detector->config.history_size;
    }

    /* Update statistics */
    if (is_malicious) {
        detector->stats.threats_detected++;
    }

    pthread_mutex_unlock(&detector->lock);
}

/* Get detector statistics */
uint32_t threat_detector_get_stats(
    threat_detector_t *detector,
    uint32_t *threats_detected,
    uint32_t *false_positives) {
    
    pthread_mutex_lock(&detector->lock);
    
    if (threats_detected)
        *threats_detected = detector->stats.threats_detected;
    if (false_positives)
        *false_positives = detector->stats.false_positives;
    
    uint32_t total = detector->stats.total_requests;
    
    pthread_mutex_unlock(&detector->lock);
    return total;
}

/* Clean up detector */
void threat_detector_destroy(threat_detector_t *detector) {
    if (!detector) return;

    pthread_mutex_lock(&detector->lock);

    /* Free patterns */
    for (size_t i = 0; i < detector->pattern_count; i++) {
        regfree(&detector->patterns[i].regex);
    }
    free(detector->patterns);

    /* Free history */
    if (detector->history) {
        for (size_t i = 0; i < detector->config.history_size; i++) {
            free(detector->history[i].data);
        }
        free(detector->history);
    }

    pthread_mutex_unlock(&detector->lock);
    pthread_mutex_destroy(&detector->lock);
    free(detector);
}