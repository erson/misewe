#include "correlation_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define MAX_SOURCES 1000
#define MAX_EVENTS 100
#define TIME_WINDOW 3600  /* 1 hour */

/* Event history for a source */
typedef struct {
    char source[64];
    struct {
        analysis_result_t analysis;
        time_t timestamp;
    } events[MAX_EVENTS];
    size_t event_count;
    size_t total_events;
    correlation_type_t last_correlation;
    time_t first_seen;
    time_t last_seen;
} source_history_t;

/* Correlation engine context */
struct correlation_engine {
    source_history_t *sources;
    size_t source_count;
    pthread_mutex_t lock;
};

/* Create correlation engine */
corr_engine_t *correlation_create(void) {
    corr_engine_t *engine = calloc(1, sizeof(*engine));
    if (!engine) return NULL;

    /* Allocate source history array */
    engine->sources = calloc(MAX_SOURCES, sizeof(source_history_t));
    if (!engine->sources) {
        free(engine);
        return NULL;
    }

    /* Initialize mutex */
    if (pthread_mutex_init(&engine->lock, NULL) != 0) {
        free(engine->sources);
        free(engine);
        return NULL;
    }

    return engine;
}

/* Find or create source history */
static source_history_t *get_source(corr_engine_t *engine,
                                  const char *source) {
    time_t now = time(NULL);

    /* Look for existing source */
    for (size_t i = 0; i < engine->source_count; i++) {
        if (strcmp(engine->sources[i].source, source) == 0) {
            engine->sources[i].last_seen = now;
            return &engine->sources[i];
        }
    }

    /* Add new source if space available */
    if (engine->source_count < MAX_SOURCES) {
        source_history_t *history = &engine->sources[engine->source_count++];
        strncpy(history->source, source, sizeof(history->source) - 1);
        history->first_seen = history->last_seen = now;
        return history;
    }

    return NULL;
}

/* Add event to history */
void correlation_add_event(corr_engine_t *engine,
                         const char *source,
                         const analysis_result_t *analysis) {
    pthread_mutex_lock(&engine->lock);

    source_history_t *history = get_source(engine, source);
    if (history) {
        size_t pos = history->event_count % MAX_EVENTS;
        history->events[pos].analysis = *analysis;
        history->events[pos].timestamp = time(NULL);
        history->event_count++;
        history->total_events++;
    }

    pthread_mutex_unlock(&engine->lock);
}

/* Check for scanning patterns */
static bool detect_scanning(const source_history_t *history,
                          correlation_result_t *result) {
    time_t now = time(NULL);
    size_t unique_paths = 0;
    char seen_paths[100][256] = {0};  /* Track unique paths */

    /* Check recent events */
    for (size_t i = 0; i < history->event_count; i++) {
        if (now - history->events[i].timestamp > TIME_WINDOW) continue;

        /* Check if path is unique */
        bool found = false;
        for (size_t j = 0; j < unique_paths; j++) {
            if (strcmp(seen_paths[j],
                      history->events[i].analysis.http.path) == 0) {
                found = true;
                break;
            }
        }

        if (!found && unique_paths < 100) {
            strncpy(seen_paths[unique_paths],
                   history->events[i].analysis.http.path,
                   255);
            unique_paths++;
        }
    }

    /* Detect rapid scanning */
    if (unique_paths > 20) {  /* Threshold for scanning */
        result->type = CORR_SCAN;
        result->confidence = unique_paths * 5;  /* Higher confidence with more paths */
        snprintf(result->details, sizeof(result->details),
                "Scanning detected: %zu unique paths in %d seconds",
                unique_paths, TIME_WINDOW);
        return true;
    }

    return false;
}

/* Check for brute force patterns */
static bool detect_bruteforce(const source_history_t *history,
                            correlation_result_t *result) {
    time_t now = time(NULL);
    size_t auth_failures = 0;

    /* Check recent events */
    for (size_t i = 0; i < history->event_count; i++) {
        if (now - history->events[i].timestamp > TIME_WINDOW) continue;

        const analysis_result_t *analysis = &history->events[i].analysis;
        
        /* Look for failed auth patterns */
        if (strstr(analysis->http.path, "/login") ||
            strstr(analysis->http.path, "/auth")) {
            auth_failures++;
        }
    }

    /* Detect brute force attempts */
    if (auth_failures > 10) {  /* Threshold for brute force */
        result->type = CORR_BRUTEFORCE;
        result->confidence = auth_failures * 10;
        snprintf(result->details, sizeof(result->details),
                "Brute force detected: %zu auth failures in %d seconds",
                auth_failures, TIME_WINDOW);
        return true;
    }

    return false;
}

/* Check for DOS patterns */
static bool detect_dos(const source_history_t *history,
                      correlation_result_t *result) {
    time_t now = time(NULL);
    size_t request_count = 0;
    size_t error_count = 0;

    /* Count requests in last minute */
    for (size_t i = 0; i < history->event_count; i++) {
        if (now - history->events[i].timestamp > 60) continue;

        request_count++;
        if (history->events[i].analysis.flags & ANALYSIS_MALFORMED) {
            error_count++;
        }
    }

    /* Detect DOS patterns */
    if (request_count > 100 || error_count > 50) {  /* Thresholds */
        result->type = CORR_DOS;
        result->confidence = (request_count + error_count * 2) * 5;
        snprintf(result->details, sizeof(result->details),
                "DOS detected: %zu requests (%zu errors) in 60 seconds",
                request_count, error_count);
        return true;
    }

    return false;
}

/* Check for backdoor patterns */
static bool detect_backdoor(const source_history_t *history,
                          correlation_result_t *result) {
    time_t now = time(NULL);
    size_t suspicious_count = 0;
    size_t obfuscated_count = 0;

    /* Analyze recent events */
    for (size_t i = 0; i < history->event_count; i++) {
        if (now - history->events[i].timestamp > TIME_WINDOW) continue;

        const analysis_result_t *analysis = &history->events[i].analysis;
        
        if (analysis->flags & ANALYSIS_SUSPICIOUS) suspicious_count++;
        if (analysis->flags & ANALYSIS_OBFUSCATED) obfuscated_count++;
    }

    /* Detect backdoor patterns */
    if (suspicious_count > 5 && obfuscated_count > 2) {
        result->type = CORR_BACKDOOR;
        result->confidence = (suspicious_count + obfuscated_count * 2) * 10;
        snprintf(result->details, sizeof(result->details),
                "Backdoor suspected: %zu suspicious and %zu obfuscated requests",
                suspicious_count, obfuscated_count);
        return true;
    }

    return false;
}

/* Check for correlations */
bool correlation_check(corr_engine_t *engine,
                      const char *source,
                      correlation_result_t *result) {
    bool correlated = false;
    pthread_mutex_lock(&engine->lock);

    source_history_t *history = get_source(engine, source);
    if (!history) {
        pthread_mutex_unlock(&engine->lock);
        return false;
    }

    /* Initialize result */
    memset(result, 0, sizeof(*result));
    strncpy(result->source, source, sizeof(result->source) - 1);
    result->first_seen = history->first_seen;
    result->last_seen = history->last_seen;
    result->event_count = history->total_events;

    /* Check for various patterns */
    if (detect_scanning(history, result)) {
        correlated = true;
    }
    else if (detect_bruteforce(history, result)) {
        correlated = true;
    }
    else if (detect_dos(history, result)) {
        correlated = true;
    }
    else if (detect_backdoor(history, result)) {
        correlated = true;
    }

    pthread_mutex_unlock(&engine->lock);
    return correlated;
}

/* Clean up */
void correlation_destroy(corr_engine_t *engine) {
    if (!engine) return;
    pthread_mutex_destroy(&engine->lock);
    free(engine->sources);
    free(engine);
}