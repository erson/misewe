#include "behavior_analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <pthread.h>

#define MAX_CLIENTS 10000
#define MAX_PATHS 1000
#define MAX_HISTORY 1000
#define ANALYSIS_WINDOW 3600  /* 1 hour */

/* Request history entry */
typedef struct {
    char method[16];
    char path[256];
    size_t size;
    int status_code;
    time_t timestamp;
} request_history_t;

/* Client tracking */
typedef struct {
    char ip[64];
    request_history_t *history;
    size_t history_pos;
    size_t total_requests;
    
    /* Path tracking */
    struct {
        char path[256];
        uint32_t count;
    } paths[MAX_PATHS];
    size_t unique_paths;

    /* Method tracking */
    struct {
        char method[16];
        uint32_t count;
    } methods[10];
    size_t unique_methods;

    /* Timing analysis */
    time_t *intervals;
    size_t interval_count;

    /* Last analysis result */
    behavior_result_t last_result;
    time_t last_analysis;
} client_track_t;

/* Analyzer context */
struct behavior_analyzer {
    client_track_t *clients;
    size_t client_count;
    pthread_mutex_t lock;
};

/* Create behavior analyzer */
behavior_analyzer_t *behavior_create(void) {
    behavior_analyzer_t *analyzer = calloc(1, sizeof(*analyzer));
    if (!analyzer) return NULL;

    /* Allocate client tracking array */
    analyzer->clients = calloc(MAX_CLIENTS, sizeof(client_track_t));
    if (!analyzer->clients) {
        free(analyzer);
        return NULL;
    }

    /* Initialize each client's storage */
    for (size_t i = 0; i < MAX_CLIENTS; i++) {
        client_track_t *client = &analyzer->clients[i];
        
        client->history = calloc(MAX_HISTORY, sizeof(request_history_t));
        client->intervals = calloc(MAX_HISTORY, sizeof(time_t));
        
        if (!client->history || !client->intervals) {
            /* Clean up on failure */
            for (size_t j = 0; j <= i; j++) {
                free(analyzer->clients[j].history);
                free(analyzer->clients[j].intervals);
            }
            free(analyzer->clients);
            free(analyzer);
            return NULL;
        }
    }

    /* Initialize mutex */
    if (pthread_mutex_init(&analyzer->lock, NULL) != 0) {
        for (size_t i = 0; i < MAX_CLIENTS; i++) {
            free(analyzer->clients[i].history);
            free(analyzer->clients[i].intervals);
        }
        free(analyzer->clients);
        free(analyzer);
        return NULL;
    }

    return analyzer;
}

/* Find or create client tracking entry */
static client_track_t *get_client(behavior_analyzer_t *analyzer,
                                const char *ip) {
    /* Look for existing client */
    for (size_t i = 0; i < analyzer->client_count; i++) {
        if (strcmp(analyzer->clients[i].ip, ip) == 0) {
            return &analyzer->clients[i];
        }
    }

    /* Add new client if space available */
    if (analyzer->client_count < MAX_CLIENTS) {
        client_track_t *client = &analyzer->clients[analyzer->client_count++];
        strncpy(client->ip, ip, sizeof(client->ip) - 1);
        return client;
    }

    return NULL;
}

/* Update path statistics */
static void update_path_stats(client_track_t *client, const char *path) {
    /* Look for existing path */
    for (size_t i = 0; i < client->unique_paths; i++) {
        if (strcmp(client->paths[i].path, path) == 0) {
            client->paths[i].count++;
            return;
        }
    }

    /* Add new path if space available */
    if (client->unique_paths < MAX_PATHS) {
        size_t idx = client->unique_paths++;
        strncpy(client->paths[idx].path, path, 255);
        client->paths[idx].count = 1;
    }
}

/* Update method statistics */
static void update_method_stats(client_track_t *client, const char *method) {
    /* Look for existing method */
    for (size_t i = 0; i < client->unique_methods; i++) {
        if (strcmp(client->methods[i].method, method) == 0) {
            client->methods[i].count++;
            return;
        }
    }

    /* Add new method if space available */
    if (client->unique_methods < 10) {
        size_t idx = client->unique_methods++;
        strncpy(client->methods[idx].method, method, 15);
        client->methods[idx].count = 1;
    }
}

/* Calculate timing regularity */
static float calculate_regularity(const time_t *intervals, size_t count) {
    if (count < 2) return 0.0f;

    /* Calculate mean interval */
    float mean = 0;
    for (size_t i = 0; i < count; i++) {
        mean += intervals[i];
    }
    mean /= count;

    /* Calculate standard deviation */
    float variance = 0;
    for (size_t i = 0; i < count; i++) {
        float diff = intervals[i] - mean;
        variance += diff * diff;
    }
    variance /= count;

    /* Convert to coefficient of variation */
    float stddev = sqrtf(variance);
    float cv = stddev / mean;

    /* Return regularity score (1 = very regular, 0 = irregular) */
    return 1.0f / (1.0f + cv);
}

/* Extract request features */
static void extract_features(client_track_t *client,
                           request_features_t *features) {
    time_t now = time(NULL);
    time_t window_start = now - ANALYSIS_WINDOW;
    
    uint32_t request_count = 0;
    uint32_t error_count = 0;
    uint32_t total_size = 0;

    /* Analyze recent history */
    for (size_t i = 0; i < MAX_HISTORY; i++) {
        request_history_t *req = &client->history[i];
        if (req->timestamp < window_start) continue;

        request_count++;
        total_size += req->size;
        if (req->status_code >= 400) error_count++;
    }

    /* Calculate features */
    features->request_rate = request_count * 60 / ANALYSIS_WINDOW;
    features->error_rate = error_count * 60 / ANALYSIS_WINDOW;
    features->avg_size = request_count ? total_size / request_count : 0;
    features->path_diversity = client->unique_paths;
    features->method_diversity = client->unique_methods;
    features->timing_regularity = calculate_regularity(
        client->intervals, client->interval_count);
}

/* Add request to history */
void behavior_add_request(behavior_analyzer_t *analyzer,
                        const char *client_ip,
                        const char *method,
                        const char *path,
                        size_t size,
                        int status_code) {
    pthread_mutex_lock(&analyzer->lock);

    client_track_t *client = get_client(analyzer, client_ip);
    if (!client) {
        pthread_mutex_unlock(&analyzer->lock);
        return;
    }

    /* Add to history */
    size_t pos = client->history_pos % MAX_HISTORY;
    request_history_t *req = &client->history[pos];

    strncpy(req->method, method, sizeof(req->method) - 1);
    strncpy(req->path, path, sizeof(req->path) - 1);
    req->size = size;
    req->status_code = status_code;
    req->timestamp = time(NULL);

    client->history_pos++;

    /* Update statistics */
    update_path_stats(client, path);
    update_method_stats(client, method);

    /* Update timing intervals */
    if (client->total_requests > 0) {
        time_t last_time = client->history[(client->history_pos - 2) % MAX_HISTORY].timestamp;
        time_t interval = req->timestamp - last_time;
        client->intervals[client->interval_count % MAX_HISTORY] = interval;
        client->interval_count++;
    }

    client->total_requests++;

    pthread_mutex_unlock(&analyzer->lock);
}

/* Detect bot behavior */
static bool detect_bot(const request_features_t *features,
                      behavior_result_t *result) {
    /* Bot detection criteria */
    if (features->timing_regularity > 0.9f &&
        features->request_rate > 30) {
        result->type = BEHAVIOR_BOT;
        result->confidence = features->timing_regularity * 100;
        snprintf(result->details, sizeof(result->details),
                "Bot behavior detected: regular timing (%.2f) "
                "with high request rate (%u/min)",
                features->timing_regularity,
                features->request_rate);
        return true;
    }

    return false;
}

/* Detect attack behavior */
static bool detect_attack(const request_features_t *features,
                        behavior_result_t *result) {
    /* Attack detection criteria */
    if (features->error_rate > 10 ||
        (features->path_diversity > 50 && features->request_rate > 20)) {
        result->type = BEHAVIOR_ATTACK;
        result->confidence = 80.0f;
        snprintf(result->details, sizeof(result->details),
                "Attack behavior detected: high error rate (%u/min) "
                "or aggressive path scanning (%u paths)",
                features->error_rate,
                features->path_diversity);
        return true;
    }

    return false;
}

/* Detect anomalous behavior */
static bool detect_anomaly(const request_features_t *features,
                         behavior_result_t *result) {
    /* Anomaly detection criteria */
    if (features->method_diversity > 3 ||
        features->avg_size > 50000) {
        result->type = BEHAVIOR_ANOMALY;
        result->confidence = 60.0f;
        snprintf(result->details, sizeof(result->details),
                "Anomalous behavior: unusual methods (%u) "
                "or large requests (%u avg bytes)",
                features->method_diversity,
                features->avg_size);
        return true;
    }

    return false;
}

/* Analyze client behavior */
bool behavior_analyze(behavior_analyzer_t *analyzer,
                     const char *client_ip,
                     behavior_result_t *result) {
    pthread_mutex_lock(&analyzer->lock);

    client_track_t *client = get_client(analyzer, client_ip);
    if (!client) {
        pthread_mutex_unlock(&analyzer->lock);
        return false;
    }

    /* Check if analysis is needed */
    time_t now = time(NULL);
    if (now - client->last_analysis < 60 &&
        client->last_result.type != BEHAVIOR_NORMAL) {
        /* Return cached result */
        *result = client->last_result;
        pthread_mutex_unlock(&analyzer->lock);
        return true;
    }

    /* Extract features */
    extract_features(client, &result->features);

    /* Run detection */
    bool detected = false;
    if (detect_bot(&result->features, result)) {
        detected = true;
    }
    else if (detect_attack(&result->features, result)) {
        detected = true;
    }
    else if (detect_anomaly(&result->features, result)) {
        detected = true;
    }
    else {
        result->type = BEHAVIOR_NORMAL;
        result->confidence = 100.0f;
        strncpy(result->details, "Normal behavior", sizeof(result->details));
    }

    /* Cache result */
    client->last_result = *result;
    client->last_analysis = now;

    pthread_mutex_unlock(&analyzer->lock);
    return detected;
}

/* Clean up analyzer */
void behavior_destroy(behavior_analyzer_t *analyzer) {
    if (!analyzer) return;

    pthread_mutex_lock(&analyzer->lock);

    /* Free client data */
    for (size_t i = 0; i < MAX_CLIENTS; i++) {
        free(analyzer->clients[i].history);
        free(analyzer->clients[i].intervals);
    }

    pthread_mutex_unlock(&analyzer->lock);
    pthread_mutex_destroy(&analyzer->lock);
    
    free(analyzer->clients);
    free(analyzer);
}