#include "intrusion_detector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <math.h>

#define MAX_FEATURES 1000
#define MAX_RULES 5000
#define HISTORY_SIZE 10000
#define NGRAM_SIZE 3

/* Feature vector */
typedef struct {
    float values[MAX_FEATURES];
    size_t count;
} feature_vector_t;

/* Detection rule */
typedef struct {
    char *pattern;
    attack_type_t type;
    confidence_t confidence;
    alert_level_t level;
    uint32_t id;
    uint32_t hits;
    float weight;
} rule_t;

/* Request history entry */
typedef struct {
    feature_vector_t features;
    bool is_attack;
    time_t timestamp;
} history_entry_t;

/* Detector context */
struct intrusion_detector {
    detector_config_t config;
    rule_t *rules;
    size_t rule_count;
    history_entry_t *history;
    size_t history_pos;
    alert_callback_t callback;
    void *callback_data;
    pthread_mutex_t lock;
    
    /* ML model data */
    float *weights;
    size_t weight_count;
    float threshold;
};

/* Feature extraction */
static void extract_features(const void *data, size_t length,
                           feature_vector_t *features) {
    const unsigned char *bytes = data;
    size_t ngram_counts[256 * 256] = {0};  /* 2-gram frequencies */
    
    /* Calculate n-gram frequencies */
    for (size_t i = 0; i < length - 1; i++) {
        uint32_t ngram = (bytes[i] << 8) | bytes[i + 1];
        ngram_counts[ngram]++;
    }
    
    /* Convert to feature vector */
    features->count = 0;
    for (size_t i = 0; i < 256 * 256 && features->count < MAX_FEATURES; i++) {
        if (ngram_counts[i] > 0) {
            features->values[features->count++] = 
                (float)ngram_counts[i] / (float)(length - 1);
        }
    }

    /* Add statistical features */
    size_t ascii_count = 0;
    size_t ctrl_count = 0;
    size_t digit_count = 0;
    size_t symbol_count = 0;

    for (size_t i = 0; i < length; i++) {
        if (bytes[i] >= 32 && bytes[i] <= 126) ascii_count++;
        if (bytes[i] < 32 || bytes[i] == 127) ctrl_count++;
        if (bytes[i] >= '0' && bytes[i] <= '9') digit_count++;
        if (strchr("!@#$%^&*(){}[]<>?|\\", bytes[i])) symbol_count++;
    }

    /* Add ratios as features */
    if (features->count < MAX_FEATURES) {
        features->values[features->count++] = (float)ascii_count / length;
    }
    if (features->count < MAX_FEATURES) {
        features->values[features->count++] = (float)ctrl_count / length;
    }
    if (features->count < MAX_FEATURES) {
        features->values[features->count++] = (float)digit_count / length;
    }
    if (features->count < MAX_FEATURES) {
        features->values[features->count++] = (float)symbol_count / length;
    }
}

/* Calculate probability using logistic regression */
static float calculate_probability(const detector_t *detector,
                                 const feature_vector_t *features) {
    float sum = 0;
    
    for (size_t i = 0; i < features->count && i < detector->weight_count; i++) {
        sum += features->values[i] * detector->weights[i];
    }
    
    /* Logistic function */
    return 1.0f / (1.0f + expf(-sum));
}

/* Update ML model weights */
static void update_weights(detector_t *detector,
                         const feature_vector_t *features,
                         bool is_attack,
                         float learning_rate) {
    float prob = calculate_probability(detector, features);
    float error = (is_attack ? 1.0f : 0.0f) - prob;
    
    /* Update weights using gradient descent */
    for (size_t i = 0; i < features->count && i < detector->weight_count; i++) {
        detector->weights[i] += learning_rate * error * features->values[i];
    }
}

/* Rule matching */
static bool match_rule(const rule_t *rule,
                      const void *data,
                      size_t length,
                      detection_result_t *result) {
    /* Simple pattern matching for now */
    if (memmem(data, length, rule->pattern, strlen(rule->pattern))) {
        if (result) {
            result->type = rule->type;
            result->confidence = rule->confidence;
            result->level = rule->level;
            result->rule_id = rule->id;
            result->timestamp = time(NULL);
            snprintf(result->details, sizeof(result->details),
                    "Matched rule %u: %s", rule->id, rule->pattern);
        }
        return true;
    }
    return false;
}

/* Create detector */
detector_t *detector_create(const detector_config_t *config) {
    detector_t *detector = calloc(1, sizeof(*detector));
    if (!detector) return NULL;

    /* Copy configuration */
    detector->config = *config;

    /* Allocate rules array */
    detector->rules = calloc(MAX_RULES, sizeof(rule_t));
    if (!detector->rules) {
        free(detector);
        return NULL;
    }

    /* Allocate history buffer if learning enabled */
    if (config->enable_learning) {
        detector->history = calloc(config->history_size,
                                 sizeof(history_entry_t));
        if (!detector->history) {
            free(detector->rules);
            free(detector);
            return NULL;
        }

        /* Initialize ML weights */
        detector->weights = calloc(MAX_FEATURES, sizeof(float));
        if (!detector->weights) {
            free(detector->history);
            free(detector->rules);
            free(detector);
            return NULL;
        }
        detector->weight_count = MAX_FEATURES;
        detector->threshold = config->threshold;
    }

    /* Initialize mutex */
    if (pthread_mutex_init(&detector->lock, NULL) != 0) {
        free(detector->weights);
        free(detector->history);
        free(detector->rules);
        free(detector);
        return NULL;
    }

    return detector;
}

/* Check request for intrusions */
bool detector_check_request(detector_t *detector,
                          const void *data,
                          size_t length,
                          detection_result_t *result) {
    bool attack_detected = false;
    pthread_mutex_lock(&detector->lock);

    /* Extract features */
    feature_vector_t features;
    extract_features(data, length, &features);

    /* Check rules first */
    for (size_t i = 0; i < detector->rule_count; i++) {
        if (match_rule(&detector->rules[i], data, length, result)) {
            attack_detected = true;
            detector->rules[i].hits++;
            break;
        }
    }

    /* Use ML model if enabled and no rule matches */
    if (!attack_detected && detector->config.enable_learning) {
        float prob = calculate_probability(detector, &features);
        
        if (prob > detector->threshold) {
            attack_detected = true;
            if (result) {
                result->type = ATTACK_UNKNOWN;
                result->confidence = prob > 0.9f ? CONFIDENCE_HIGH :
                                   prob > 0.7f ? CONFIDENCE_MEDIUM :
                                   CONFIDENCE_LOW;
                result->level = ALERT_WARNING;
                result->timestamp = time(NULL);
                snprintf(result->details, sizeof(result->details),
                        "ML model detection (probability: %.2f)", prob);
            }
        }

        /* Store in history */
        if (detector->history) {
            history_entry_t *entry = &detector->history[detector->history_pos];
            memcpy(&entry->features, &features, sizeof(features));
            entry->is_attack = attack_detected;
            entry->timestamp = time(NULL);
            detector->history_pos = (detector->history_pos + 1) %
                                  detector->config.history_size;
        }
    }

    /* Trigger callback if attack detected */
    if (attack_detected && detector->callback) {
        detector->callback(result, detector->callback_data);
    }

    pthread_mutex_unlock(&detector->lock);
    return attack_detected;
}

/* Train the ML model */
void detector_train(detector_t *detector,
                   const void *data,
                   size_t length,
                   bool is_attack) {
    if (!detector->config.enable_learning) return;

    pthread_mutex_lock(&detector->lock);

    /* Extract features */
    feature_vector_t features;
    extract_features(data, length, &features);

    /* Update model */
    update_weights(detector, &features, is_attack, 0.1f);

    pthread_mutex_unlock(&detector->lock);
}

/* Set alert callback */
void detector_set_callback(detector_t *detector,
                         alert_callback_t callback,
                         void *user_data) {
    pthread_mutex_lock(&detector->lock);
    detector->callback = callback;
    detector->callback_data = user_data;
    pthread_mutex_unlock(&detector->lock);
}

/* Clean up detector */
void detector_destroy(detector_t *detector) {
    if (!detector) return;

    pthread_mutex_lock(&detector->lock);

    /* Free rules */
    for (size_t i = 0; i < detector->rule_count; i++) {
        free(detector->rules[i].pattern);
    }
    free(detector->rules);

    /* Free ML data */
    free(detector->weights);
    free(detector->history);

    pthread_mutex_unlock(&detector->lock);
    pthread_mutex_destroy(&detector->lock);
    free(detector);
}