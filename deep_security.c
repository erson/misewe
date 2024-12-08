#include "deep_security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>

/* Maximum tracking entries */
#define MAX_CLIENTS 10000
#define MAX_PATTERNS 1000
#define HISTORY_SIZE 100

/* Client tracking */
typedef struct {
    char ip[16];
    time_t first_seen;
    time_t last_seen;
    proto_state_t state;
    uint32_t request_count;
    uint32_t error_count;
    uint32_t burst_count;
    time_t burst_start;
    struct {
        uint32_t method_types[8];  /* Counts per HTTP method */
        uint32_t status_codes[6];  /* Counts per status category (1xx-6xx) */
        uint32_t avg_size;
        uint32_t max_size;
        uint32_t min_size;
    } stats;
    struct {
        time_t timestamps[HISTORY_SIZE];
        size_t sizes[HISTORY_SIZE];
        int status_codes[HISTORY_SIZE];
        size_t pos;
    } history;
    behavior_flags_t flags;
} client_track_t;

/* Pattern matching */
typedef struct {
    char *pattern;
    size_t length;
    uint32_t flags;
} pattern_t;

/* Security context */
struct deep_security {
    security_config_t config;
    client_track_t *clients;
    size_t client_count;
    pattern_t *patterns;
    size_t pattern_count;
    pthread_mutex_t lock;
    FILE *log_file;
};

/* Initialize pattern database */
static bool init_patterns(deep_security_t *sec) {
    sec->patterns = calloc(MAX_PATTERNS, sizeof(pattern_t));
    if (!sec->patterns) return false;

    /* Add known malicious patterns */
    const char *initial_patterns[] = {
        "/../",             /* Path traversal */
        "cmd=",             /* Command injection */
        "exec(",            /* Code execution */
        "UNION SELECT",     /* SQL injection */
        "<script",          /* XSS */
        "eval(",            /* JavaScript injection */
        NULL
    };

    for (const char **p = initial_patterns; *p && 
         sec->pattern_count < MAX_PATTERNS; p++) {
        pattern_t *pattern = &sec->patterns[sec->pattern_count++];
        pattern->pattern = strdup(*p);
        pattern->length = strlen(*p);
        pattern->flags = BEHAVIOR_MALICIOUS;
    }

    return true;
}

/* Find or create client tracking entry */
static client_track_t *get_client(deep_security_t *sec,
                                const char *ip) {
    time_t now = time(NULL);

    /* Look for existing entry */
    for (size_t i = 0; i < sec->client_count; i++) {
        if (strcmp(sec->clients[i].ip, ip) == 0) {
            sec->clients[i].last_seen = now;
            return &sec->clients[i];
        }
    }

    /* Add new entry if space available */
    if (sec->client_count < MAX_CLIENTS) {
        client_track_t *client = &sec->clients[sec->client_count++];
        memset(client, 0, sizeof(*client));
        strncpy(client->ip, ip, sizeof(client->ip) - 1);
        client->first_seen = client->last_seen = now;
        client->state = STATE_INIT;
        client->stats.min_size = UINT32_MAX;
        return client;
    }

    return NULL;
}

/* Check for rate limiting */
static bool check_rate_limit(deep_security_t *sec,
                           client_track_t *client) {
    time_t now = time(NULL);

    /* Reset burst counter if outside window */
    if (now - client->burst_start >= 60) {
        client->burst_count = 0;
        client->burst_start = now;
    }

    /* Check burst limit */
    if (client->burst_count >= sec->config.burst_limit) {
        client->flags |= BEHAVIOR_AGGRESSIVE;
        return false;
    }

    /* Check rate limit */
    uint32_t minute_rate = 0;
    for (size_t i = 0; i < HISTORY_SIZE; i++) {
        if (now - client->history.timestamps[i] < 60) {
            minute_rate++;
        }
    }

    if (minute_rate >= sec->config.rate_limit) {
        client->flags |= BEHAVIOR_AUTOMATED;
        return false;
    }

    client->burst_count++;
    return true;
}

/* Update client history */
static void update_history(client_track_t *client,
                         size_t size, int status) {
    time_t now = time(NULL);
    size_t pos = client->history.pos;

    client->history.timestamps[pos] = now;
    client->history.sizes[pos] = size;
    client->history.status_codes[pos] = status;

    client->history.pos = (pos + 1) % HISTORY_SIZE;

    /* Update statistics */
    client->stats.avg_size = 
        (client->stats.avg_size * (client->request_count - 1) + size) /
        client->request_count;
    
    if (size > client->stats.max_size) client->stats.max_size = size;
    if (size < client->stats.min_size) client->stats.min_size = size;

    if (status >= 100 && status < 600) {
        client->stats.status_codes[status / 100]++;
    }
}

/* Pattern matching with Boyer-Moore-Horspool */
static bool find_pattern(const char *text, size_t text_len,
                        const char *pattern, size_t pattern_len) {
    if (pattern_len > text_len) return false;

    /* Build bad character table */
    size_t bad_char[256];
    for (size_t i = 0; i < 256; i++) {
        bad_char[i] = pattern_len;
    }
    for (size_t i = 0; i < pattern_len - 1; i++) {
        bad_char[(unsigned char)pattern[i]] = pattern_len - 1 - i;
    }

    /* Search */
    size_t pos = pattern_len - 1;
    while (pos < text_len) {
        size_t p = pattern_len - 1;
        size_t t = pos;
        while (p != SIZE_MAX && pattern[p] == text[t]) {
            p--;
            t--;
        }
        if (p == SIZE_MAX) return true;
        pos += bad_char[(unsigned char)text[pos]];
    }

    return false;
}

/* Check request content */
static behavior_flags_t analyze_content(deep_security_t *sec,
                                      const void *data,
                                      size_t length) {
    behavior_flags_t flags = BEHAVIOR_NORMAL;
    const char *text = data;

    /* Check each pattern */
    for (size_t i = 0; i < sec->pattern_count; i++) {
        pattern_t *pattern = &sec->patterns[i];
        if (find_pattern(text, length,
                        pattern->pattern,
                        pattern->length)) {
            flags |= pattern->flags;
            if (flags & BEHAVIOR_MALICIOUS) break;
        }
    }

    /* Additional content checks */
    size_t upper_count = 0;
    size_t symbol_count = 0;
    size_t number_count = 0;

    for (size_t i = 0; i < length; i++) {
        if (isupper(text[i])) upper_count++;
        else if (ispunct(text[i])) symbol_count++;
        else if (isdigit(text[i])) number_count++;
    }

    /* Check for suspicious content patterns */
    if (upper_count > length / 2) flags |= BEHAVIOR_SUSPICIOUS;
    if (symbol_count > length / 4) flags |= BEHAVIOR_SUSPICIOUS;
    if (number_count > length / 3) flags |= BEHAVIOR_SUSPICIOUS;

    return flags;
}

/* Create security context */
deep_security_t *security_create(const security_config_t *config) {
    deep_security_t *sec = calloc(1, sizeof(*sec));
    if (!sec) return NULL;

    /* Copy configuration */
    sec->config = *config;

    /* Allocate client tracking array */
    sec->clients = calloc(MAX_CLIENTS, sizeof(client_track_t));
    if (!sec->clients) {
        free(sec);
        return NULL;
    }

    /* Initialize patterns */
    if (!init_patterns(sec)) {
        free(sec->clients);
        free(sec);
        return NULL;
    }

    /* Initialize mutex */
    if (pthread_mutex_init(&sec->lock, NULL) != 0) {
        free(sec->patterns);
        free(sec->clients);
        free(sec);
        return NULL;
    }

    return sec;
}

/* Check request security */
bool security_check_request(deep_security_t *sec,
                          const char *client_ip,
                          const void *data,
                          size_t length) {
    bool allowed = true;
    pthread_mutex_lock(&sec->lock);

    /* Get client tracking */
    client_track_t *client = get_client(sec, client_ip);
    if (!client) {
        pthread_mutex_unlock(&sec->lock);
        return false;
    }

    /* Basic checks */
    if (length > sec->config.max_request_size) {
        client->flags |= BEHAVIOR_SUSPICIOUS;
        allowed = false;
        goto end;
    }

    /* Rate limiting */
    if (!check_rate_limit(sec, client)) {
        allowed = false;
        goto end;
    }

    /* Content analysis */
    behavior_flags_t content_flags = analyze_content(sec, data, length);
    client->flags |= content_flags;

    /* Update history */
    client->request_count++;
    update_history(client, length, 0);  /* Status code updated later */

    /* Security level checks */
    switch (sec->config.level) {
        case SECURITY_PARANOID:
            allowed = !(client->flags & (BEHAVIOR_SUSPICIOUS |
                                       BEHAVIOR_AUTOMATED |
                                       BEHAVIOR_AGGRESSIVE |
                                       BEHAVIOR_MALICIOUS));
            break;

        case SECURITY_HIGH:
            allowed = !(client->flags & (BEHAVIOR_AGGRESSIVE |
                                       BEHAVIOR_MALICIOUS));
            break;

        case SECURITY_STANDARD:
            allowed = !(client->flags & BEHAVIOR_MALICIOUS);
            break;

        case SECURITY_MINIMAL:
            allowed = true;
            break;
    }

end:
    pthread_mutex_unlock(&sec->lock);
    return allowed;
}

/* Update protocol state */
void security_update_state(deep_security_t *sec,
                         const char *client_ip,
                         proto_state_t new_state) {
    pthread_mutex_lock(&sec->lock);

    client_track_t *client = get_client(sec, client_ip);
    if (client) {
        /* Check for invalid state transitions */
        switch (client->state) {
            case STATE_INIT:
                if (new_state != STATE_HEADERS &&
                    new_state != STATE_ERROR) {
                    client->error_count++;
                }
                break;

            case STATE_HEADERS:
                if (new_state != STATE_BODY &&
                    new_state != STATE_COMPLETE &&
                    new_state != STATE_ERROR) {
                    client->error_count++;
                }
                break;

            case STATE_BODY:
                if (new_state != STATE_COMPLETE &&
                    new_state != STATE_ERROR) {
                    client->error_count++;
                }
                break;

            case STATE_COMPLETE:
            case STATE_ERROR:
                if (new_state != STATE_INIT) {
                    client->error_count++;
                }
                break;
        }

        client->state = new_state;
    }

    pthread_mutex_unlock(&sec->lock);
}

/* Analyze client behavior */
behavior_flags_t security_analyze_behavior(deep_security_t *sec,
                                         const char *client_ip) {
    behavior_flags_t flags = BEHAVIOR_NORMAL;
    pthread_mutex_lock(&sec->lock);

    client_track_t *client = get_client(sec, client_ip);
    if (!client) {
        pthread_mutex_unlock(&sec->lock);
        return BEHAVIOR_SUSPICIOUS;
    }

    /* Check error rate */
    float error_rate = (float)client->error_count /
                      (float)client->request_count;
    if (error_rate > 0.1) flags |= BEHAVIOR_SUSPICIOUS;
    if (error_rate > 0.3) flags |= BEHAVIOR_MALICIOUS;

    /* Check request patterns */
    time_t now = time(NULL);
    uint32_t intervals[10] = {0};  /* 10-second intervals */
    uint32_t max_interval = 0;

    for (size_t i = 0; i < HISTORY_SIZE; i++) {
        time_t ts = client->history.timestamps[i];
        if (now - ts < 100) {  /* Last 100 seconds */
            uint32_t interval = (now - ts) / 10;
            intervals[interval]++;
            if (intervals[interval] > max_interval) {
                max_interval = intervals[interval];
            }
        }
    }

    /* Check for suspicious patterns */
    if (max_interval > sec->config.rate_limit / 2) {
        flags |= BEHAVIOR_AUTOMATED;
    }
    if (max_interval > sec->config.rate_limit) {
        flags |= BEHAVIOR_AGGRESSIVE;
    }

    /* Combine with existing flags */
    flags |= client->flags;

    pthread_mutex_unlock(&sec->lock);
    return flags;
}

/* Clean up security context */
void security_destroy(deep_security_t *sec) {
    if (!sec) return;

    pthread_mutex_lock(&sec->lock);

    /* Free patterns */
    for (size_t i = 0; i < sec->pattern_count; i++) {
        free(sec->patterns[i].pattern);
    }
    free(sec->patterns);

    /* Free client tracking */
    free(sec->clients);

    pthread_mutex_unlock(&sec->lock);
    pthread_mutex_destroy(&sec->lock);
    free(sec);
}