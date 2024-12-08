#include "advanced_security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <regex.h>

/* Maximum tracking entries */
#define MAX_CLIENTS 10000
#define MAX_PATTERNS 1000

/* Client tracking structure */
typedef struct {
    char ip[16];
    time_t *requests;
    size_t request_count;
    uint32_t attack_count;
    time_t first_seen;
    time_t last_seen;
    bool blocked;
} client_track_t;

/* Security context */
struct security_ctx {
    security_config_t config;
    client_track_t *clients;
    size_t client_count;
    regex_t *patterns;
    size_t pattern_count;
    pthread_mutex_t lock;
    FILE *log_file;
};

/* Known attack patterns */
static const char *attack_patterns[] = {
    /* SQL Injection */
    "\\b(UNION|SELECT|INSERT|UPDATE|DELETE)\\b.*\\bFROM\\b",
    "'\\s*OR\\s*'?\\s*'?\\s*\\d+\\s*'?\\s*=\\s*\\d+",
    "\\b(AND|OR)\\s+\\d+\\s*=\\s*\\d+\\s*--",
    
    /* XSS */
    "<script[^>]*>",
    "javascript:",
    "onload=",
    "onerror=",
    
    /* Path Traversal */
    "\\.\\./",
    "%2e%2e/",
    "\\\\\\.\\.",
    
    /* Command Injection */
    "\\b(cat|grep|awk|sed|curl|wget)\\b",
    "[;&|`]",
    "\\$\\([^)]*\\)",
    
    /* Protocol Abuse */
    "\\r[^\\n]",
    "\\n[^\\r]",
    "%00",
    
    NULL
};

/* Initialize security patterns */
static bool init_patterns(security_ctx_t *ctx) {
    const char **pattern = attack_patterns;
    size_t count = 0;
    
    /* Count patterns */
    while (pattern[count]) count++;
    
    /* Allocate pattern array */
    ctx->patterns = calloc(count, sizeof(regex_t));
    if (!ctx->patterns) return false;
    
    /* Compile patterns */
    for (size_t i = 0; i < count; i++) {
        if (regcomp(&ctx->patterns[i], attack_patterns[i], 
                    REG_EXTENDED | REG_ICASE) != 0) {
            /* Cleanup on failure */
            for (size_t j = 0; j < i; j++) {
                regfree(&ctx->patterns[j]);
            }
            free(ctx->patterns);
            return false;
        }
    }
    
    ctx->pattern_count = count;
    return true;
}

/* Create security context */
security_ctx_t *security_create(const security_config_t *config) {
    security_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    /* Copy configuration */
    ctx->config = *config;

    /* Allocate client tracking array */
    ctx->clients = calloc(MAX_CLIENTS, sizeof(client_track_t));
    if (!ctx->clients) {
        free(ctx);
        return NULL;
    }

    /* Initialize regex patterns */
    if (!init_patterns(ctx)) {
        free(ctx->clients);
        free(ctx);
        return NULL;
    }

    /* Initialize mutex */
    if (pthread_mutex_init(&ctx->lock, NULL) != 0) {
        free(ctx->patterns);
        free(ctx->clients);
        free(ctx);
        return NULL;
    }

    /* Open log file */
    ctx->log_file = fopen("security.log", "a");
    if (ctx->log_file) {
        setbuf(ctx->log_file, NULL);  /* Disable buffering */
    }

    return ctx;
}

/* Find or create client tracking entry */
static client_track_t *get_client(security_ctx_t *ctx,
                                const char *ip) {
    time_t now = time(NULL);

    /* Look for existing client */
    for (size_t i = 0; i < ctx->client_count; i++) {
        if (strcmp(ctx->clients[i].ip, ip) == 0) {
            ctx->clients[i].last_seen = now;
            return &ctx->clients[i];
        }
    }

    /* Add new client if space available */
    if (ctx->client_count < MAX_CLIENTS) {
        client_track_t *client = &ctx->clients[ctx->client_count++];
        strncpy(client->ip, ip, sizeof(client->ip) - 1);
        client->first_seen = client->last_seen = now;
        
        /* Allocate request tracking */
        client->requests = calloc(ctx->config.limits.max_requests,
                                sizeof(time_t));
        if (!client->requests) return NULL;
        
        return client;
    }

    return NULL;
}

/* Check rate limit for client */
static bool check_rate_limit(security_ctx_t *ctx,
                           client_track_t *client) {
    time_t now = time(NULL);
    size_t valid_count = 0;

    /* Count requests within window */
    for (size_t i = 0; i < client->request_count; i++) {
        if (now - client->requests[i] < ctx->config.limits.window_seconds) {
            client->requests[valid_count++] = client->requests[i];
        }
    }

    client->request_count = valid_count;

    /* Check if under limit */
    if (client->request_count >= ctx->config.limits.max_requests) {
        return false;
    }

    /* Add new request */
    client->requests[client->request_count++] = now;
    return true;
}

/* Check for attack patterns */
static attack_type_t detect_attack(security_ctx_t *ctx,
                                 const char *data,
                                 size_t length) {
    /* Quick check for obvious bad patterns */
    if (strstr(data, "../") || strstr(data, "..\\")) {
        return ATTACK_TRAVERSAL;
    }

    if (strstr(data, "<script") || strstr(data, "javascript:")) {
        return ATTACK_XSS;
    }

    /* Check regex patterns */
    for (size_t i = 0; i < ctx->pattern_count; i++) {
        if (regexec(&ctx->patterns[i], data, 0, NULL, 0) == 0) {
            /* Determine attack type based on pattern index */
            if (i < 3) return ATTACK_SQL_INJECTION;
            if (i < 7) return ATTACK_XSS;
            if (i < 10) return ATTACK_TRAVERSAL;
            if (i < 13) return ATTACK_COMMAND_INJECTION;
            return ATTACK_PROTOCOL;
        }
    }

    return ATTACK_NONE;
}

/* Check if request should be allowed */
bool security_check_request(security_ctx_t *ctx,
                          const char *client_ip,
                          const char *method,
                          const char *uri,
                          const char *headers,
                          const char *body,
                          size_t body_length) {
    bool allowed = true;
    attack_type_t attack = ATTACK_NONE;

    pthread_mutex_lock(&ctx->lock);

    /* Get client tracking */
    client_track_t *client = get_client(ctx, client_ip);
    if (!client) {
        pthread_mutex_unlock(&ctx->lock);
        return false;
    }

    /* Check if client is blocked */
    if (client->blocked) {
        pthread_mutex_unlock(&ctx->lock);
        return false;
    }

    /* Check rate limit */
    if (!check_rate_limit(ctx, client)) {
        security_log_attack(ctx, client_ip, ATTACK_DOS,
                          "Rate limit exceeded");
        allowed = false;
        goto end;
    }

    /* Size limits */
    if (body_length > ctx->config.limits.max_body_size) {
        security_log_attack(ctx, client_ip, ATTACK_DOS,
                          "Request too large");
        allowed = false;
        goto end;
    }

    /* Check URI for attacks */
    if ((attack = detect_attack(ctx, uri, strlen(uri))) != ATTACK_NONE) {
        security_log_attack(ctx, client_ip, attack,
                          "Attack detected in URI");
        allowed = false;
        goto end;
    }

    /* Check headers for attacks */
    if ((attack = detect_attack(ctx, headers, strlen(headers))) != ATTACK_NONE) {
        security_log_attack(ctx, client_ip, attack,
                          "Attack detected in headers");
        allowed = false;
        goto end;
    }

    /* Check body for attacks if present */
    if (body && body_length > 0) {
        if ((attack = detect_attack(ctx, body, body_length)) != ATTACK_NONE) {
            security_log_attack(ctx, client_ip, attack,
                              "Attack detected in body");
            allowed = false;
            goto end;
        }
    }

end:
    /* Update attack count and check for blocking */
    if (!allowed) {
        client->attack_count++;
        if (client->attack_count >= 5) {  /* Block after 5 attacks */
            client->blocked = true;
        }
    }

    pthread_mutex_unlock(&ctx->lock);
    return allowed;
}

/* Log security event */
void security_log_attack(security_ctx_t *ctx,
                        const char *client_ip,
                        attack_type_t type,
                        const char *details) {
    if (!ctx->config.log_attacks) return;

    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp),
            "%Y-%m-%d %H:%M:%S",
            localtime(&now));

    /* Log to file */
    if (ctx->log_file) {
        fprintf(ctx->log_file, "[%s] [%s] %s: %s\n",
                timestamp,
                type == ATTACK_DOS ? "DOS" :
                type == ATTACK_SQL_INJECTION ? "SQL" :
                type == ATTACK_XSS ? "XSS" :
                type == ATTACK_TRAVERSAL ? "PATH" :
                type == ATTACK_COMMAND_INJECTION ? "CMD" :
                type == ATTACK_PROTOCOL ? "PROTOCOL" : "UNKNOWN",
                client_ip,
                details);
    }

    /* Call alert callback if configured */
    if (ctx->config.alert_callback) {
        ctx->config.alert_callback(type, client_ip, details);
    }
}

/* Clean up security context */
void security_destroy(security_ctx_t *ctx) {
    if (!ctx) return;

    pthread_mutex_lock(&ctx->lock);

    /* Free patterns */
    for (size_t i = 0; i < ctx->pattern_count; i++) {
        regfree(&ctx->patterns[i]);
    }
    free(ctx->patterns);

    /* Free client tracking */
    for (size_t i = 0; i < ctx->client_count; i++) {
        free(ctx->clients[i].requests);
    }
    free(ctx->clients);

    /* Close log file */
    if (ctx->log_file) {
        fclose(ctx->log_file);
    }

    pthread_mutex_unlock(&ctx->lock);
    pthread_mutex_destroy(&ctx->lock);

    free(ctx);
}