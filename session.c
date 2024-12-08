#include "session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#define SESSION_ID_LEN 32
#define TOKEN_LEN 64

struct session_mgr {
    session_config_t config;
    session_t *sessions;
    size_t count;
    pthread_mutex_t lock;
    unsigned char hmac_key[64];
};

/* Generate random string */
static void generate_random_string(char *buf, size_t len) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyz"
                                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                "0123456789-_";
    unsigned char random[256];

    /* Generate random bytes */
    if (RAND_bytes(random, len) != 1) {
        /* Fallback to less secure but still useful random */
        for (size_t i = 0; i < len; i++) {
            random[i] = rand() & 0xFF;
        }
    }

    /* Convert to printable characters */
    for (size_t i = 0; i < len; i++) {
        buf[i] = charset[random[i] % (sizeof(charset) - 1)];
    }
    buf[len] = '\0';
}

/* Generate HMAC-based token */
static void generate_token(session_mgr_t *mgr, const char *session_id,
                         char *token, size_t token_len) {
    unsigned char hmac[SHA256_DIGEST_LENGTH];
    char buffer[512];
    time_t now = time(NULL);

    /* Combine session ID, timestamp, and secret */
    snprintf(buffer, sizeof(buffer), "%s:%ld:%s",
             session_id, now, mgr->config.secret_key);

    /* Calculate HMAC */
    HMAC(EVP_sha256(), mgr->hmac_key, sizeof(mgr->hmac_key),
         (unsigned char*)buffer, strlen(buffer),
         hmac, NULL);

    /* Convert to hex */
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH && (i * 2) < token_len - 1; i++) {
        sprintf(token + (i * 2), "%02x", hmac[i]);
    }
}

/* Create session manager */
session_mgr_t *session_mgr_create(const session_config_t *config) {
    session_mgr_t *mgr = calloc(1, sizeof(*mgr));
    if (!mgr) return NULL;

    /* Copy configuration */
    mgr->config = *config;

    /* Allocate session array */
    mgr->sessions = calloc(config->max_sessions, sizeof(session_t));
    if (!mgr->sessions) {
        free(mgr);
        return NULL;
    }

    /* Initialize mutex */
    if (pthread_mutex_init(&mgr->lock, NULL) != 0) {
        free(mgr->sessions);
        free(mgr);
        return NULL;
    }

    /* Generate HMAC key */
    if (RAND_bytes(mgr->hmac_key, sizeof(mgr->hmac_key)) != 1) {
        pthread_mutex_destroy(&mgr->lock);
        free(mgr->sessions);
        free(mgr);
        return NULL;
    }

    return mgr;
}

/* Create new session */
session_t *session_create(session_mgr_t *mgr, const char *ip,
                         const char *user_agent) {
    time_t now = time(NULL);
    session_t *session = NULL;

    pthread_mutex_lock(&mgr->lock);

    /* Find free slot */
    for (size_t i = 0; i < mgr->config.max_sessions; i++) {
        if (mgr->sessions[i].created == 0) {
            session = &mgr->sessions[i];
            break;
        }
    }

    if (!session) {
        pthread_mutex_unlock(&mgr->lock);
        return NULL;
    }

    /* Initialize session */
    memset(session, 0, sizeof(*session));
    generate_random_string(session->id, SESSION_ID_LEN);
    generate_token(mgr, session->id, session->token, sizeof(session->token));
    strncpy(session->ip, ip, sizeof(session->ip) - 1);
    strncpy(session->user_agent, user_agent, sizeof(session->user_agent) - 1);
    session->created = now;
    session->expires = now + mgr->config.session_timeout;
    session->flags = mgr->config.default_flags;

    mgr->count++;
    pthread_mutex_unlock(&mgr->lock);

    return session;
}

/* Get existing session */
session_t *session_get(session_mgr_t *mgr, const char *id) {
    pthread_mutex_lock(&mgr->lock);

    session_t *session = NULL;
    for (size_t i = 0; i < mgr->config.max_sessions; i++) {
        if (mgr->sessions[i].created != 0 &&
            strcmp(mgr->sessions[i].id, id) == 0) {
            session = &mgr->sessions[i];
            break;
        }
    }

    pthread_mutex_unlock(&mgr->lock);
    return session;
}

/* Validate session */
bool session_validate(session_mgr_t *mgr, session_t *session,
                     const char *ip, const char *user_agent) {
    if (!session || !ip || !user_agent) return false;

    time_t now = time(NULL);

    /* Check expiration */
    if (now >= session->expires) {
        return false;
    }

    /* Check IP and user agent if strict mode enabled */
    if (session->flags & SESSION_FLAG_STRICT) {
        if (strcmp(session->ip, ip) != 0 ||
            strcmp(session->user_agent, user_agent) != 0) {
            return false;
        }
    }

    return true;
}

/* Refresh session */
bool session_refresh(session_mgr_t *mgr, session_t *session) {
    if (!session) return false;

    pthread_mutex_lock(&mgr->lock);

    /* Update expiration */
    session->expires = time(NULL) + mgr->config.session_timeout;

    /* Rotate token if configured */
    if (mgr->config.rotate_tokens) {
        generate_token(mgr, session->id, session->token,
                      sizeof(session->token));
    }

    pthread_mutex_unlock(&mgr->lock);
    return true;
}

/* Verify CSRF token */
bool session_verify_token(session_mgr_t *mgr, session_t *session,
                         const char *token) {
    if (!session || !token) return false;

    bool valid;
    pthread_mutex_lock(&mgr->lock);
    valid = (strcmp(session->token, token) == 0);
    pthread_mutex_unlock(&mgr->lock);

    return valid;
}

/* Destroy session */
void session_destroy(session_mgr_t *mgr, session_t *session) {
    if (!session) return;

    pthread_mutex_lock(&mgr->lock);

    /* Clear session data */
    memset(session, 0, sizeof(*session));
    mgr->count--;

    pthread_mutex_unlock(&mgr->lock);
}

/* Clean up session manager */
void session_mgr_destroy(session_mgr_t *mgr) {
    if (!mgr) return;

    /* Clear all sensitive data */
    memset(mgr->hmac_key, 0, sizeof(mgr->hmac_key));
    for (size_t i = 0; i < mgr->config.max_sessions; i++) {
        memset(&mgr->sessions[i], 0, sizeof(session_t));
    }

    pthread_mutex_destroy(&mgr->lock);
    free(mgr->sessions);
    free(mgr);
}