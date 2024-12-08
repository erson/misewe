#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>
#include <time.h>
#include <stdbool.h>

/* Session flags */
typedef enum {
    SESSION_FLAG_SECURE = 1 << 0,      /* HTTPS only */
    SESSION_FLAG_HTTPONLY = 1 << 1,    /* No JavaScript access */
    SESSION_FLAG_STRICT = 1 << 2       /* Strict session validation */
} session_flags_t;

/* Session data */
typedef struct {
    char id[64];                /* Session ID */
    char token[128];           /* CSRF token */
    char ip[16];               /* Client IP */
    char user_agent[256];      /* Client user agent */
    time_t created;            /* Creation timestamp */
    time_t expires;            /* Expiration timestamp */
    uint32_t flags;            /* Session flags */
} session_t;

/* Session manager context */
typedef struct session_mgr session_mgr_t;

/* Session manager configuration */
typedef struct {
    size_t max_sessions;       /* Maximum concurrent sessions */
    time_t session_timeout;    /* Session timeout in seconds */
    bool rotate_tokens;        /* Whether to rotate CSRF tokens */
    const char *secret_key;    /* Key for token generation */
    uint32_t default_flags;    /* Default session flags */
} session_config_t;

/* Function prototypes */
session_mgr_t *session_mgr_create(const session_config_t *config);
void session_mgr_destroy(session_mgr_t *mgr);
session_t *session_create(session_mgr_t *mgr, const char *ip,
                         const char *user_agent);
session_t *session_get(session_mgr_t *mgr, const char *id);
bool session_validate(session_mgr_t *mgr, session_t *session,
                     const char *ip, const char *user_agent);
bool session_refresh(session_mgr_t *mgr, session_t *session);
void session_destroy(session_mgr_t *mgr, session_t *session);
bool session_verify_token(session_mgr_t *mgr, session_t *session,
                         const char *token);

#endif /* SESSION_H */