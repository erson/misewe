#ifndef AUTH_H
#define AUTH_H

#include <stdbool.h>

/* Authentication context */
typedef struct auth_ctx auth_ctx_t;

/* Authentication result */
typedef struct {
    bool success;
    char username[64];
    bool is_admin;
    char error[256];
} auth_result_t;

/* Function prototypes */
auth_ctx_t *auth_create(const char *auth_file);
void auth_destroy(auth_ctx_t *auth);

auth_result_t auth_check_credentials(auth_ctx_t *auth,
                                   const char *user,
                                   const char *pass);

bool auth_parse_header(const char *header, char *user, char *pass);

#endif /* AUTH_H */