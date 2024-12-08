#ifndef AUTH_H
#define AUTH_H

#include <stdbool.h>

/* Define the auth context type */
typedef struct auth_ctx auth_ctx_t;

/* Function prototypes */
auth_ctx_t *auth_create(const char *passwd_file);
void auth_destroy(auth_ctx_t *auth);

/* Check credentials */
bool auth_check_credentials(auth_ctx_t *auth, const char *user, const char *pass);

/* Parse Authorization header */
bool auth_parse_header(const char *header, char *user, char *pass);

#endif /* AUTH_H */