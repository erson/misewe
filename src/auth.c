```c
#include "auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>

struct auth_ctx {
    char *passwd_file;
};

auth_ctx_t *auth_create(const char *passwd_file) {
    auth_ctx_t *auth = calloc(1, sizeof(*auth));
    if (auth) {
        auth->passwd_file = strdup(passwd_file);
    }
    return auth;
}

void auth_destroy(auth_ctx_t *auth) {
    if (auth) {
        free(auth->passwd_file);
        free(auth);
    }
}

bool auth_check_credentials(auth_ctx_t *auth, const char *user, const char *pass) {
    FILE *f = fopen(auth->passwd_file, "r");
    if (!f) return false;

    char line[256];
    bool found = false;

    while (fgets(line, sizeof(line), f)) {
        char file_user[128], file_pass[128];
        if (sscanf(line, "%127[^:]:%127s", file_user, file_pass) == 2) {
            if (strcmp(user, file_user) == 0) {
                /* Compare hashed passwords */
                char *hashed = crypt(pass, file_pass);
                found = (strcmp(hashed, file_pass) == 0);
                break;
            }
        }
    }

    fclose(f);
    return found;
}

bool auth_parse_header(const char *header, char *user, char *pass) {
    /* Basic auth format: "Basic base64(user:pass)" */
    if (strncmp(header, "Basic ", 6) != 0) return false;

    /* Decode base64 */
    char decoded[256];
    /* TODO: Implement base64 decode */
    
    /* Split into user:pass */
    char *colon = strchr(decoded, ':');
    if (!colon) return false;

    *colon = '\0';
    strcpy(user, decoded);
    strcpy(pass, colon + 1);
    return true;
}
```