#include "auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Auth context structure */
struct auth_ctx {
    char *passwd_file;
};

/* Create auth context */
auth_ctx_t *auth_create(const char *passwd_file) {
    auth_ctx_t *auth = calloc(1, sizeof(*auth));
    if (auth) {
        auth->passwd_file = strdup(passwd_file);
    }
    return auth;
}

/* Clean up auth context */
void auth_destroy(auth_ctx_t *auth) {
    if (auth) {
        free(auth->passwd_file);
        free(auth);
    }
}

/* Simple password verification (for demonstration) */
static bool verify_password(const char *stored_pass, const char *provided_pass) {
    return strcmp(stored_pass, provided_pass) == 0;
}

/* Check credentials */
bool auth_check_credentials(auth_ctx_t *auth, const char *user, const char *pass) {
    FILE *f = fopen(auth->passwd_file, "r");
    if (!f) return false;

    char line[256];
    bool found = false;

    while (fgets(line, sizeof(line), f)) {
        char file_user[128], file_pass[128];
        if (sscanf(line, "%127[^:]:%127s", file_user, file_pass) == 2) {
            if (strcmp(user, file_user) == 0) {
                found = verify_password(file_pass, pass);
                break;
            }
        }
    }

    fclose(f);
    return found;
}

/* Base64 decode (simplified) */
static void base64_decode(const char *input, char *output) {
    /* Note: This is a simplified version.
     * In production, use a proper base64 decoding library */
    strcpy(output, input);  /* Placeholder for demonstration */
}

/* Parse Authorization header */
bool auth_parse_header(const char *header, char *user, char *pass) {
    /* Basic auth format: "Basic base64(user:pass)" */
    if (strncmp(header, "Basic ", 6) != 0) return false;

    /* Skip "Basic " prefix */
    const char *encoded = header + 6;

    /* Decode base64 */
    char decoded[256];
    base64_decode(encoded, decoded);

    /* Split into user:pass */
    char *colon = strchr(decoded, ':');
    if (!colon) return false;

    *colon = '\0';
    strcpy(user, decoded);
    strcpy(pass, colon + 1);
    return true;
}