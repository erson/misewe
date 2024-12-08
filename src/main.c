#include <stdio.h>
#include <stdlib.h>
#include "auth.h"

int main(void) {
    /* Create auth context */
    auth_ctx_t *auth = auth_create("passwd.txt");
    if (!auth) {
        fprintf(stderr, "Failed to create auth context\n");
        return 1;
    }

    printf("Auth system initialized\n");

    /* Clean up */
    auth_destroy(auth);
    return 0;
}