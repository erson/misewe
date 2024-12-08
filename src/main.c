#include <stdio.h>
#include <stdlib.h>
#include "security_config.h"

int main(void) {
    security_config_t *config = security_config_create();
    if (!config) {
        fprintf(stderr, "Failed to create configuration\n");
        return 1;
    }

    printf("Server starting with security level: %d\n", config->level);
    security_config_destroy(config);
    return 0;
}