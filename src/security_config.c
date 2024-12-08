#include "security_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Set default configuration values */
void security_config_set_defaults(security_config_t *config) {
    config->level = SECURITY_MEDIUM;

    /* Default limits */
    config->limits.max_requests_per_min = 60;
    config->limits.max_connections = 100;
    config->limits.max_request_size = 1024 * 1024;  // 1MB
    config->limits.timeout_seconds = 30;

    /* Default allowed extensions */
    strcpy(config->files.allowed_exts[0], ".html");
    strcpy(config->files.allowed_exts[1], ".css");
    strcpy(config->files.allowed_exts[2], ".js");
    strcpy(config->files.allowed_exts[3], ".txt");
    config->files.ext_count = 4;

    /* Default logging */
    config->log_requests = true;
    config->log_errors = true;
    strcpy(config->log_dir, "logs");
}

/* Create security configuration */
security_config_t *security_config_create(void) {
    security_config_t *config = calloc(1, sizeof(*config));
    if (config) {
        security_config_set_defaults(config);
    }
    return config;
}

/* Load configuration from file */
bool security_config_load(security_config_t *config, const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return false;

    char line[256];
    char *key, *value;

    while (fgets(line, sizeof(line), f)) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') continue;

        /* Remove newline */
        line[strcspn(line, "\n")] = 0;

        /* Split line into key=value */
        key = strtok(line, "=");
        value = strtok(NULL, "=");

        if (key && value) {
            /* Trim whitespace */
            while (*key && *key == ' ') key++;
            while (*value && *value == ' ') value++;

            /* Parse configuration values */
            if (strcmp(key, "security_level") == 0) {
                if (strcmp(value, "low") == 0)
                    config->level = SECURITY_LOW;
                else if (strcmp(value, "medium") == 0)
                    config->level = SECURITY_MEDIUM;
                else if (strcmp(value, "high") == 0)
                    config->level = SECURITY_HIGH;
                else if (strcmp(value, "paranoid") == 0)
                    config->level = SECURITY_PARANOID;
            }
            else if (strcmp(key, "max_requests_per_min") == 0) {
                config->limits.max_requests_per_min = atoi(value);
            }
            else if (strcmp(key, "max_connections") == 0) {
                config->limits.max_connections = atoi(value);
            }
            else if (strcmp(key, "max_request_size") == 0) {
                config->limits.max_request_size = atol(value);
            }
            else if (strcmp(key, "timeout_seconds") == 0) {
                config->limits.timeout_seconds = atoi(value);
            }
            else if (strcmp(key, "allowed_extension") == 0) {
                if (config->files.ext_count < 16) {
                    strncpy(config->files.allowed_exts[config->files.ext_count++],
                           value, 7);
                }
            }
            else if (strcmp(key, "log_requests") == 0) {
                config->log_requests = atoi(value);
            }
            else if (strcmp(key, "log_errors") == 0) {
                config->log_errors = atoi(value);
            }
            else if (strcmp(key, "log_dir") == 0) {
                strncpy(config->log_dir, value, sizeof(config->log_dir) - 1);
            }
        }
    }

    fclose(f);
    return true;
}

/* Clean up configuration */
void security_config_destroy(security_config_t *config) {
    free(config);
}