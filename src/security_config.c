#include "security_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Set default configuration values */
void security_config_set_defaults(security_config_t *config) {
    if (!config) return;

    /* Basic security settings */
    config->level = SECURITY_MEDIUM;

    /* Rate limiting and connection settings */
    config->limits.max_requests_per_min = 60;
    config->limits.max_connections = 100;
    config->limits.max_request_size = 1024 * 1024;  /* 1MB */
    config->limits.timeout_seconds = 30;

    /* Allowed file extensions */
    strcpy(config->files.allowed_exts[0], ".html");
    strcpy(config->files.allowed_exts[1], ".css");
    strcpy(config->files.allowed_exts[2], ".js");
    strcpy(config->files.allowed_exts[3], ".txt");
    config->files.ext_count = 4;

    /* Logging configuration */
    config->log_requests = true;
    config->log_errors = true;
    strcpy(config->log_dir, "logs");

    /* Web security features */
    config->enable_https = true;
    config->require_auth = true;
    config->enable_rate_limit = true;
    config->rate_limit_requests = 60;
    config->rate_limit_window = 60;
    config->enable_xss_protection = true;
    config->enable_csrf_protection = true;
    strncpy(config->csrf_token_secret, "change_this_in_production", sizeof(config->csrf_token_secret) - 1);
    config->enable_cors = false;
    strncpy(config->allowed_origins, "*", sizeof(config->allowed_origins) - 1);
    config->enable_hsts = true;
    config->hsts_max_age = 31536000; /* 1 year */
    config->enable_csp = true;
    strncpy(config->csp_policy, 
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'",
            sizeof(config->csp_policy) - 1);
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
    if (!config || !filename) return false;

    FILE *f = fopen(filename, "r");
    if (!f) return false;

    /* Set defaults first */
    security_config_set_defaults(config);

    char line[1024];
    char key[64], value[960];

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%63[^=]=%959s", key, value) == 2) {
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
            else if (strcmp(key, "max_requests_per_min") == 0)
                config->limits.max_requests_per_min = atoi(value);
            else if (strcmp(key, "max_connections") == 0)
                config->limits.max_connections = atoi(value);
            else if (strcmp(key, "max_request_size") == 0)
                config->limits.max_request_size = atol(value);
            else if (strcmp(key, "timeout_seconds") == 0)
                config->limits.timeout_seconds = atoi(value);
            else if (strcmp(key, "log_requests") == 0)
                config->log_requests = atoi(value);
            else if (strcmp(key, "log_errors") == 0)
                config->log_errors = atoi(value);
            else if (strcmp(key, "log_dir") == 0)
                strncpy(config->log_dir, value, sizeof(config->log_dir) - 1);
            else if (strcmp(key, "enable_https") == 0)
                config->enable_https = atoi(value);
            else if (strcmp(key, "require_auth") == 0)
                config->require_auth = atoi(value);
            else if (strcmp(key, "enable_rate_limit") == 0)
                config->enable_rate_limit = atoi(value);
            else if (strcmp(key, "rate_limit_requests") == 0)
                config->rate_limit_requests = atoi(value);
            else if (strcmp(key, "rate_limit_window") == 0)
                config->rate_limit_window = atoi(value);
            else if (strcmp(key, "enable_xss_protection") == 0)
                config->enable_xss_protection = atoi(value);
            else if (strcmp(key, "enable_csrf_protection") == 0)
                config->enable_csrf_protection = atoi(value);
            else if (strcmp(key, "csrf_token_secret") == 0)
                strncpy(config->csrf_token_secret, value, sizeof(config->csrf_token_secret) - 1);
            else if (strcmp(key, "enable_cors") == 0)
                config->enable_cors = atoi(value);
            else if (strcmp(key, "allowed_origins") == 0)
                strncpy(config->allowed_origins, value, sizeof(config->allowed_origins) - 1);
            else if (strcmp(key, "enable_hsts") == 0)
                config->enable_hsts = atoi(value);
            else if (strcmp(key, "hsts_max_age") == 0)
                config->hsts_max_age = atoi(value);
            else if (strcmp(key, "enable_csp") == 0)
                config->enable_csp = atoi(value);
            else if (strcmp(key, "csp_policy") == 0)
                strncpy(config->csp_policy, value, sizeof(config->csp_policy) - 1);
        }
    }

    fclose(f);
    return true;
}

/* Save configuration to file */
bool security_config_save(const security_config_t *config, const char *filename) {
    if (!config || !filename) return false;

    FILE *f = fopen(filename, "w");
    if (!f) return false;

    /* Write basic security settings */
    fprintf(f, "security_level=%s\n", 
            config->level == SECURITY_LOW ? "low" :
            config->level == SECURITY_MEDIUM ? "medium" :
            config->level == SECURITY_HIGH ? "high" : "paranoid");

    /* Write limits */
    fprintf(f, "max_requests_per_min=%u\n", config->limits.max_requests_per_min);
    fprintf(f, "max_connections=%u\n", config->limits.max_connections);
    fprintf(f, "max_request_size=%zu\n", config->limits.max_request_size);
    fprintf(f, "timeout_seconds=%u\n", config->limits.timeout_seconds);

    /* Write logging settings */
    fprintf(f, "log_requests=%d\n", config->log_requests);
    fprintf(f, "log_errors=%d\n", config->log_errors);
    fprintf(f, "log_dir=%s\n", config->log_dir);

    /* Write web security features */
    fprintf(f, "enable_https=%d\n", config->enable_https);
    fprintf(f, "require_auth=%d\n", config->require_auth);
    fprintf(f, "enable_rate_limit=%d\n", config->enable_rate_limit);
    fprintf(f, "rate_limit_requests=%u\n", config->rate_limit_requests);
    fprintf(f, "rate_limit_window=%u\n", config->rate_limit_window);
    fprintf(f, "enable_xss_protection=%d\n", config->enable_xss_protection);
    fprintf(f, "enable_csrf_protection=%d\n", config->enable_csrf_protection);
    fprintf(f, "csrf_token_secret=%s\n", config->csrf_token_secret);
    fprintf(f, "enable_cors=%d\n", config->enable_cors);
    fprintf(f, "allowed_origins=%s\n", config->allowed_origins);
    fprintf(f, "enable_hsts=%d\n", config->enable_hsts);
    fprintf(f, "hsts_max_age=%u\n", config->hsts_max_age);
    fprintf(f, "enable_csp=%d\n", config->enable_csp);
    fprintf(f, "csp_policy=%s\n", config->csp_policy);

    fclose(f);
    return true;
}

/* Clean up configuration */
void security_config_destroy(security_config_t *config) {
    free(config);
}