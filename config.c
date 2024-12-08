#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Create default configuration */
static void config_set_defaults(server_config_t *config) {
    /* Network defaults */
    config->port = 8000;
    strcpy(config->bind_addr, "127.0.0.1");
    config->backlog = 10;
    
    /* Security defaults */
    config->limits.max_requests_per_min = 60;
    config->limits.max_connections = 1000;
    config->limits.max_request_size = 1024 * 1024;  /* 1MB */
    config->limits.max_header_size = 8192;
    config->limits.timeout_seconds = 30;
    
    /* File defaults */
    strcpy(config->root_dir, "./www");
    
    /* Default allowed extensions */
    strcpy(config->files.allowed_exts[0], ".html");
    strcpy(config->files.allowed_exts[1], ".css");
    strcpy(config->files.allowed_exts[2], ".js");
    strcpy(config->files.allowed_exts[3], ".txt");
    strcpy(config->files.allowed_exts[4], ".ico");
    config->files.ext_count = 5;
    
    /* Logging defaults */
    strcpy(config->access_log, "access.log");
    strcpy(config->error_log, "error.log");
    config->log_requests = true;
    config->log_errors = true;
}

/* Load configuration from file */
server_config_t *config_load(const char *filename) {
    server_config_t *config = calloc(1, sizeof(*config));
    if (!config) return NULL;
    
    /* Set defaults first */
    config_set_defaults(config);
    
    /* Read configuration file if provided */
    if (filename) {
        FILE *f = fopen(filename, "r");
        if (f) {
            char line[512];
            while (fgets(line, sizeof(line), f)) {
                /* Remove newline */
                char *nl = strchr(line, '\n');
                if (nl) *nl = '\0';
                
                /* Skip comments and empty lines */
                if (line[0] == '#' || line[0] == '\0') continue;
                
                /* Parse key=value pairs */
                char *sep = strchr(line, '=');
                if (sep) {
                    *sep = '\0';
                    char *key = line;
                    char *value = sep + 1;
                    
                    /* Trim whitespace */
                    while (*key && isspace(*key)) key++;
                    while (*value && isspace(*value)) value++;
                    
                    /* Set configuration value */
                    if (strcmp(key, "port") == 0) {
                        config->port = atoi(value);
                    }
                    else if (strcmp(key, "bind_addr") == 0) {
                        strncpy(config->bind_addr, value, sizeof(config->bind_addr) - 1);
                    }
                    else if (strcmp(key, "root_dir") == 0) {
                        strncpy(config->root_dir, value, sizeof(config->root_dir) - 1);
                    }
                    /* Add more configuration options here */
                }
            }
            fclose(f);
        }
    }
    
    return config;
}

/* Validate configuration */
bool config_validate(const server_config_t *config) {
    if (!config) return false;
    
    /* Check port range */
    if (config->port < 1 || config->port > 65535) return false;
    
    /* Check limits */
    if (config->limits.max_request_size < 1024 ||
        config->limits.max_request_size > 1024 * 1024 * 10) return false;
        
    if (config->limits.timeout_seconds < 1 ||
        config->limits.timeout_seconds > 300) return false;
        
    /* Check root directory */
    if (access(config->root_dir, R_OK) != 0) return false;
    
    return true;
}

/* Free configuration */
void config_free(server_config_t *config) {
    free(config);
}