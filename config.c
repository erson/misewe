#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "config.h"

/* Trim whitespace from string */
static char *trim(char *str) {
    char *end;
    
    while (isspace(*str)) str++;
    if (*str == 0) return str;
    
    end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) end--;
    *(end + 1) = '\0';
    
    return str;
}

/* Parse config line */
static void parse_line(server_config_t *config, char *line) {
    char *key, *value;
    
    key = trim(strtok(line, "="));
    if (!key || *key == '#') return;
    
    value = trim(strtok(NULL, "\n"));
    if (!value) return;
    
    if (strcmp(key, "port") == 0) {
        config->port = (uint16_t)atoi(value);
    }
    else if (strcmp(key, "bind_addr") == 0) {
        strncpy(config->bind_addr, value, sizeof(config->bind_addr) - 1);
    }
    else if (strcmp(key, "max_request_size") == 0) {
        config->max_request_size = (size_t)atol(value);
    }
    else if (strcmp(key, "max_clients") == 0) {
        config->max_clients = (size_t)atol(value);
    }
    else if (strcmp(key, "requests_per_second") == 0) {
        config->requests_per_second = atoi(value);
    }
    else if (strcmp(key, "timeout_seconds") == 0) {
        config->timeout_seconds = atoi(value);
    }
    else if (strcmp(key, "log_file") == 0) {
        strncpy(config->log_file, value, sizeof(config->log_file) - 1);
    }
    else if (strcmp(key, "ssl_enabled") == 0) {
        config->ssl.enabled = atoi(value);
    }
    else if (strcmp(key, "ssl_cert_file") == 0) {
        strncpy(config->ssl.cert_file, value, sizeof(config->ssl.cert_file) - 1);
    }
    else if (strcmp(key, "ssl_key_file") == 0) {
        strncpy(config->ssl.key_file, value, sizeof(config->ssl.key_file) - 1);
    }
    else if (strcmp(key, "allowed_extension") == 0) {
        if (config->security.count < 16) {
            strncpy(config->security.allowed_extensions[config->security.count++],
                   value, 15);
        }
    }
}

server_config_t *config_load(const char *filename) {
    FILE *fp;
    char line[1024];
    server_config_t *config;
    
    config = calloc(1, sizeof(*config));
    if (!config) return NULL;
    
    /* Set defaults */
    config->port = 8000;
    strcpy(config->bind_addr, "127.0.0.1");
    config->max_request_size = 4096;
    config->max_clients = 1000;
    config->requests_per_second = 10;
    config->timeout_seconds = 30;
    strcpy(config->log_file, "server.log");
    config->ssl.enabled = 0;
    
    /* Default allowed extensions */
    strcpy(config->security.allowed_extensions[0], ".html");
    strcpy(config->security.allowed_extensions[1], ".txt");
    strcpy(config->security.allowed_extensions[2], ".css");
    strcpy(config->security.allowed_extensions[3], ".js");
    config->security.count = 4;
    
    /* Read config file */
    fp = fopen(filename, "r");
    if (!fp) return config;  /* Use defaults if file not found */
    
    while (fgets(line, sizeof(line), fp)) {
        parse_line(config, line);
    }
    
    fclose(fp);
    return config;
}

void config_free(server_config_t *config) {
    free(config);
}