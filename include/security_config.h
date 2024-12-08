#ifndef SECURITY_CONFIG_H
#define SECURITY_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

/* Security levels */
typedef enum {
    SECURITY_LOW,       // Basic security
    SECURITY_MEDIUM,    // Standard security
    SECURITY_HIGH,      // Enhanced security
    SECURITY_PARANOID   // Maximum security
} security_level_t;

/* Security configuration */
typedef struct {
    security_level_t level;
    struct {
        uint32_t max_requests_per_min;  // Rate limiting
        uint32_t max_connections;       // Connection limiting
        size_t max_request_size;        // Request size limit
        int timeout_seconds;            // Connection timeout
    } limits;
    struct {
        char allowed_exts[16][8];     // Allowed file extensions
        size_t ext_count;
    } files;
    bool log_requests;                // Enable request logging
    bool log_errors;                  // Enable error logging
    char log_dir[256];               // Log directory path
} security_config_t;

/* Function prototypes */
security_config_t *security_config_create(void);
void security_config_destroy(security_config_t *config);
bool security_config_load(security_config_t *config, const char *filename);
void security_config_set_defaults(security_config_t *config);

#endif /* SECURITY_CONFIG_H */