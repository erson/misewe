#ifndef SECURITY_VALIDATOR_H
#define SECURITY_VALIDATOR_H

#include <stdint.h>
#include <stdbool.h>

/* Validation modes */
typedef enum {
    VALIDATE_STRICT,      /* Strict RFC compliance */
    VALIDATE_NORMAL,      /* Standard security checks */
    VALIDATE_PERMISSIVE   /* Basic security only */
} validation_mode_t;

/* Protocol types */
typedef enum {
    PROTO_HTTP,
    PROTO_WEBSOCKET,
    PROTO_TLS
} protocol_type_t;

/* Validation context */
typedef struct validator validator_t;

/* Configuration */
typedef struct {
    validation_mode_t mode;
    protocol_type_t protocol;
    bool decode_payload;      /* URL/Base64/etc. decoding */
    bool normalize_path;      /* Path normalization */
    bool validate_encoding;   /* Character encoding validation */
    size_t max_depth;        /* Maximum recursion depth */
} validator_config_t;

/* Validation result */
typedef struct {
    bool valid;
    char error[256];
    int error_offset;
    uint32_t flags;
} validation_result_t;

/* Function prototypes */
validator_t *validator_create(const validator_config_t *config);
void validator_destroy(validator_t *v);

bool validator_check_request(
    validator_t *v,
    const char *data,
    size_t length,
    validation_result_t *result);

#endif /* SECURITY_VALIDATOR_H */