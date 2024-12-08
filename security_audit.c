#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "security_audit.h"
#include "logger.h"

#define AUDIT_HMAC_KEY "change_this_in_production"
#define MAX_AUDIT_FILE_SIZE (100 * 1024 * 1024)  // 100MB

struct audit_ctx {
    FILE *audit_file;
    char filename[256];
    uint32_t sequence;
    unsigned char hmac_key[64];
    size_t current_size;
    pthread_mutex_t lock;
};

/* Initialize HMAC key from environment or secure storage */
static void init_hmac_key(audit_ctx_t *ctx) {
    const char *key = getenv("AUDIT_HMAC_KEY");
    if (key) {
        HMAC(EVP_sha256(), key, strlen(key),
             (unsigned char *)AUDIT_HMAC_KEY, strlen(AUDIT_HMAC_KEY),
             ctx->hmac_key, NULL);
    } else {
        /* Fallback to default key (should be changed in production) */
        memcpy(ctx->hmac_key, AUDIT_HMAC_KEY, strlen(AUDIT_HMAC_KEY));
    }
}

/* Calculate HMAC for audit record */
static void calculate_record_hmac(const audit_record_t *record,
                                const unsigned char *key,
                                unsigned char *hmac) {
    HMAC_CTX *hmac_ctx = HMAC_CTX_new();
    HMAC_Init_ex(hmac_ctx, key, 64, EVP_sha256(), NULL);
    HMAC_Update(hmac_ctx, (unsigned char *)record,
                sizeof(audit_record_t) - SHA256_DIGEST_LENGTH);
    HMAC_Final(hmac_ctx, hmac, NULL);
    HMAC_CTX_free(hmac_ctx);
}

/* Initialize audit system */
audit_ctx_t *audit_init(const char *audit_file) {
    audit_ctx_t *ctx = calloc(1, sizeof(audit_ctx_t));
    if (!ctx) return NULL;

    strncpy(ctx->filename, audit_file, sizeof(ctx->filename) - 1);
    ctx->audit_file = fopen(audit_file, "a+");
    if (!ctx->audit_file) {
        free(ctx);
        return NULL;
    }

    /* Set secure permissions */
    fchmod(fileno(ctx->audit_file), S_IRUSR | S_IWUSR);

    /* Initialize mutex */
    pthread_mutex_init(&ctx->lock, NULL);

    /* Set up HMAC key */
    init_hmac_key(ctx);

    /* Get current file size */
    fseek(ctx->audit_file, 0, SEEK_END);
    ctx->current_size = ftell(ctx->audit_file);

    /* Read last sequence number if file exists */
    if (ctx->current_size > 0) {
        audit_record_t last_record;
        fseek(ctx->audit_file, -sizeof(audit_record_t), SEEK_END);
        if (fread(&last_record, sizeof(last_record), 1, ctx->audit_file) == 1) {
            ctx->sequence = last_record.sequence + 1;
        }
    }

    return ctx;
}

/* Log audit event with integrity protection */
void audit_log_event(audit_ctx_t *ctx, audit_event_t event,
                     const char *client_ip, const char *resource,
                     const char *details, int severity) {
    if (!ctx || !ctx->audit_file) return;

    pthread_mutex_lock(&ctx->lock);

    /* Check if log rotation needed */
    if (ctx->current_size >= MAX_AUDIT_FILE_SIZE) {
        audit_rotate_logs(ctx);
    }

    /* Prepare audit record */
    audit_record_t record = {
        .timestamp = time(NULL),
        .event_type = event,
        .sequence = ctx->sequence++,
        .severity = severity
    };

    strncpy(record.client_ip, client_ip ? client_ip : "unknown",
            sizeof(record.client_ip) - 1);
    strncpy(record.resource, resource ? resource : "none",
            sizeof(record.resource) - 1);
    strncpy(record.details, details ? details : "",
            sizeof(record.details) - 1);

    /* Calculate HMAC */
    unsigned char hmac[SHA256_DIGEST_LENGTH];
    calculate_record_hmac(&record, ctx->hmac_key, hmac);

    /* Write record and HMAC */
    if (fwrite(&record, sizeof(record), 1, ctx->audit_file) == 1 &&
        fwrite(hmac, SHA256_DIGEST_LENGTH, 1, ctx->audit_file) == 1) {
        ctx->current_size += sizeof(record) + SHA256_DIGEST_LENGTH;
        fflush(ctx->audit_file);
        /* Ensure data is written to disk */
        fdatasync(fileno(ctx->audit_file));
    } else {
        ERROR_LOG("Failed to write audit record");
    }

    pthread_mutex_unlock(&ctx->lock);
}

/* Rotate audit logs */
void audit_rotate_logs(audit_ctx_t *ctx) {
    char new_name[300];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);

    /* Generate new filename with timestamp */
    strftime(new_name, sizeof(new_name), "%Y%m%d_%H%M%S_", tm_info);
    strncat(new_name, ctx->filename,
            sizeof(new_name) - strlen(new_name) - 1);

    /* Close current file */
    fclose(ctx->audit_file);

    /* Rename current file */
    rename(ctx->filename, new_name);

    /* Open new file */
    ctx->audit_file = fopen(ctx->filename, "a+");
    if (ctx->audit_file) {
        fchmod(fileno(ctx->audit_file), S_IRUSR | S_IWUSR);
        ctx->current_size = 0;
    }
}

/* Verify audit log integrity */
int audit_verify_integrity(audit_ctx_t *ctx) {
    if (!ctx || !ctx->audit_file) return 0;

    pthread_mutex_lock(&ctx->lock);

    /* Rewind file */
    fseek(ctx->audit_file, 0, SEEK_SET);

    audit_record_t record;
    unsigned char stored_hmac[SHA256_DIGEST_LENGTH];
    unsigned char calculated_hmac[SHA256_DIGEST_LENGTH];
    int valid = 1;
    uint32_t last_sequence = 0;

    while (fread(&record, sizeof(record), 1, ctx->audit_file) == 1 &&
           fread(stored_hmac, SHA256_DIGEST_LENGTH, 1, ctx->audit_file) == 1) {
        
        /* Verify sequence */
        if (record.sequence != last_sequence + 1) {
            ERROR_LOG("Audit log sequence mismatch: expected %u, got %u",
                     last_sequence + 1, record.sequence);
            valid = 0;
            break;
        }
        last_sequence = record.sequence;

        /* Verify HMAC */
        calculate_record_hmac(&record, ctx->hmac_key, calculated_hmac);
        if (memcmp(stored_hmac, calculated_hmac, SHA256_DIGEST_LENGTH) != 0) {
            ERROR_LOG("Audit log integrity check failed at sequence %u",
                     record.sequence);
            valid = 0;
            break;
        }
    }

    pthread_mutex_unlock(&ctx->lock);
    return valid;
}

/* Clean up audit system */
void audit_cleanup(audit_ctx_t *ctx) {
    if (!ctx) return;

    pthread_mutex_lock(&ctx->lock);
    
    if (ctx->audit_file) {
        fclose(ctx->audit_file);
    }
    
    /* Securely wipe HMAC key */
    secure_memzero(ctx->hmac_key, sizeof(ctx->hmac_key));
    
    pthread_mutex_unlock(&ctx->lock);
    pthread_mutex_destroy(&ctx->lock);
    
    free(ctx);
}