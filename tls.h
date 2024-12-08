#ifndef TLS_H
#define TLS_H

#include <openssl/ssl.h>
#include <stdbool.h>

/* TLS configuration */
typedef struct {
    const char *cert_file;
    const char *key_file;
    const char *ca_file;
    const char *ciphers;
    int min_version;
    bool verify_peer;
    bool prefer_server_ciphers;
} tls_config_t;

/* TLS context */
typedef struct tls_ctx tls_ctx_t;

/* Function prototypes */
tls_ctx_t *tls_create(const tls_config_t *config);
void tls_destroy(tls_ctx_t *ctx);
SSL *tls_accept(tls_ctx_t *ctx, int client_fd);
void tls_close(SSL *ssl);

#endif /* TLS_H */