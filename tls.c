#include "tls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/conf.h>

struct tls_ctx {
    SSL_CTX *ssl_ctx;
    tls_config_t config;
};

/* Initialize OpenSSL */
static void init_openssl(void) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

/* Clean up OpenSSL */
static void cleanup_openssl(void) {
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

/* Create TLS context */
tls_ctx_t *tls_create(const tls_config_t *config) {
    static bool initialized = false;
    if (!initialized) {
        init_openssl();
        initialized = true;
    }

    tls_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    /* Copy configuration */
    ctx->config = *config;

    /* Create SSL context */
    const SSL_METHOD *method = TLS_server_method();
    ctx->ssl_ctx = SSL_CTX_new(method);
    if (!ctx->ssl_ctx) {
        free(ctx);
        return NULL;
    }

    /* Set minimum TLS version */
    SSL_CTX_set_min_proto_version(ctx->ssl_ctx, config->min_version);

    /* Set cipher preferences */
    if (config->ciphers) {
        SSL_CTX_set_cipher_list(ctx->ssl_ctx, config->ciphers);
    }
    if (config->prefer_server_ciphers) {
        SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }

    /* Load certificates */
    if (SSL_CTX_use_certificate_file(ctx->ssl_ctx, config->cert_file,
                                   SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx->ssl_ctx);
        free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, config->key_file,
                                   SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx->ssl_ctx);
        free(ctx);
        return NULL;
    }

    /* Set up client verification */
    if (config->verify_peer) {
        SSL_CTX_set_verify(ctx->ssl_ctx,
                          SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                          NULL);
        if (config->ca_file) {
            SSL_CTX_load_verify_locations(ctx->ssl_ctx, config->ca_file, NULL);
        }
    }

    /* Set security options */
    SSL_CTX_set_options(ctx->ssl_ctx,
        SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |  /* Disable SSL 2.0 and 3.0 */
        SSL_OP_NO_COMPRESSION |               /* Disable compression */
        SSL_OP_NO_TICKET |                    /* Disable session tickets */
        SSL_OP_NO_RENEGOTIATION              /* Disable renegotiation */
    );

    return ctx;
}

/* Accept TLS connection */
SSL *tls_accept(tls_ctx_t *ctx, int client_fd) {
    SSL *ssl = SSL_new(ctx->ssl_ctx);
    if (!ssl) return NULL;

    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }

    return ssl;
}

/* Close TLS connection */
void tls_close(SSL *ssl) {
    if (!ssl) return;
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

/* Clean up TLS context */
void tls_destroy(tls_ctx_t *ctx) {
    if (!ctx) return;
    SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);
    cleanup_openssl();
}