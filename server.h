#ifndef SERVER_H
#define SERVER_H

#include "config.h"
#include <stdatomic.h>
#include <pthread.h>

/* Forward declarations */
typedef struct server server_t;
typedef struct client client_t;

/* Client context */
struct client {
    int fd;                     /* Client socket */
    char addr[16];              /* Client IP address */
    time_t connected_at;        /* Connection timestamp */
    size_t request_count;       /* Number of requests */
    pthread_t thread;           /* Client thread */
    server_t *server;           /* Back reference to server */
    bool active;                /* Client active flag */
};

/* Server context */
struct server {
    int fd;                     /* Server socket */
    config_t *config;           /* Server configuration */
    atomic_bool running;        /* Server running flag */
    client_t *clients;          /* Client array */
    pthread_mutex_t lock;       /* Server lock */
    size_t client_count;        /* Current client count */
};

/* Function prototypes */
server_t *server_create(const config_t *config);
void server_destroy(server_t *server);
bool server_start(server_t *server);
void server_stop(server_t *server);

#endif /* SERVER_H */