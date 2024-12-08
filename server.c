#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

/* Static function declarations */
static void handle_signal(int sig);
static void *handle_client(void *arg);
static bool setup_socket(server_t *server);
static bool accept_client(server_t *server);
static void cleanup_client(client_t *client);

/* Global server reference for signal handling */
static server_t *g_server = NULL;

/* Signal handler */
static void handle_signal(int sig) {
    (void)sig;  /* Unused parameter */
    if (g_server) {
        atomic_store(&g_server->running, false);
    }
}

/* Create server context */
server_t *server_create(const config_t *config) {
    if (!config || !config_validate(config)) {
        return NULL;
    }

    server_t *server = calloc(1, sizeof(*server));
    if (!server) {
        return NULL;
    }

    /* Initialize server context */
    server->config = config_load(NULL);  /* Create copy of config */
    if (!server->config) {
        free(server);
        return NULL;
    }

    /* Allocate client array */
    server->clients = calloc(config->max_clients, sizeof(client_t));
    if (!server->clients) {
        config_free(server->config);
        free(server);
        return NULL;
    }

    /* Initialize mutex */
    if (pthread_mutex_init(&server->lock, NULL) != 0) {
        free(server->clients);
        config_free(server->config);
        free(server);
        return NULL;
    }

    atomic_init(&server->running, true);
    g_server = server;

    /* Set up signal handlers */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);  /* Ignore SIGPIPE */

    return server;
}

/* Set up server socket */
static bool setup_socket(server_t *server) {
    /* Create socket */
    server->fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (server->fd < 0) {
        perror("socket");
        return false;
    }

    /* Set socket options */
    int opt = 1;
    setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(server->fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    /* Set up address */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server->config->port);
    inet_pton(AF_INET, server->config->bind_addr, &addr.sin_addr);

    /* Bind socket */
    if (bind(server->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server->fd);
        return false;
    }

    /* Listen for connections */
    if (listen(server->fd, SOMAXCONN) < 0) {
        perror("listen");
        close(server->fd);
        return false;
    }

    return true;
}

/* Accept new client connection */
static bool accept_client(server_t *server) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    /* Accept connection */
    int client_fd = accept4(server->fd, (struct sockaddr*)&addr, 
                           &addr_len, SOCK_NONBLOCK);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("accept");
        }
        return false;
    }

    /* Lock server */
    pthread_mutex_lock(&server->lock);

    /* Find free client slot */
    client_t *client = NULL;
    for (size_t i = 0; i < server->config->max_clients; i++) {
        if (!server->clients[i].active) {
            client = &server->clients[i];
            break;
        }
    }

    /* Check if server is full */
    if (!client) {
        pthread_mutex_unlock(&server->lock);
        close(client_fd);
        return false;
    }

    /* Initialize client context */
    memset(client, 0, sizeof(*client));
    client->fd = client_fd;
    client->server = server;
    client->active = true;
    client->connected_at = time(NULL);
    inet_ntop(AF_INET, &addr.sin_addr, client->addr, sizeof(client->addr));

    /* Create client thread */
    if (pthread_create(&client->thread, NULL, handle_client, client) != 0) {
        client->active = false;
        pthread_mutex_unlock(&server->lock);
        close(client_fd);
        return false;
    }

    server->client_count++;
    pthread_mutex_unlock(&server->lock);
    return true;
}

/* Handle client connection */
static void *handle_client(void *arg) {
    client_t *client = arg;
    server_t *server = client->server;

    /* Set socket timeout */
    struct timeval tv = {
        .tv_sec = server->config->timeout_sec,
        .tv_usec = 0
    };
    setsockopt(client->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Handle client requests */
    while (atomic_load(&server->running)) {
        /* TODO: Implement request handling */
        break;  /* For now, just handle one request */
    }

    cleanup_client(client);
    return NULL;
}

/* Clean up client resources */
static void cleanup_client(client_t *client) {
    if (!client->active) return;

    close(client->fd);
    client->active = false;

    pthread_mutex_lock(&client->server->lock);
    client->server->client_count--;
    pthread_mutex_unlock(&client->server->lock);
}

/* Start server */
bool server_start(server_t *server) {
    if (!server) return false;

    /* Set up server socket */
    if (!setup_socket(server)) {
        return false;
    }

    printf("Server listening on %s:%d\n", 
           server->config->bind_addr, 
           server->config->port);

    /* Main server loop */
    while (atomic_load(&server->running)) {
        accept_client(server);
        usleep(1000);  /* Small sleep to prevent busy loop */
    }

    return true;
}

/* Stop server */
void server_stop(server_t *server) {
    if (!server) return;
    atomic_store(&server->running, false);

    /* Wait for clients to finish */
    for (size_t i = 0; i < server->config->max_clients; i++) {
        if (server->clients[i].active) {
            pthread_join(server->clients[i].thread, NULL);
        }
    }
}

/* Clean up server resources */
void server_destroy(server_t *server) {
    if (!server) return;

    server_stop(server);
    close(server->fd);

    pthread_mutex_destroy(&server->lock);
    free(server->clients);
    config_free(server->config);
    free(server);

    g_server = NULL;
}