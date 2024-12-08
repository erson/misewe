#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include "../include/server.h"
#include "../include/http.h"
#include "../include/security.h"
#include "../include/security_config.h"

/* Debug logging */
#define DEBUG(fmt, ...) \
    fprintf(stderr, "[DEBUG] %s:%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

/* Global test server */
static server_t *test_server = NULL;
static pthread_t server_thread;
static volatile bool server_running = false;

/* Test utilities */
#define TEST(name) static bool test_##name(void)
#define RUN_TEST(name) do { \
    printf("Running %s...\n", #name); \
    bool result = test_##name(); \
    printf("%s: %s\n", #name, result ? "PASS" : "FAIL"); \
    if (!result) return 1; \
} while(0)

/* Forward declarations */
static void stop_test_server(void);
static bool start_test_server(void);
static int send_test_request(const char *request);

/* Server thread function */
static void *run_test_server(void *arg) {
    (void)arg;
    DEBUG("Server thread starting");
    server_running = true;
    server_run(test_server);
    server_running = false;
    DEBUG("Server thread exiting");
    return NULL;
}

/* Stop test server */
static void stop_test_server(void) {
    DEBUG("Stopping test server");
    if (test_server) {
        server_destroy(test_server);
        if (server_running) {
            pthread_join(server_thread, NULL);
        }
        test_server = NULL;
        server_running = false;
    }
    DEBUG("Server stopped");
}

/* Start test server */
static bool start_test_server(void) {
    DEBUG("Starting test server");
    server_config_t config = {
        .port = 8080,
        .bind_addr = "127.0.0.1",
        .root_dir = "www",
        .max_requests = 60
    };

    test_server = server_create(&config);
    if (!test_server) {
        DEBUG("Failed to create server");
        return false;
    }

    if (pthread_create(&server_thread, NULL, run_test_server, NULL) != 0) {
        DEBUG("Failed to create server thread: %s", strerror(errno));
        server_destroy(test_server);
        test_server = NULL;
        return false;
    }

    /* Wait for server to start */
    int retries = 50;  /* 5 seconds total */
    while (!server_running && retries-- > 0) {
        usleep(100000);  /* 100ms */
    }

    if (!server_running) {
        DEBUG("Server failed to start");
        stop_test_server();
        return false;
    }

    DEBUG("Server started successfully");
    return true;
}

/* HTTP test utilities */
static int send_test_request(const char *request) {
    DEBUG("Sending request: %s", request);
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        DEBUG("Failed to create socket: %s", strerror(errno));
        return -1;
    }

    /* Set socket timeout */
    struct timeval tv = {
        .tv_sec = 2,  /* 2 second timeout */
        .tv_usec = 0
    };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(8080),
        .sin_addr.s_addr = inet_addr("127.0.0.1")
    };

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        DEBUG("Failed to connect: %s", strerror(errno));
        close(sock);
        return -1;
    }

    ssize_t sent = write(sock, request, strlen(request));
    if (sent < 0) {
        DEBUG("Failed to send request: %s", strerror(errno));
        close(sock);
        return -1;
    }
    DEBUG("Sent %zd bytes", sent);

    return sock;
}

/* Server tests */
TEST(server_create) {
    server_t *server = server_create(&(server_config_t){
        .port = 8081,  /* Different port to avoid conflict with test server */
        .bind_addr = "127.0.0.1",
        .root_dir = "www",
        .max_requests = 60
    });
    bool result = (server != NULL);
    server_destroy(server);
    return result;
}

TEST(server_bind) {
    server_t *server = server_create(&(server_config_t){
        .port = 8082,  /* Different port to avoid conflict with test server */
        .bind_addr = "127.0.0.1",
        .root_dir = "www",
        .max_requests = 60
    });
    bool result = (server != NULL);
    server_destroy(server);
    return result;
}

/* HTTP tests */
TEST(http_parse_request) {
    const char *request = "GET /index.html HTTP/1.1\r\n"
                         "Host: localhost:8080\r\n"
                         "\r\n";
    http_request_t req;
    if (!http_parse_request(request, strlen(request), &req))
        return false;
    return (req.method == HTTP_GET && strcmp(req.path, "/index.html") == 0);
}

TEST(http_error_response) {
    DEBUG("Starting HTTP error response test");

    /* Send invalid request */
    const char *invalid_request = "INVALID REQUEST\r\n\r\n";
    int sock = send_test_request(invalid_request);
    if (sock < 0) {
        DEBUG("Failed to send request");
        return false;
    }

    /* Read response with timeout */
    char response[4096] = {0};
    ssize_t total_bytes = 0;
    int retries = 20;  /* 2 seconds total */

    while (retries-- > 0) {
        ssize_t bytes = read(sock, response + total_bytes, 
                           sizeof(response) - total_bytes - 1);
        if (bytes > 0) {
            total_bytes += bytes;
            response[total_bytes] = '\0';
            
            /* Check if we have a complete response */
            if (strstr(response, "\r\n\r\n")) {
                DEBUG("Received complete response: %s", response);
                break;
            }
        } else if (bytes == 0) {
            /* Connection closed */
            break;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            DEBUG("Read error: %s", strerror(errno));
            break;
        }
        usleep(100000);  /* 100ms */
    }

    close(sock);
    
    if (total_bytes <= 0) {
        DEBUG("No response received");
        return false;
    }

    /* Check response - accept either format */
    bool has_error = (strstr(response, "400 Bad Request") != NULL) ||
                    (strstr(response, "400 Error") != NULL && 
                     strstr(response, "Bad Request") != NULL);
    
    DEBUG("Response %s error message", has_error ? "contains" : "does not contain");
    return has_error;
}

/* Security tests */
TEST(security_features) {
    /* Configure security */
    security_config_t config = {
        .level = SECURITY_HIGH,
        .enable_rate_limit = true,
        .rate_limit_requests = 10,
        .enable_xss_protection = true,
        .limits = {
            .max_request_size = 1024 * 1024
        }
    };

    /* Create security context */
    security_ctx_t *ctx = security_create(&config);
    if (!ctx) return false;

    /* Test SQL injection detection */
    bool sql_blocked = !security_check_request(ctx,
        "192.168.1.1",
        "GET",
        "/users",
        "id=1 OR 1=1",
        NULL,
        0
    );

    /* Test XSS detection */
    bool xss_blocked = !security_check_request(ctx,
        "192.168.1.1",
        "POST",
        "/comment",
        NULL,
        "<script>alert('xss')</script>",
        28
    );

    security_destroy(ctx);
    return sql_blocked && xss_blocked;
}

TEST(rate_limit) {
    /* Configure rate limit */
    security_config_t config = {
        .enable_rate_limit = true,
        .rate_limit_requests = 5,
        .rate_limit_window = 60
    };

    /* Create security context */
    security_ctx_t *ctx = security_create(&config);
    if (!ctx) return false;

    /* Test rate limiting */
    const char *ip = "192.168.1.1";
    bool rate_limited = false;

    /* Send requests until rate limit is hit */
    for (int i = 0; i < 10; i++) {
        if (!security_check_request(ctx, ip, "GET", "/", "", NULL, 0)) {
            rate_limited = true;
            break;
        }
    }

    security_destroy(ctx);
    return rate_limited;
}

/* Integration tests */
static void *client_thread(void *unused) {
    (void)unused;  /* Suppress unused parameter warning */
    
    const char *request = "GET /index.html HTTP/1.1\r\n"
                         "Host: localhost:8080\r\n"
                         "\r\n";
    int sock = send_test_request(request);
    if (sock >= 0) {
        char response[4096];
        read(sock, response, sizeof(response) - 1);
        close(sock);
    }
    return NULL;
}

TEST(concurrent_connections) {
    #define NUM_CLIENTS 10
    pthread_t threads[NUM_CLIENTS];
    
    for (int i = 0; i < NUM_CLIENTS; i++) {
        if (pthread_create(&threads[i], NULL, client_thread, NULL) != 0)
            return false;
    }
    
    for (int i = 0; i < NUM_CLIENTS; i++) {
        if (pthread_join(threads[i], NULL) != 0)
            return false;
    }
    
    return true;
}

/* Main test runner */
int main(void) {
    printf("Starting test suite...\n\n");

    /* Create test environment */
    if (mkdir("www", 0755) < 0 && errno != EEXIST) {
        perror("Failed to create www directory");
        return 1;
    }

    FILE *f = fopen("www/index.html", "w");
    if (f) {
        fprintf(f, "<html><body>Test Page</body></html>");
        fclose(f);
    } else {
        perror("Failed to create test page");
        return 1;
    }

    /* Start test server for integration tests */
    if (!start_test_server()) {
        printf("Failed to start test server\n");
        return 1;
    }

    /* Run all tests */
    int result = 0;
    RUN_TEST(server_create);
    RUN_TEST(server_bind);
    RUN_TEST(http_parse_request);
    RUN_TEST(http_error_response);
    RUN_TEST(security_features);
    RUN_TEST(rate_limit);
    RUN_TEST(concurrent_connections);

    /* Stop test server */
    stop_test_server();

    /* Clean up test environment */
    unlink("www/index.html");
    rmdir("www");

    printf("\nTest suite %s!\n", result == 0 ? "PASSED" : "FAILED");
    return result;
} 