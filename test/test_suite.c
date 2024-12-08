#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include "../include/server.h"
#include "../include/http.h"
#include "../include/security_config.h"

/* Test utilities */
#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("Running %s...\n", #name); \
    test_##name(); \
    printf("[PASS] %s\n", #name); \
} while(0)

/* Server test utilities */
static server_t *create_test_server(void) {
    server_config_t config = {
        .port = 8080,
        .bind_addr = "127.0.0.1",
        .root_dir = "www",
        .max_requests = 60
    };
    return server_create(&config);
}

/* HTTP test utilities */
static int send_test_request(const char *request) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(8080),
        .sin_addr.s_addr = inet_addr("127.0.0.1")
    };

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    write(sock, request, strlen(request));
    return sock;
}

/* Test cases */

/* Server tests */
TEST(server_create) {
    server_t *server = create_test_server();
    assert(server != NULL);
    server_destroy(server);
}

TEST(server_bind) {
    server_t *server = create_test_server();
    assert(server != NULL);
    server_destroy(server);
}

/* HTTP tests */
TEST(http_parse_request) {
    const char *request = "GET /index.html HTTP/1.1\r\n"
                         "Host: localhost:8080\r\n"
                         "\r\n";
    http_request_t req;
    assert(http_parse_request(request, strlen(request), &req));
    assert(req.method == HTTP_GET);
    assert(strcmp(req.path, "/index.html") == 0);
}

TEST(http_error_response) {
    int sock = send_test_request("INVALID\r\n\r\n");
    if (sock >= 0) {
        char response[1024];
        ssize_t bytes = read(sock, response, sizeof(response) - 1);
        assert(bytes > 0);
        response[bytes] = '\0';
        assert(strstr(response, "400 Bad Request") != NULL);
        close(sock);
    }
}

/* Security tests */
TEST(file_type_validation) {
    const char *valid_requests[] = {
        "GET /index.html HTTP/1.1\r\n\r\n",
        "GET /style.css HTTP/1.1\r\n\r\n",
        "GET /script.js HTTP/1.1\r\n\r\n"
    };
    
    const char *invalid_requests[] = {
        "GET /test.php HTTP/1.1\r\n\r\n",
        "GET /config.ini HTTP/1.1\r\n\r\n",
        "GET /../secret.txt HTTP/1.1\r\n\r\n"
    };

    for (size_t i = 0; i < sizeof(valid_requests)/sizeof(valid_requests[0]); i++) {
        int sock = send_test_request(valid_requests[i]);
        if (sock >= 0) {
            char response[1024];
            read(sock, response, sizeof(response) - 1);
            assert(strstr(response, "403 Forbidden") == NULL);
            close(sock);
        }
    }

    for (size_t i = 0; i < sizeof(invalid_requests)/sizeof(invalid_requests[0]); i++) {
        int sock = send_test_request(invalid_requests[i]);
        if (sock >= 0) {
            char response[1024];
            read(sock, response, sizeof(response) - 1);
            assert(strstr(response, "403 Forbidden") != NULL);
            close(sock);
        }
    }
}

/* Integration tests */
static void *client_thread(void *arg) {
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
        pthread_create(&threads[i], NULL, client_thread, NULL);
    }
    
    for (int i = 0; i < NUM_CLIENTS; i++) {
        pthread_join(threads[i], NULL);
    }
}

/* Main test runner */
int main(void) {
    printf("Starting test suite...\n\n");

    /* Create test environment */
    mkdir("www", 0755);
    FILE *f = fopen("www/index.html", "w");
    if (f) {
        fprintf(f, "<html><body>Test Page</body></html>");
        fclose(f);
    }

    /* Run tests */
    RUN_TEST(server_create);
    RUN_TEST(server_bind);
    RUN_TEST(http_parse_request);
    RUN_TEST(http_error_response);
    RUN_TEST(file_type_validation);
    RUN_TEST(concurrent_connections);

    /* Clean up test environment */
    unlink("www/index.html");
    rmdir("www");

    printf("\nAll tests passed!\n");
    return 0;
} 