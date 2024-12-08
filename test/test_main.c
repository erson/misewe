#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../security.h"
#include "../http.h"

/* Test results tracking */
static int tests_run = 0;
static int tests_failed = 0;

/* Test macro */
#define TEST(name, test) \
    do { \
        printf("Running test: %s... ", name); \
        tests_run++; \
        if (test) { \
            printf("PASS\n"); \
        } else { \
            printf("FAIL\n"); \
            tests_failed++; \
        } \
    } while (0)

/* Test HTTP parsing */
static bool test_http_parser(void) {
    const char *request = 
        "GET /index.html HTTP/1.1\r\n"
        "Host: localhost:8000\r\n"
        "User-Agent: curl/7.68.0\r\n"
        "\r\n";

    http_request_t req;
    if (!http_parse_request(request, strlen(request), &req)) {
        return false;
    }

    return strcmp(req.path, "/index.html") == 0;
}

/* Test security checks */
static bool test_security_checks(void) {
    security_config_t config = {
        .level = SECURITY_HIGH,
        .limits = {
            .max_requests = 60,
            .window_seconds = 60
        }
    };

    security_ctx_t *ctx = security_create(&config);
    if (!ctx) return false;

    /* Test SQL injection detection */
    bool sql_blocked = !security_check_request(ctx,
        "127.0.0.1",
        "GET",
        "/page?id=1' OR '1'='1",
        "",
        NULL,
        0
    );

    /* Test XSS detection */
    bool xss_blocked = !security_check_request(ctx,
        "127.0.0.1",
        "GET",
        "/<script>alert(1)</script>",
        "",
        NULL,
        0
    );

    security_destroy(ctx);
    return sql_blocked && xss_blocked;
}

/* Test rate limiting */
static bool test_rate_limiting(void) {
    security_config_t config = {
        .level = SECURITY_HIGH,
        .limits = {
            .max_requests = 5,
            .window_seconds = 1
        }
    };

    security_ctx_t *ctx = security_create(&config);
    if (!ctx) return false;

    /* Send multiple requests */
    const char *ip = "127.0.0.1";
    bool limited = false;

    for (int i = 0; i < 10; i++) {
        if (!security_check_request(ctx, ip, "GET", "/", "", NULL, 0)) {
            limited = true;
            break;
        }
    }

    security_destroy(ctx);
    return limited;
}

/* Main test function */
int main(void) {
    printf("Running security tests...\n\n");

    TEST("HTTP Parser", test_http_parser());
    TEST("Security Checks", test_security_checks());
    TEST("Rate Limiting", test_rate_limiting());

    printf("\nTests complete: %d run, %d failed\n",
           tests_run, tests_failed);

    return tests_failed ? 1 : 0;
}