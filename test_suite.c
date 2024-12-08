#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <curl/curl.h>
#include "server.h"

/* Test cases structure */
typedef struct {
    const char *name;
    const char *path;
    int expected_status;
} test_case_t;

/* Response data structure */
typedef struct {
    char *data;
    size_t size;
} response_t;

/* Write callback for curl */
static size_t write_callback(void *ptr, size_t size, size_t nmemb, response_t *resp) {
    size_t new_size = resp->size + size * nmemb;
    resp->data = realloc(resp->data, new_size + 1);
    if (!resp->data) return 0;
    
    memcpy(resp->data + resp->size, ptr, size * nmemb);
    resp->size = new_size;
    resp->data[resp->size] = '\0';
    
    return size * nmemb;
}

/* Run single test */
static int run_test(const test_case_t *test) {
    CURL *curl;
    CURLcode res;
    long status;
    response_t resp = {0};
    char url[256];
    
    printf("Running test: %s... ", test->name);
    
    snprintf(url, sizeof(url), "http://localhost:%d%s", SERVER_PORT, test->path);
    
    curl = curl_easy_init();
    if (!curl) {
        printf("FAIL (curl init)\n");
        return 1;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        printf("FAIL (%s)\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        free(resp.data);
        return 1;
    }
    
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);
    free(resp.data);
    
    if (status == test->expected_status) {
        printf("PASS\n");
        return 0;
    } else {
        printf("FAIL (expected %d, got %ld)\n", test->expected_status, status);
        return 1;
    }
}

/* Test cases */
static const test_case_t test_cases[] = {
    {"Valid HTML", "/index.html", 200},
    {"Directory Traversal", "/../etc/passwd", 403},
    {"Invalid Extension", "/test.php", 403},
    {"Not Found", "/nonexistent.html", 404},
    {"Invalid Path", "/<script>alert(1)</script>", 403},
    {NULL, NULL, 0}
};

/* Rate limit test */
static void test_rate_limit(void) {
    int success_count = 0;
    int fail_count = 0;
    CURL *curl;
    long status;
    char url[256];
    
    printf("Testing rate limit... ");
    
    snprintf(url, sizeof(url), "http://localhost:%d/index.html", SERVER_PORT);
    curl = curl_easy_init();
    
    /* Send requests rapidly */
    for (int i = 0; i < 20; i++) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        
        if (status == 200) success_count++;
        if (status == 429) fail_count++;
    }
    
    curl_easy_cleanup(curl);
    
    if (fail_count > 0) {
        printf("PASS (%d allowed, %d blocked)\n", success_count, fail_count);
    } else {
        printf("FAIL (rate limit not enforced)\n");
    }
}

int main(void) {
    int pid, status, failed = 0;
    const test_case_t *test;
    
    /* Start server in child process */
    pid = fork();
    if (pid == 0) {
        server_ctx_t *server = server_create(SERVER_PORT);
        if (!server) exit(1);
        server_run(server);
        server_destroy(server);
        exit(0);
    }
    
    /* Wait for server to start */
    sleep(1);
    
    /* Initialize curl */
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    /* Run test cases */
    for (test = test_cases; test->name; test++) {
        failed += run_test(test);
    }
    
    /* Run rate limit test */
    test_rate_limit();
    
    /* Cleanup */
    curl_global_cleanup();
    
    /* Stop server */
    kill(pid, SIGTERM);
    waitpid(pid, &status, 0);
    
    return failed ? 1 : 0;
}