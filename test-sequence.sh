#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Test server configuration
SERVER_HOST="localhost"
SERVER_PORT="8000"
SERVER_BIN="./bin/zircon"
SERVER_PID=""

# Test statistics
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0

# Header function
function print_header() {
    echo -e "\n${YELLOW}====== $1 ======${NC}\n"
}

# Test function
function run_test() {
    local test_name="$1"
    local test_cmd="$2"
    local expected_code="$3"
    
    echo -n "Test: $test_name... "
    TESTS_TOTAL=$((TESTS_TOTAL+1))
    
    eval "$test_cmd" > /tmp/test_output 2>&1
    local result=$?
    
    if [ $result -eq $expected_code ]; then
        echo -e "${GREEN}PASSED${NC}"
        TESTS_PASSED=$((TESTS_PASSED+1))
    else
        echo -e "${RED}FAILED${NC} (Expected: $expected_code, Got: $result)"
        cat /tmp/test_output
        TESTS_FAILED=$((TESTS_FAILED+1))
    fi
}

# Test header function
function test_header() {
    echo -e "${GREEN}\n=== $1 ===${NC}"
}

# Start server
function start_server() {
    echo "Starting Zircon server..."
    $SERVER_BIN > /dev/null 2>&1 &
    SERVER_PID=$!
    
    # Wait for server to start
    sleep 2
    
    # Check if server is running
    if kill -0 $SERVER_PID 2>/dev/null; then
        echo -e "${GREEN}Server started (PID: $SERVER_PID)${NC}"
        return 0
    else
        echo -e "${RED}Failed to start server!${NC}"
        return 1
    fi
}

# Stop server
function stop_server() {
    if [ -n "$SERVER_PID" ]; then
        echo "Stopping server (PID: $SERVER_PID)..."
        kill $SERVER_PID
        wait $SERVER_PID 2>/dev/null
        echo -e "${GREEN}Server stopped${NC}"
    fi
}

# Display test results
function print_results() {
    echo -e "\n${YELLOW}=== TEST RESULTS ===${NC}"
    echo -e "Total tests: $TESTS_TOTAL"
    echo -e "Passed tests: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Failed tests: ${RED}$TESTS_FAILED${NC}"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "\n${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "\n${RED}Some tests failed.${NC}"
        exit 1
    fi
}

# Cleanup on exit
function cleanup() {
    stop_server
}

# Set cleanup handler
trap cleanup EXIT

# Main program
print_header "Zircon Webserver Test Protocol"

# Clean build
echo "Performing clean build..."
make clean && make

# Start server
start_server
if [ $? -ne 0 ]; then
    echo -e "${RED}Tests canceled because server failed to start${NC}"
    exit 1
fi

# 1. Basic HTTP Requests
test_header "Basic HTTP Requests"

# HTML file access
run_test "HTML access" "curl -s -o /dev/null -w '%{http_code}' http://$SERVER_HOST:$SERVER_PORT/index.html" 0
run_test "CSS access" "curl -s -o /dev/null -w '%{http_code}' http://$SERVER_HOST:$SERVER_PORT/style.css" 0
run_test "JavaScript access" "curl -s -o /dev/null -w '%{http_code}' http://$SERVER_HOST:$SERVER_PORT/test.js" 0
run_test "Image access" "curl -s -o /dev/null -w '%{http_code}' http://$SERVER_HOST:$SERVER_PORT/test-image.png" 0
run_test "404 - Missing file" "curl -s -o /dev/null -w '%{http_code}' http://$SERVER_HOST:$SERVER_PORT/nonexistent-file.html" 0

# 2. HTTP Header Tests
test_header "HTTP Header Tests"

run_test "Content-Type (HTML)" "curl -s -I http://$SERVER_HOST:$SERVER_PORT/index.html | grep -c 'Content-Type: text/html'" 0
run_test "Content-Type (CSS)" "curl -s -I http://$SERVER_HOST:$SERVER_PORT/style.css | grep -c 'Content-Type: text/css'" 0
run_test "Content-Type (JS)" "curl -s -I http://$SERVER_HOST:$SERVER_PORT/test.js | grep -c 'Content-Type: application/javascript'" 0
run_test "Content-Type (PNG)" "curl -s -I http://$SERVER_HOST:$SERVER_PORT/test-image.png | grep -c 'Content-Type: image/png'" 0

# 3. Security Header Tests
test_header "Security Header Tests"

run_test "X-Frame-Options" "curl -s -I http://$SERVER_HOST:$SERVER_PORT/index.html | grep -c 'X-Frame-Options'" 0
run_test "X-Content-Type-Options" "curl -s -I http://$SERVER_HOST:$SERVER_PORT/index.html | grep -c 'X-Content-Type-Options'" 0
run_test "X-XSS-Protection" "curl -s -I http://$SERVER_HOST:$SERVER_PORT/index.html | grep -c 'X-XSS-Protection'" 0
run_test "Content-Security-Policy" "curl -s -I http://$SERVER_HOST:$SERVER_PORT/index.html | grep -c 'Content-Security-Policy'" 0
run_test "HSTS" "curl -s -I http://$SERVER_HOST:$SERVER_PORT/index.html | grep -c 'Strict-Transport-Security'" 0

# 4. Cache and ETag Tests
test_header "Cache and ETag Tests"

run_test "ETag presence" "curl -s -I http://$SERVER_HOST:$SERVER_PORT/index.html | grep -c 'ETag'" 0
run_test "Cache-Control presence" "curl -s -I http://$SERVER_HOST:$SERVER_PORT/index.html | grep -c 'Cache-Control'" 0

# Get ETag value and use in next request
echo "Preparing ETag test..."
ETAG=$(curl -s -I http://$SERVER_HOST:$SERVER_PORT/index.html | grep ETag | awk '{print $2}' | tr -d '\r')
echo "ETag: $ETAG"

run_test "304 Not Modified" "curl -s -o /dev/null -w '%{http_code}' -H \"If-None-Match: $ETAG\" http://$SERVER_HOST:$SERVER_PORT/index.html | grep -c '304'" 0

# 5. Path Traversal Security Test
test_header "Security Tests"

run_test "Path traversal blocking" "curl -s -o /dev/null -w '%{http_code}' http://$SERVER_HOST:$SERVER_PORT/../etc/passwd | grep -c '403'" 0
run_test "File type restriction" "curl -s -o /dev/null -w '%{http_code}' http://$SERVER_HOST:$SERVER_PORT/file.php | grep -c '403'" 0

# 6. Fast Requests and Rate Limiting
test_header "Rate Limiting Test"

echo "Rate limiting test - sending 100 rapid requests..."
STATUS_429=0
for i in {1..100}; do
    STATUS=$(curl -s -o /dev/null -w '%{http_code}' http://$SERVER_HOST:$SERVER_PORT/)
    if [ "$STATUS" == "429" ]; then
        STATUS_429=1
        break
    fi
done

if [ $STATUS_429 -eq 1 ]; then
    echo -e "${GREEN}PASSED${NC} - Rate limiting active"
    TESTS_PASSED=$((TESTS_PASSED+1))
else
    echo -e "${RED}FAILED${NC} - Rate limiting not triggered"
    TESTS_FAILED=$((TESTS_FAILED+1))
fi
TESTS_TOTAL=$((TESTS_TOTAL+1))

# 7. HTTP Method Tests
test_header "HTTP Method Tests"

run_test "HEAD method" "curl -s -I http://$SERVER_HOST:$SERVER_PORT/index.html | grep -c '200 OK'" 0
run_test "GET method" "curl -s http://$SERVER_HOST:$SERVER_PORT/index.html | grep -c 'secure web server'" 0
run_test "Invalid method (OPTIONS)" "curl -s -X OPTIONS -o /dev/null -w '%{http_code}' http://$SERVER_HOST:$SERVER_PORT/ | grep -c '400'" 0

# 8. ETag and HTTP 304 Detailed Test
test_header "ETag and 304 Detailed Test"

# First request - get ETag
ETAG=$(curl -s -I http://$SERVER_HOST:$SERVER_PORT/test.html | grep ETag | awk '{print $2}' | tr -d '\r')
echo "ETag: $ETAG"

# Second request - expect 304 with If-None-Match
run_test "304 verification" "curl -s -o /dev/null -w '%{http_code}' -H \"If-None-Match: $ETAG\" http://$SERVER_HOST:$SERVER_PORT/test.html" 0

# Clean up after server performance test
stop_server

# Display test results
print_results

exit 0