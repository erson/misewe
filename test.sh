#!/bin/sh

# Use POSIX-compliant shell syntax for better portability
# Colors using tput for better portability across terminals
if [ -t 1 ]; then
    GREEN=$(tput setaf 2)
    RED=$(tput setaf 1)
    YELLOW=$(tput setaf 3)
    NC=$(tput sgr0)
else
    GREEN=""
    RED=""
    YELLOW=""
    NC=""
fi

# Test result counters
PASSED=0
FAILED=0
TOTAL=0

# Server configuration - can be overridden by environment variables
: "${SERVER_HOST:=localhost}"
: "${SERVER_PORT:=8000}"
: "${SERVER_BINARY:=misewe}"

print_header() {
    printf "\n%s=== %s ===%s\n\n" "${YELLOW}" "$1" "${NC}"
}

run_test() {
    name="$1"
    cmd="$2"
    expected="$3"
    
    printf "Testing %s... " "$name"
    TOTAL=$((TOTAL + 1))
    
    eval "$cmd" > /dev/null 2>&1
    result=$?
    
    if [ $result -eq "$expected" ]; then
        printf "%sPASSED%s\n" "${GREEN}" "${NC}"
        PASSED=$((PASSED + 1))
    else
        printf "%sFAILED%s\n" "${RED}" "${NC}"
        FAILED=$((FAILED + 1))
    fi
}

# Check if server is running using a portable method
check_server() {
    if ! curl -s "http://${SERVER_HOST}:${SERVER_PORT}" >/dev/null 2>&1; then
        printf "%sError: Server is not running at http://%s:%s%s\n" "${RED}" "${SERVER_HOST}" "${SERVER_PORT}" "${NC}"
        printf "Please start the server first:\n"
        printf "  ./bin/%s\n" "${SERVER_BINARY}"
        exit 1
    fi
}

check_server

print_header "Basic Functionality Tests"

# Basic access tests
run_test "basic HTML access" \
    "curl -s http://${SERVER_HOST}:${SERVER_PORT}/index.html" 0

run_test "CSS file access" \
    "curl -s http://${SERVER_HOST}:${SERVER_PORT}/style.css" 0

run_test "404 handling" \
    "curl -s -f http://${SERVER_HOST}:${SERVER_PORT}/nonexistent.html" 22

print_header "Security Tests"

# Security feature tests
run_test "path traversal prevention" \
    "curl -s http://${SERVER_HOST}:${SERVER_PORT}/../etc/passwd" 22

run_test "file type restrictions" \
    "curl -s http://${SERVER_HOST}:${SERVER_PORT}/test.php" 22

run_test "XSS protection headers" \
    "curl -s -I http://${SERVER_HOST}:${SERVER_PORT}/index.html | grep -q 'X-XSS-Protection'" 0

# Rate limiting test
print_header "Rate Limiting Test"
printf "Testing rate limiting... "
count=0
for i in $(seq 1 100); do
    if ! curl -s "http://${SERVER_HOST}:${SERVER_PORT}/" > /dev/null; then
        break
    fi
    count=$((count + 1))
    sleep 1
done

if [ $count -lt 100 ]; then
    printf "%sPASSED%s\n" "${GREEN}" "${NC}"
    PASSED=$((PASSED + 1))
else
    printf "%sFAILED%s\n" "${RED}" "${NC}"
    FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))

print_header "Security Headers Test"

# Test security headers
headers=$(curl -s -I "http://${SERVER_HOST}:${SERVER_PORT}/index.html")
for header in "X-Frame-Options" "X-Content-Type-Options" "X-XSS-Protection"; do
    printf "Testing %s... " "$header"
    TOTAL=$((TOTAL + 1))
    if printf "%s" "$headers" | grep -q "$header"; then
        printf "%sPASSED%s\n" "${GREEN}" "${NC}"
        PASSED=$((PASSED + 1))
    else
        printf "%sFAILED%s\n" "${RED}" "${NC}"
        FAILED=$((FAILED + 1))
    fi
done

# Print summary
print_header "Test Summary"
printf "Total tests: %s%d%s\n" "${YELLOW}" "$TOTAL" "${NC}"
printf "Passed: %s%d%s\n" "${GREEN}" "$PASSED" "${NC}"
printf "Failed: %s%d%s\n" "${RED}" "$FAILED" "${NC}"

# Exit with status based on test results
if [ $FAILED -eq 0 ]; then
    printf "\n%sAll tests passed!%s\n" "${GREEN}" "${NC}"
    exit 0
else
    printf "\n%sSome tests failed.%s\n" "${RED}" "${NC}"
    printf "Check the test output above for details.\n"
    exit 1
fi