#!/bin/bash

# Colors for better readability
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test result counters
PASSED=0
FAILED=0
TOTAL=0

# Temporary files
TMPFILE=$(mktemp)
trap 'rm -f $TMPFILE' EXIT

print_header() {
    echo -e "\n${YELLOW}=== $1 ===${NC}\n"
}

print_info() {
    echo -e "${BLUE}INFO: $1${NC}"
}

run_test() {
    local test_name="$1"
    local command="$2"
    local expected_result="$3"
    local description="$4"
    
    echo -n "Testing $test_name... "
    TOTAL=$((TOTAL + 1))
    
    if [ -n "$description" ]; then
        print_info "$description"
    fi
    
    if eval "$command" > "$TMPFILE" 2>&1; then
        if [ "$?" -eq "$expected_result" ]; then
            echo -e "${GREEN}PASSED${NC}"
            PASSED=$((PASSED + 1))
        else
            echo -e "${RED}FAILED${NC}"
            echo "Expected return code $expected_result, got $?"
            cat "$TMPFILE"
            FAILED=$((FAILED + 1))
        fi
    else
        echo -e "${RED}FAILED${NC}"
        cat "$TMPFILE"
        FAILED=$((FAILED + 1))
    fi
}

# Check if server is running
if ! pgrep misewe > /dev/null; then
    echo -e "${RED}Error: Misewe server is not running${NC}"
    echo "Please start the server first:"
    echo "  ./bin/misewe"
    exit 1
fi

print_header "XSS Protection Tests"

run_test "basic XSS attempt" \
    "curl -s 'http://localhost:8000/<script>alert(1)</script>'" 22 \
    "Testing basic script injection"

run_test "XSS in query params" \
    "curl -s 'http://localhost:8000/index.html?q=<script>alert(1)</script>'" 22 \
    "Testing script injection in query parameters"

run_test "XSS protection header" \
    "curl -s -I http://localhost:8000/index.html | grep -q 'X-XSS-Protection: 1; mode=block'" 0 \
    "Checking if XSS protection header is set correctly"

print_header "Path Traversal Tests"

run_test "basic path traversal" \
    "curl -s http://localhost:8000/../etc/passwd" 22 \
    "Testing basic directory traversal"

run_test "encoded path traversal" \
    "curl -s 'http://localhost:8000/..%2f..%2fetc%2fpasswd'" 22 \
    "Testing URL-encoded directory traversal"

run_test "double encoded traversal" \
    "curl -s 'http://localhost:8000/%2e%2e%2f%2e%2e%2fetc%2fpasswd'" 22 \
    "Testing double URL-encoded directory traversal"

print_header "File Access Control Tests"

run_test "restricted file types" \
    "curl -s http://localhost:8000/test.php" 22 \
    "Testing access to PHP files"

run_test "hidden files" \
    "curl -s http://localhost:8000/.htaccess" 22 \
    "Testing access to hidden files"

print_header "Rate Limiting Tests"

echo -n "Testing rate limiting... "
TOTAL=$((TOTAL + 1))
count=0
blocked=0

print_info "Sending 100 rapid requests to test rate limiting"
for i in {1..100}; do
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/ | grep -q "429"; then
        blocked=1
        break
    fi
    ((count++))
done

if [ $blocked -eq 1 ] && [ $count -lt 100 ]; then
    echo -e "${GREEN}PASSED${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}FAILED${NC}"
    echo "Rate limiting did not trigger after $count requests"
    FAILED=$((FAILED + 1))
fi

print_header "Security Headers Tests"

headers=$(curl -s -I http://localhost:8000/index.html)

# Test each security header
for header in \
    "X-Frame-Options: DENY" \
    "X-Content-Type-Options: nosniff" \
    "X-XSS-Protection: 1; mode=block" \
    "Content-Security-Policy" \
    "Strict-Transport-Security"; do
    
    echo -n "Testing presence of $header... "
    TOTAL=$((TOTAL + 1))
    
    if echo "$headers" | grep -q "$header"; then
        echo -e "${GREEN}PASSED${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}FAILED${NC}"
        FAILED=$((FAILED + 1))
    fi
done

print_header "HTTP Method Tests"

run_test "invalid HTTP method" \
    "curl -X INVALID http://localhost:8000/" 22 \
    "Testing server response to invalid HTTP method"

run_test "blocked PUT method" \
    "curl -X PUT http://localhost:8000/" 22 \
    "Testing if PUT method is blocked"

# Print summary
print_header "Security Test Summary"
echo -e "Total tests: ${YELLOW}$TOTAL${NC}"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"

# Exit with status based on test results
if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}All security tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}Some security tests failed.${NC}"
    echo "Please review the test output above and check server logs for details."
    exit 1
fi