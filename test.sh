#!/bin/bash

# Colors for better readability
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test result counters
PASSED=0
FAILED=0
TOTAL=0

print_header() {
    echo -e "\n${YELLOW}=== $1 ===${NC}\n"
}

run_test() {
    local test_name="$1"
    local command="$2"
    local expected_result="$3"
    
    echo -n "Testing $test_name... "
    TOTAL=$((TOTAL + 1))
    
    if eval "$command" > /dev/null 2>&1; then
        if [ "$?" -eq "$expected_result" ]; then
            echo -e "${GREEN}PASSED${NC}"
            PASSED=$((PASSED + 1))
        else
            echo -e "${RED}FAILED${NC}"
            FAILED=$((FAILED + 1))
        fi
    else
        echo -e "${RED}FAILED${NC}"
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

print_header "Basic Functionality Tests"

# Basic access tests
run_test "basic HTML access" \
    "curl -s http://localhost:8000/index.html" 0

run_test "CSS file access" \
    "curl -s http://localhost:8000/style.css" 0

run_test "404 handling" \
    "curl -s -f http://localhost:8000/nonexistent.html" 22

print_header "Security Tests"

# Security feature tests
run_test "path traversal prevention" \
    "curl -s http://localhost:8000/../etc/passwd" 22

run_test "file type restrictions" \
    "curl -s http://localhost:8000/test.php" 22

run_test "XSS protection headers" \
    "curl -s -I http://localhost:8000/index.html | grep -q 'X-XSS-Protection'" 0

# Rate limiting test
print_header "Rate Limiting Test"
echo -n "Testing rate limiting... "
count=0
for i in {1..100}; do
    if curl -s http://localhost:8000/ > /dev/null; then
        ((count++))
    else
        break
    fi
done
if [ $count -lt 100 ]; then
    echo -e "${GREEN}PASSED${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}FAILED${NC}"
    FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))

print_header "Security Headers Test"

# Test security headers
headers=$(curl -s -I http://localhost:8000/index.html)
for header in "X-Frame-Options" "X-Content-Type-Options" "X-XSS-Protection"; do
    echo -n "Testing $header... "
    TOTAL=$((TOTAL + 1))
    if echo "$headers" | grep -q "$header"; then
        echo -e "${GREEN}PASSED${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}FAILED${NC}"
        FAILED=$((FAILED + 1))
    fi
done

# Print summary
print_header "Test Summary"
echo -e "Total tests: ${YELLOW}$TOTAL${NC}"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"

# Exit with status based on test results
if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}Some tests failed.${NC}"
    echo "Check the test output above for details."
    exit 1
fi