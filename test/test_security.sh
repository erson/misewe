#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Base URL
BASE_URL="http://localhost:8000"

echo "Running security tests..."

# Test 1: Basic Access
test_basic_access() {
    echo -n "Testing basic access... "
    if curl -s "$BASE_URL/index.html" > /dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
    fi
}

# Test 2: Path Traversal Prevention
test_path_traversal() {
    echo -n "Testing path traversal prevention... "
    if curl -s "$BASE_URL/../etc/passwd" > /dev/null; then
        echo -e "${RED}VULNERABLE${NC}"
    else
        echo -e "${GREEN}PROTECTED${NC}"
    fi
}

# Test 3: File Type Restrictions
test_file_restrictions() {
    echo -n "Testing file type restrictions... "
    if curl -s "$BASE_URL/test.php" > /dev/null; then
        echo -e "${RED}VULNERABLE${NC}"
    else
        echo -e "${GREEN}PROTECTED${NC}"
    fi
}

# Test 4: Rate Limiting
test_rate_limiting() {
    echo -n "Testing rate limiting... "
    count=0
    for i in {1..100}; do
        if curl -s "$BASE_URL/" > /dev/null; then
            ((count++))
        else
            break
        fi
    done
    if [ $count -lt 100 ]; then
        echo -e "${GREEN}WORKING${NC}"
    else
        echo -e "${RED}NOT WORKING${NC}"
    fi
}

# Test 5: Security Headers
test_security_headers() {
    echo -n "Testing security headers... "
    headers=$(curl -s -I "$BASE_URL/index.html")
    if echo "$headers" | grep -q "X-Frame-Options" && \
       echo "$headers" | grep -q "X-Content-Type-Options" && \
       echo "$headers" | grep -q "X-XSS-Protection"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}MISSING${NC}"
    fi
}

# Run all tests
test_basic_access
test_path_traversal
test_file_restrictions
test_rate_limiting
test_security_headers

echo "Security tests complete."