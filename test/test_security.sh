#!/bin/sh

# Colors for output (using tput for better portability)
if [ -t 1 ]; then
    GREEN=$(tput setaf 2)
    RED=$(tput setaf 1)
    NC=$(tput sgr0)
else
    GREEN=""
    RED=""
    NC=""
fi

# Base URL
BASE_URL="http://localhost:8000"

echo "Running security tests..."

# Test 1: Basic Access
test_basic_access() {
    printf "Testing basic access... "
    if curl -s "$BASE_URL/index.html" > /dev/null; then
        printf "%sOK%s\n" "${GREEN}" "${NC}"
    else
        printf "%sFAILED%s\n" "${RED}" "${NC}"
    fi
}

# Test 2: Path Traversal Prevention
test_path_traversal() {
    printf "Testing path traversal prevention... "
    if curl -s -f "$BASE_URL/../etc/passwd" > /dev/null 2>&1; then
        printf "%sVULNERABLE%s\n" "${RED}" "${NC}"
    else
        printf "%sPROTECTED%s\n" "${GREEN}" "${NC}"
    fi
}

# Test 3: File Type Restrictions
test_file_restrictions() {
    printf "Testing file type restrictions... "
    if curl -s -f "$BASE_URL/test.php" > /dev/null 2>&1; then
        printf "%sVULNERABLE%s\n" "${RED}" "${NC}"
    else
        printf "%sPROTECTED%s\n" "${GREEN}" "${NC}"
    fi
}

# Test 4: Rate Limiting
test_rate_limiting() {
    printf "Testing rate limiting... "
    count=0
    blocked=0
    i=0
    while [ $i -lt 100 ] && [ $blocked -eq 0 ]; do
        response=$(curl -s -w "%{http_code}" -o /dev/null "$BASE_URL/")
        if [ "$response" = "429" ]; then
            blocked=1
        elif [ "$response" = "200" ]; then
            count=$((count + 1))
        else
            printf "%sFAILED%s (Unexpected response code: %s)\n" "${RED}" "${NC}" "$response"
            return 1
        fi
        i=$((i + 1))
    done
    
    if [ $blocked -eq 1 ]; then
        printf "%sWORKING%s (Blocked after %d requests)\n" "${GREEN}" "${NC}" "$count"
    else
        printf "%sNOT WORKING%s (No rate limiting after %d requests)\n" "${RED}" "${NC}" "$count"
    fi
}

# Test 5: Security Headers
test_security_headers() {
    printf "Testing security headers... "
    headers=$(curl -s -I "$BASE_URL/index.html")
    if printf "%s" "$headers" | grep -q "X-Frame-Options" && \
       printf "%s" "$headers" | grep -q "X-Content-Type-Options" && \
       printf "%s" "$headers" | grep -q "X-XSS-Protection"; then
        printf "%sOK%s\n" "${GREEN}" "${NC}"
    else
        printf "%sMISSING%s\n" "${RED}" "${NC}"
    fi
}

# Run all tests
test_basic_access
test_path_traversal
test_file_restrictions
test_rate_limiting
test_security_headers

echo "Security tests complete."