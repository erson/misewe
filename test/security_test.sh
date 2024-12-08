#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo "Testing server security..."

# Test 1: Basic Access
echo -n "Testing basic access... "
if curl -s http://localhost:8000/index.html > /dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Test 2: Path Traversal Prevention
echo -n "Testing path traversal prevention... "
if curl -s http://localhost:8000/../etc/passwd > /dev/null; then
    echo -e "${RED}VULNERABLE${NC}"
else
    echo -e "${GREEN}PROTECTED${NC}"
fi

# Test 3: File Type Restrictions
echo -n "Testing file type restrictions... "
if curl -s http://localhost:8000/test.php > /dev/null; then
    echo -e "${RED}VULNERABLE${NC}"
else
    echo -e "${GREEN}PROTECTED${NC}"
fi

# Test 4: Rate Limiting
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
    echo -e "${GREEN}WORKING${NC}"
else
    echo -e "${RED}NOT WORKING${NC}"
fi

# Test 5: Security Headers
echo -n "Testing security headers... "
headers=$(curl -s -I http://localhost:8000/index.html)
if echo "$headers" | grep -q "X-Frame-Options" && \
   echo "$headers" | grep -q "X-Content-Type-Options" && \
   echo "$headers" | grep -q "X-XSS-Protection"; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}MISSING${NC}"
fi

echo "Security test complete."