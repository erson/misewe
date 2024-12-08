#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "Testing server features..."

# Test basic access
echo -n "Testing basic access... "
if curl -s http://localhost:8000/index.html > /dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Test rate limiting
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

# Test security headers
echo -n "Testing security headers... "
headers=$(curl -s -I http://localhost:8000/index.html)
if echo "$headers" | grep -q "X-Frame-Options: DENY"; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}MISSING${NC}"
fi

echo "Tests complete."