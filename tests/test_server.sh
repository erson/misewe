#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "Testing secure server..."

# Test 1: Basic Access
echo -n "Testing basic access... "
if curl -s http://localhost:8000/index.html > /dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Test 2: Authentication
echo -n "Testing authentication... "
if curl -s -u admin:password123 http://localhost:8000/protected/ > /dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Test 3: Path Traversal Prevention
echo -n "Testing path traversal prevention... "
if curl -s http://localhost:8000/../etc/passwd > /dev/null; then
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

echo "Tests complete."