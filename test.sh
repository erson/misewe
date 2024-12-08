#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "Testing Misewe server..."

# Test basic access
echo -n "Testing basic access... "
if curl -s http://localhost:8000/index.html > /dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Test security features
echo -n "Testing path traversal prevention... "
if ! curl -s http://localhost:8000/../etc/passwd > /dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Test file type restriction
echo -n "Testing file type restriction... "
if ! curl -s http://localhost:8000/test.php > /dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Test security headers
echo -n "Testing security headers... "
if curl -sI http://localhost:8000/index.html | grep -q "X-Frame-Options: DENY"; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

echo "Tests complete."