#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "Testing server features..."

# Test 1: Basic Access
echo -n "Testing basic access... "
if curl -s http://localhost:8000/index.html > /dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Test 2: File Type Restriction
echo -n "Testing file type restriction... "
if ! curl -s http://localhost:8000/test.php > /dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Test 3: Path Traversal
echo -n "Testing path traversal prevention... "
if ! curl -s http://localhost:8000/../etc/passwd > /dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Test 4: Missing File
echo -n "Testing 404 handling... "
if ! curl -s http://localhost:8000/nonexistent.html > /dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

echo "Tests complete."