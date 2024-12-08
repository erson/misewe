#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo "Testing server security..."

# Test basic access
echo -n "Testing basic access... "
if curl -s http://localhost:8000/index.html > /dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Test path traversal
echo -n "Testing path traversal prevention... "
if curl -s http://localhost:8000/../etc/passwd > /dev/null; then
    echo -e "${RED}VULNERABLE${NC}"
else
    echo -e "${GREEN}PROTECTED${NC}"
fi

# Test XSS protection
echo -n "Testing XSS protection... "
if curl -s "http://localhost:8000/<script>alert(1)</script>" > /dev/null; then
    echo -e "${RED}VULNERABLE${NC}"
else
    echo -e "${GREEN}PROTECTED${NC}"
fi

# Test SQL injection
echo -n "Testing SQL injection protection... "
if curl -s "http://localhost:8000/page?id=1%27%20OR%20%271%27=%271" > /dev/null; then
    echo -e "${RED}VULNERABLE${NC}"
else
    echo -e "${GREEN}PROTECTED${NC}"
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

echo "Security test complete."