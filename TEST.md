# Secure Server Test Guide

This document provides test procedures for all security features of the secure server.

## Table of Contents
1. [Basic Functionality Tests](#basic-functionality-tests)
2. [Security Feature Tests](#security-feature-tests)
3. [Performance Tests](#performance-tests)
4. [Attack Simulation Tests](#attack-simulation-tests)
5. [Logging Tests](#logging-tests)

## Setup

First, build and start the server:
```bash
# Build the server
make clean
make

# Start the server
./bin/secure_server
```

## Basic Functionality Tests

### 1. Basic HTTP Request
```bash
# Test normal page access
curl http://localhost:8000/index.html

# Expected result: 200 OK with HTML content
```

### 2. Static File Types
```bash
# Test HTML file
curl http://localhost:8000/index.html

# Test CSS file
curl http://localhost:8000/style.css

# Test JavaScript file
curl http://localhost:8000/script.js

# All should return 200 OK with appropriate content
```

## Security Feature Tests

### 1. Path Traversal Prevention
```bash
# Test directory traversal
curl http://localhost:8000/../etc/passwd
# Expected: 403 Forbidden

# Test encoded traversal
curl http://localhost:8000/..%2f..%2fetc%2fpasswd
# Expected: 403 Forbidden

# Test multiple slashes
curl http://localhost:8000////etc/passwd
# Expected: 403 Forbidden
```

### 2. Rate Limiting
```bash
# Test rapid requests
for i in {1..100}; do
    curl http://localhost:8000/
    sleep 0.1
done
# Expected: Should start receiving 429 Too Many Requests
```

### 3. File Type Restrictions
```bash
# Test prohibited file types
curl http://localhost:8000/test.php
# Expected: 403 Forbidden

curl http://localhost:8000/shell.cgi
# Expected: 403 Forbidden

curl http://localhost:8000/.htaccess
# Expected: 403 Forbidden
```

### 4. Security Headers
```bash
# Check security headers
curl -I http://localhost:8000/index.html

# Expected headers:
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# X-XSS-Protection: 1; mode=block
# Content-Security-Policy: default-src 'self'
```

### 5. Input Validation
```bash
# Test XSS attempt
curl "http://localhost:8000/<script>alert(1)</script>"
# Expected: 400 Bad Request

# Test SQL injection attempt
curl "http://localhost:8000/page?id=1'%20OR%20'1'='1"
# Expected: 400 Bad Request

# Test command injection
curl "http://localhost:8000/$(cat /etc/passwd)"
# Expected: 400 Bad Request
```

## Performance Tests

### 1. Concurrent Connections
```bash
# Test multiple concurrent connections
ab -n 1000 -c 100 http://localhost:8000/index.html

# Expected: Should handle concurrent connections without errors
```

### 2. Large File Handling
```bash
# Create a large test file
dd if=/dev/zero of=www/large.txt bs=1M count=10

# Test large file download
curl http://localhost:8000/large.txt -o /dev/null
# Expected: Should transfer completely without timeout
```

## Attack Simulation Tests

### 1. DOS Attack Simulation
```bash
# Rapid connection attempts
for i in {1..1000}; do
    curl http://localhost:8000/ &
done

# Expected: Rate limiting should prevent server overload
```

### 2. Protocol Attack Tests
```bash
# Invalid HTTP method
curl -X INVALID http://localhost:8000/
# Expected: 405 Method Not Allowed

# Malformed request
printf "GET / INVALID\r\n\r\n" | nc localhost 8000
# Expected: 400 Bad Request
```

### 3. Buffer Overflow Attempts
```bash
# Long URL
curl "http://localhost:8000/$(printf 'A%.0s' {1..10000})"
# Expected: 414 URI Too Long

# Long headers
curl -H "X-Test: $(printf 'A%.0s' {1..10000})" http://localhost:8000/
# Expected: 413 Request Entity Too Large
```

## Logging Tests

### 1. Access Log Verification
```bash
# Make some requests
curl http://localhost:8000/index.html
curl http://localhost:8000/style.css

# Check access log
tail -f logs/access.log
# Expected: Should show requests with timestamps and status codes
```

### 2. Error Log Verification
```bash
# Generate some errors
curl http://localhost:8000/nonexistent.html
curl http://localhost:8000/../etc/passwd

# Check error log
tail -f logs/error.log
# Expected: Should show detailed error messages
```

### 3. Security Event Logging
```bash
# Generate security events
curl "http://localhost:8000/<script>alert(1)</script>"
curl http://localhost:8000/../etc/passwd

# Check security log
tail -f logs/security.log
# Expected: Should show security violations with IP addresses
```

## Automated Testing Script

Here's a script to run all tests automatically:

```bash
#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "Starting comprehensive server tests..."

# Function to test and report
test_feature() {
    local test_name=$1
    local command=$2
    local expected=$3
    
    echo -n "Testing $test_name... "
    result=$(eval $command)
    if [[ $result == *"$expected"* ]]; then
        echo -e "${GREEN}PASS${NC}"
    else
        echo -e "${RED}FAIL${NC}"
    fi
}

# Basic functionality tests
test_feature "Basic Access" \
    "curl -s -o /dev/null -w '%{http_code}' http://localhost:8000/index.html" \
    "200"

# Security tests
test_feature "Path Traversal" \
    "curl -s -o /dev/null -w '%{http_code}' http://localhost:8000/../etc/passwd" \
    "403"

test_feature "Rate Limiting" \
    "for i in {1..100}; do curl -s http://localhost:8000/ > /dev/null; done" \
    "429"

test_feature "File Type Restriction" \
    "curl -s -o /dev/null -w '%{http_code}' http://localhost:8000/test.php" \
    "403"

test_feature "Security Headers" \
    "curl -s -I http://localhost:8000/index.html" \
    "X-Frame-Options: DENY"

echo "Tests complete!"
```

## Monitoring Guide

### Real-time Monitoring
Use this command to monitor server activity in real-time:
```bash
# Watch all logs
tail -f logs/access.log logs/error.log logs/security.log

# Monitor connections
watch 'netstat -an | grep 8000'

# Monitor server process
top -p $(pgrep secure_server)
```

### Health Checks
```bash
# Check server response time
time curl http://localhost:8000/index.html

# Check memory usage
ps aux | grep secure_server

# Check open file descriptors
lsof -p $(pgrep secure_server)
```

## Notes

- Run tests in a development environment
- Some tests may trigger security measures
- Rate limiting may require delays between tests
- Monitor system resources during testing
- Check logs for detailed information about failures

For troubleshooting:
1. Check logs in logs/ directory
2. Verify server configuration
3. Ensure proper permissions
4. Monitor system resources
5. Check network connectivity