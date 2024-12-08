# Misewe Test Guide

This document describes how to test the Misewe secure web server.

## Prerequisites

Make sure you have the following installed:
- curl
- netstat
- bash

## Basic Tests

### 1. Start the Server
```bash
make clean
make
./bin/secure_server
```

### 2. Run Test Suite
```bash
./test.sh
```

## Manual Testing

### 1. Basic Access
```bash
# Test basic HTML access
curl http://localhost:8000/index.html

# Test CSS file
curl http://localhost:8000/style.css
```

### 2. Security Features

#### Path Traversal Prevention
```bash
# Should return 403 Forbidden
curl http://localhost:8000/../etc/passwd
curl http://localhost:8000/..%2f..%2fetc%2fpasswd
```

#### File Type Restrictions
```bash
# Should return 403 Forbidden
curl http://localhost:8000/test.php
curl http://localhost:8000/script.cgi
```

#### Rate Limiting
```bash
# Should be blocked after too many requests
for i in {1..100}; do
    curl http://localhost:8000/
    sleep 0.1
done
```

#### Security Headers
```bash
# Check security headers
curl -I http://localhost:8000/index.html
```

### 3. Error Handling

```bash
# Test 404 Not Found
curl http://localhost:8000/nonexistent.html

# Test 400 Bad Request
printf "GET / INVALID\r\n\r\n" | nc localhost 8000

# Test 413 Request Too Large
curl -X POST -d @large_file http://localhost:8000/
```

## Performance Testing

### 1. Basic Load Test
```bash
# Using Apache Bench (ab)
ab -n 1000 -c 10 http://localhost:8000/index.html
```

### 2. Concurrent Connections
```bash
# Test multiple simultaneous connections
for i in {1..50}; do
    curl http://localhost:8000/ &
done
```

## Security Testing

### 1. File Access Control
```bash
# Create test files
echo "public" > www/public.html
echo "private" > www/private.txt

# Test access
curl http://localhost:8000/public.html   # Should succeed
curl http://localhost:8000/private.txt   # Should fail
```

### 2. Request Validation
```bash
# Test long URLs (should fail)
curl "http://localhost:8000/$(printf 'A%.0s' {1..1000})"

# Test special characters (should fail)
curl "http://localhost:8000/<script>alert(1)</script>"
```

### 3. Protocol Compliance
```bash
# Test invalid HTTP method
curl -X INVALID http://localhost:8000/

# Test invalid HTTP version
printf "GET / HTTP/9.9\r\n\r\n" | nc localhost 8000
```

## Monitoring

### 1. Log Analysis
```bash
# Watch logs in real-time
tail -f logs/server.log

# Count error occurrences
grep ERROR logs/server.log | wc -l
```

### 2. Connection Monitoring
```bash
# Monitor active connections
watch 'netstat -an | grep 8000'

# Monitor server process
top -p $(pgrep secure_server)
```

### 3. Resource Usage
```bash
# Check file descriptors
lsof -p $(pgrep secure_server)

# Check memory usage
ps aux | grep secure_server
```

## Test Files

### Create Test Content
```bash
# Create test HTML
cat > www/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Misewe Test</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <h1>Welcome to Misewe</h1>
    <p>Server is running!</p>
</body>
</html>
EOF

# Create test CSS
cat > www/style.css << 'EOF'
body {
    font-family: Arial, sans-serif;
    margin: 40px;
    background: #f0f0f0;
}
EOF
```

## Common Issues

1. **Permission Denied**
   - Solution: Check file permissions in www directory

2. **Address Already in Use**
   - Solution: Check if another instance is running
   - Use: `lsof -i :8000`

3. **Connection Refused**
   - Solution: Verify server is running
   - Check: `ps aux | grep secure_server`

## Performance Baselines

- Response time: < 10ms
- Concurrent connections: 100+
- Memory usage: < 10MB
- CPU usage: < 5%

## Test Cleanup

```bash
# Stop server
killall secure_server

# Clean logs
rm -f logs/*

# Remove test files
rm -f www/*
```

Remember to always monitor the server logs while testing for detailed information about any issues or security events.