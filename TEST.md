# Testing Misewe - A Complete Guide

This guide will walk you through testing every aspect of Misewe. Whether you're a developer contributing to the project or a system administrator deploying it, these tests will help ensure everything works as expected.

## Quick Start

Run the entire test suite with a single command:
```bash
./test.sh
```

You can customize the test environment using these environment variables:
```bash
# Configure server location
export SERVER_HOST=localhost  # Default: localhost
export SERVER_PORT=8000      # Default: 8000
export SERVER_BINARY=misewe  # Default: misewe

# Run tests
./test.sh
```

Want to run specific security tests?
```bash
./test_security.sh
```

## What We Test

### 1. Security Features
- ✅ XSS Protection
- ✅ Path Traversal Prevention
- ✅ Rate Limiting
- ✅ File Access Control
- ✅ Security Headers

### 2. Server Functionality
- ✅ Basic HTTP Methods (GET, POST, HEAD)
- ✅ File Serving
- ✅ Error Handling
- ✅ Connection Management

## Manual Testing Guide

### Basic Functionality

Test basic file serving:
```bash
# Should return your index page
curl http://localhost:8000/index.html

# Should return your stylesheet
curl http://localhost:8000/style.css

# Should return 404
curl http://localhost:8000/nonexistent.html
```

### Security Testing

1. **XSS Protection**
   ```bash
   # Should be blocked
   curl "http://localhost:8000/<script>alert(1)</script>"
   
   # Check security headers
   curl -I http://localhost:8000/index.html | grep -i xss
   ```

2. **Path Traversal**
   ```bash
   # All these should return 403 Forbidden
   curl http://localhost:8000/../etc/passwd
   curl http://localhost:8000/..%2f..%2fetc%2fpasswd
   curl http://localhost:8000/assets/../../etc/passwd
   ```

3. **Rate Limiting**
   ```bash
   # Should get blocked after too many requests
   for i in {1..100}; do
       curl http://localhost:8000/
       sleep 0.1
   done
   ```

### Load Testing

Test server performance:
```bash
# Install Apache Bench if needed
sudo apt install apache2-utils

# Run load test (1000 requests, 10 concurrent)
ab -n 1000 -c 10 http://localhost:8000/index.html

# Check server stats during test
top -p $(pgrep misewe)
```

## Automated Test Suite

Our test suite is organized into several components:

1. **Unit Tests** (`test/test_suite.c`)
   - HTTP Parser
   - Security Functions
   - Configuration Loading

2. **Integration Tests** (`test_security.sh`)
   - End-to-end Security Features
   - Server Response Validation

3. **Performance Tests** (`test/benchmark.sh`)
   - Response Time
   - Concurrent Connections
   - Memory Usage

## Setting Up Test Environment

1. Create test files:
```bash
# Create test directory structure
mkdir -p www/assets www/css

# Create test HTML file
cat > www/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <h1>Misewe Test Page</h1>
</body>
</html>
EOF

# Create test CSS
echo "body { font-family: Arial; }" > www/css/style.css
```

2. Set up logging:
```bash
mkdir -p logs
chmod 755 logs
```

## Common Test Issues

### 1. Tests Failing to Connect
```bash
# Check if server is running on custom host/port
curl http://$SERVER_HOST:$SERVER_PORT

# Check process
ps aux | grep $SERVER_BINARY
```

### 2. Permission Issues
```bash
# Fix test file permissions (Unix/Linux)
chmod -R 755 www/
chmod 755 test/*.sh

# For Windows (in PowerShell with admin rights)
icacls www /grant Everyone:F /t
icacls test\*.sh /grant Everyone:F
```

### 3. Rate Limit Tests Failing
```bash
# Reset rate limit counters
./bin/$SERVER_BINARY --reset-limits

# Adjust rate limit in config
vim config.ini  # modify rate_limit_requests
```

## Cross-Platform Compatibility

The test suite is designed to work across different operating systems:

### Unix/Linux
- All features supported out of the box
- Uses standard POSIX shell commands
- Color output supported in most terminals

### macOS
- Full compatibility with Unix/Linux features
- Install required tools: `brew install curl grep`

### Windows
- Run using Git Bash, WSL, or Cygwin
- PowerShell support through wrapper scripts
- Color output supported in modern terminals

### Docker
```bash
# Run tests in container
docker run -e SERVER_HOST=host.docker.internal \
          -e SERVER_PORT=8000 \
          -v $(pwd):/app \
          -w /app \
          alpine:latest \
          ./test.sh
```

## Test Result Analysis

Good test results should show:
- All security tests passing
- Response times under 10ms
- Memory usage below 10MB
- Zero memory leaks
- All security headers present

## Contributing New Tests

1. Add unit tests to `test/test_suite.c`
2. Add integration tests to `test_security.sh`
3. Update this documentation
4. Submit a PR!

## Need Help?

- Check the logs: `tail -f logs/test.log`
- Join our Discord: [discord.gg/misewe](https://discord.gg/misewe)
- Open an issue: [github.com/erson/misewe/issues](https://github.com/erson/misewe/issues)