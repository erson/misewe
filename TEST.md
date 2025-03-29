# Misewe Web Server Test Protocol

This document describes the test protocol for the Misewe web server. The test protocol covers various aspects of the server's functionality, including HTTP requests, response headers, security features, and rate limiting.

## Test Categories

The test protocol is organized into several categories:

### 1. Basic HTTP Requests

Tests the server's ability to serve different types of files:
- HTML files
- CSS stylesheets
- JavaScript files
- Image files (PNG)
- Error handling (404 Not Found)

### 2. HTTP Header Tests

Verifies that the server sends correct headers based on file types:
- Content-Type for HTML files
- Content-Type for CSS files
- Content-Type for JavaScript files
- Content-Type for image files

### 3. Security Header Tests

Checks for essential security headers:
- X-Frame-Options (prevents clickjacking)
- X-Content-Type-Options (prevents MIME sniffing)
- X-XSS-Protection (helps prevent XSS attacks)
- Content-Security-Policy (restricts resource loading)
- Strict-Transport-Security (HSTS, encourages HTTPS)

### 4. Cache Control Tests

Validates the server's cache control mechanisms:
- ETag header presence
- Cache-Control header presence
- 304 Not Modified responses with If-None-Match headers

### 5. Security Feature Tests

Tests security-related features:
- Path traversal prevention
- File type restrictions

### 6. HTTP Method Tests

Verifies support for different HTTP methods:
- HEAD method (headers only, no body)
- GET method (full response)

### 7. Rate Limiting Tests

Tests the rate limiting functionality:
- Sending multiple requests quickly
- Receiving 429 (Too Many Requests) responses when limits are exceeded

## Running Tests

To run the complete test protocol:

```bash
# Build the server
make

# Run the test protocol
./test-improved.sh
```

The test script will:
1. Build the server
2. Start the server
3. Run all test categories
4. Display detailed results
5. Stop the server

## Manual Testing

For manual testing, you can use tools like `curl`:

```bash
# Test basic file access
curl -v http://localhost:8000/index.html

# Test caching with ETag
curl -v -H "If-None-Match: \"your-etag-value\"" http://localhost:8000/index.html

# Test rate limiting
for i in {1..100}; do curl -s http://localhost:8000/; done
```

## Test Success Criteria

A successful test run will show:
- All tests passed
- No unexpected errors
- All HTTP responses contain correct headers
- Security features work as expected
- Rate limiting properly restricts request frequency

If any test fails, the output will indicate which specific test failed and provide details about the failure.
