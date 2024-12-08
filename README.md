# Secure Web Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![C99](https://img.shields.io/badge/C-99-blue.svg)]()

A high-performance, security-focused web server implementation in C. Built with an emphasis on robust security features and extensive testing, this server is designed to provide a secure foundation for serving static content while protecting against common web vulnerabilities.

## 🚀 Features

### Security
- 🛡️ XSS (Cross-Site Scripting) Protection
- 🔒 SQL Injection Prevention
- ⏱️ Rate Limiting with IP tracking
- 📁 File Type Validation
- 🔑 CSRF Protection
- 🌐 Configurable CORS Support
- 🔐 HSTS Support
- 📋 Content Security Policy

### Performance
- 🚄 Concurrent Connection Handling
- 🧵 Multi-threaded Architecture
- 🔄 Connection Pooling
- ⚡ Zero-copy File Serving

### Development
- 🧪 Comprehensive Test Suite
- 📝 Detailed Logging
- 🔍 Memory Safety Checks
- 📊 Performance Metrics

## 🛠️ Building

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install gcc make

# macOS
xcode-select --install

# Fedora
sudo dnf install gcc make
```

### Compilation
```bash
make
```

## 🧪 Testing

Run the comprehensive test suite:
```bash
make test
```

## 📁 Project Structure

```
.
├── src/            # Source files
│   ├── server.c    # Main server implementation
│   ├── http.c      # HTTP protocol handling
│   └── security.c  # Security features
├── include/        # Header files
├── test/          # Test suite
│   ├── test.md    # Test documentation
│   └── test_*.c   # Test implementations
└── www/           # Web root directory
```

## 🔧 Configuration

The server supports various configuration options:
- Port and binding address
- Rate limiting thresholds
- Security policy settings
- Logging levels
- File type restrictions

## 🔒 Security Features

### XSS Protection
- Input validation and sanitization
- Content-Security-Policy headers
- XSS-Protection headers

### SQL Injection Prevention
- Query parameter validation
- Pattern matching
- Escape sequence detection

### Rate Limiting
- Per-IP tracking
- Configurable time windows
- Automatic blocking

### File Validation
- MIME type checking
- Path traversal prevention
- Extension whitelisting

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🛡️ Security

Found a security issue? Please report it privately via email instead of using the public issue tracker.