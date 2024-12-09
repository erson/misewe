# Misewe - A Minimal(Modern) Secure Web Server

A lightweight, security-first web server written in C that doesn't compromise on performance. Whether you're serving static content or building a secure foundation for your web applications, Misewe has got you covered.

## Why Misewe?

- 🛡️ **Security First**: Built from the ground up with security best practices
- ⚡ **Blazing Fast**: Optimized C implementation with zero-copy file serving
- 🧪 **Battle-tested**: Comprehensive test suite covering security and performance
- 🔧 **Easy to Configure**: Simple configuration for all security features
- 🌐 **Portable**: Works across different Unix-like systems and Windows (via WSL)

## Quick Start

1. Clone and build:
```bash
git clone https://github.com/erson/misewe.git
cd misewe
make
```

2. Start the server:
```bash
./bin/misewe
```

That's it! Your secure web server is running at http://localhost:8000

## Security Features

### Path Traversal Prevention
- Strict path validation using realpath()
- Blocks access to files outside web root
- Handles URL-encoded traversal attempts
- Validates path components for safety

### File Type Restrictions
- Whitelist of allowed file extensions
- Blocks dangerous file types (PHP, ASP, etc.)
- Multiple extension checking (e.g., .php.html)
- Directory access control with trailing slash requirement

### Rate Limiting
- Per-IP request tracking
- Configurable window and request limits
- Burst handling with token bucket algorithm
- Automatic blocking of excessive requests

### Security Headers
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- X-XSS-Protection: 1; mode=block
- Content-Security-Policy: default-src 'self'
- Strict-Transport-Security: max-age=31536000

## Configuration Guide

Create a `config.ini` in your root directory:
```ini
[server]
port=8000
threads=4
web_root=www

[security]
enable_rate_limit=true
rate_limit_requests=60
rate_limit_window=60

[files]
allowed_extensions=.html,.htm,.css,.js,.txt,.ico,.png,.jpg,.jpeg,.gif,.webp,.svg,.woff,.woff2,.ttf,.eot,.json,.xml
```

## Development Setup

### Prerequisites
You'll need:
- GCC or Clang
- Make
- pthread library
- curl (for testing)

#### On Ubuntu/Debian:
```bash
sudo apt update
sudo apt install build-essential libpthread-stubs0-dev curl
```

#### On macOS:
```bash
brew install gcc make curl
```

#### On Windows (WSL):
```bash
wsl --install  # If WSL not installed
sudo apt update
sudo apt install build-essential libpthread-stubs0-dev curl
```

### Building
```bash
# Standard build
make

# Debug build
make DEBUG=1

# Run tests
make test
./test.sh
```

## Portability Notes

### File System
- Uses PATH_MAX from <linux/limits.h> for path buffers
- Falls back to 4096 if not defined
- Handles both forward and backslashes for paths
- Uses realpath() for canonical path resolution

### Network
- Supports both IPv4 and IPv6
- Handles platform-specific socket options
- Proper error handling for different systems

### Threading
- POSIX threads (pthread) for portability
- Fallback to single-threaded mode if unavailable
- Thread-safe data structures and operations

## Latest Changes

### Security Improvements (v1.1.0)
- Enhanced path traversal prevention using realpath()
- Added comprehensive file type restrictions
- Improved rate limiting with proper request order
- Fixed security check bypass issues

### Bug Fixes
- Fixed rate limiter counting after security checks
- Corrected HTTP status codes for security violations
- Fixed path validation for non-existent files
- Improved error handling in security checks

## License

MIT License - feel free to use in your projects, commercial or otherwise.

## Need Help?

- 📖 Check our [Wiki](https://github.com/erson/misewe/wiki)
- 🐛 Report issues on our [Issue Tracker](https://github.com/erson/misewe/issues)
- 💬 Join our [Discord community](https://discord.gg/misewe)
