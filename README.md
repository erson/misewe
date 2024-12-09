# Misewe - A Minimal(Modern) Secure Web Server

A lightweight, security-first web server written in C that doesn't compromise on performance. Whether you're serving static content or building a secure foundation for your web applications, Misewe has got you covered.

## Why Misewe?

- 🛡️ **Security First**: Built from the ground up with security best practices
- ⚡ **Blazing Fast**: Optimized C implementation with zero-copy file serving
- 🧪 **Battle-tested**: Comprehensive test suite covering security and performance
- 🔧 **Easy to Configure**: Simple configuration for all security features

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

## Real-World Security Features

### XSS Protection
We don't just set headers - we actively sanitize content and implement CSP:
```bash
# Check the headers yourself
curl -I http://localhost:8000 | grep -i xss
```

### Rate Limiting
Protect against DDoS and brute force attacks:
```bash
# Configuration example
max_requests=100
time_window=60  # seconds
```

### Smart File Access
- Automatic MIME type detection
- Path traversal prevention
- Extension blacklisting

## Configuration Guide

Create a `config.ini` in your root directory:
```ini
[server]
port=8000
threads=4

[security]
enable_rate_limit=true
rate_limit_requests=100
rate_limit_window=60

[cors]
enable_cors=true
allowed_origins=https://yourdomain.com
```

## Development Setup

### Prerequisites
You'll need:
- GCC or Clang
- Make
- pthread library

On Ubuntu/Debian:
```bash
sudo apt update
sudo apt install build-essential libpthread-stubs0-dev
```

### Building for Development
```bash
# Build with debug symbols
make DEBUG=1

# Run tests
make test
```

## Performance Tips

1. **File Serving**
   - Enable zero-copy transfers
   - Use appropriate buffer sizes

2. **Connection Handling**
   - Adjust thread pool size based on CPU cores
   - Fine-tune keep-alive settings

## Contributing

We love contributions! Here's how to get started:

1. Fork the repo
2. Create a feature branch
3. Write clean, commented code
4. Add tests for new features
5. Submit a PR

## Troubleshooting

### Common Issues

1. **Address already in use**
   ```bash
   # Check if port 8000 is in use
   lsof -i :8000
   # Kill existing process if needed
   kill $(lsof -t -i:8000)
   ```

2. **Permission denied**
   ```bash
   # Check log directory permissions
   ls -la logs/
   # Fix permissions
   chmod 755 logs/
   ```

## License

MIT License - feel free to use in your projects, commercial or otherwise.

## Need Help?

- 📖 Check our [Wiki](https://github.com/erson/misewe/wiki)
- 🐛 Report issues on our [Issue Tracker](https://github.com/erson/misewe/issues)
- 💬 Join our [Discord community](https://discord.gg/misewe)
