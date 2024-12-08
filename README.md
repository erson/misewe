# Misewe - Minimal Secure Web Server

Misewe is a minimal, security-focused web server written in C. It's designed to be lightweight while maintaining strong security features.

## Features

- 🔒 Security-first design
- 📁 Static file serving
- ⚡️ Fast and lightweight
- 🛡️ Built-in security headers
- 🚫 Path traversal prevention
- 🔑 File type restrictions
- 📝 Detailed logging
- ⏰ Request rate limiting

## Building

### Prerequisites

```bash
# On Ubuntu/Debian
sudo apt-get update
sudo apt-get install gcc make

# On macOS
xcode-select --install
```

### Compilation

```bash
# Clone the repository
git clone https://github.com/yourusername/misewe.git
cd misewe

# Build the server
make clean
make
```

## Usage

### Starting the Server

```bash
# Create web root directory if it doesn't exist
mkdir -p www

# Create a test page
echo "<h1>Welcome to Misewe</h1>" > www/index.html

# Run the server
./bin/secure_server
```

The server will start on localhost:8000 by default.

### Directory Structure

```
misewe/
├── src/           # Source files
├── include/       # Header files
├── www/          # Web root directory
├── logs/         # Log files
├── obj/          # Object files
└── bin/          # Binary output
```

### Configuration

Default settings:
- Port: 8000
- Bind Address: 127.0.0.1
- Web Root: ./www
- Max Request Size: 8192 bytes
- Allowed File Types: .html, .css, .js, .txt

## Security Features

1. **Request Validation**
   - Path traversal prevention
   - File type restrictions
   - Request size limits
   - Character validation

2. **Security Headers**
   - X-Content-Type-Options: nosniff
   - X-Frame-Options: DENY
   - X-XSS-Protection: 1; mode=block
   - Content-Security-Policy: default-src 'self'

3. **Rate Limiting**
   - Per-IP tracking
   - Configurable limits
   - Automatic blocking

4. **Logging**
   - Access logging
   - Error logging
   - Security events

## Testing

Run the test suite:
```bash
./test.sh
```

See TEST.md for detailed testing information.

## Monitoring

Monitor server logs:
```bash
# Watch access log
tail -f logs/server.log

# Monitor connections
netstat -an | grep 8000
```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see LICENSE file for details.