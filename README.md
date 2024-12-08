# Secure Web Server

A secure web server implementation in C with focus on security features and robust testing.

## Features

- HTTP request handling
- Security features (XSS protection, SQL injection prevention)
- Rate limiting
- File type validation
- Concurrent connection handling
- Comprehensive test suite

## Building

```bash
make
```

## Testing

```bash
make test
```

## Project Structure

- `src/` - Source files
- `include/` - Header files
- `test/` - Test suite
- `www/` - Web root directory

## Security Features

- XSS Protection
- SQL Injection Prevention
- Rate Limiting
- File Type Validation
- CSRF Protection
- CORS Support
- HSTS Support
- Content Security Policy

## Requirements

- GCC compiler
- Make build system
- POSIX-compliant system
- pthread support

## License

MIT License