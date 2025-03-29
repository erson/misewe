# Zircon - A Minimal Secure Web Server

**IMPORTANT: This is an experimental project built entirely with AI assistance. DO NOT USE IN PRODUCTION!**

This project is a proof-of-concept web server written in C, developed through collaboration with AI. It serves as an interesting experiment in AI-assisted development and demonstrates both the capabilities and limitations of current AI coding assistants.

## Project Context

- **AI-Driven Development**: Every line of code, from architecture to implementation, was written with AI guidance
- **Experimental Nature**: While functional, this is a learning experiment, not production software
- **Research Value**: Demonstrates AI's current capabilities in system programming
- **Educational Purpose**: Useful for studying AI-human collaboration in software development

## Features Implemented

- Basic HTTP server functionality (GET, HEAD)
- Security features (path traversal prevention, file type restrictions)
- Rate limiting implementation
- File serving capabilities with correct MIME types
- ETag and caching support
- Security headers (XSS protection, content security policy, etc.)
- Comprehensive test suite

## Recent Improvements

The latest updates to the project include:

- Proper MIME type detection for served files
- ETag generation and validation for caching
- Cache-Control headers for browser caching optimization
- Improved HTTP headers formatting
- Better handling of HEAD requests
- Enhanced security headers implementation
- More robust rate limiting mechanism
- Comprehensive test protocol

## Running the Project

For experimental or educational purposes only:

```bash
# Clone and build
git clone https://github.com/erson/zircon.git
cd zircon
make

# Start server (for testing only)
./bin/zircon

# Run test suite
./test-improved.sh
```

## Project Structure

```
zircon/
├── bin/          # Compiled executables
├── conf/         # Configuration files
├── include/      # Header files
├── obj/          # Object files (created during build)
├── src/          # Source code
├── test/         # Test scripts and utilities
├── www/          # Web root directory
├── test-improved.sh  # Test protocol
└── README.md     # This file
```

## Known Limitations

As an AI-developed project, there are inherent limitations:
- Security measures may not be comprehensive
- Edge cases might not be fully handled
- Performance optimizations may be basic
- Code structure reflects AI's current capabilities

## Educational Value

This project is valuable for:
- Studying AI-assisted development
- Learning about web server implementation
- Understanding security considerations
- Exploring test-driven development

## Development Notes

### AI Collaboration Process
- All code was written through interaction with AI
- Decisions were guided by AI suggestions
- Testing and validation were AI-assisted
- Documentation was AI-generated

### Technical Stack
- Language: C
- Build System: Make
- Testing: Shell scripts
- Platform: POSIX-compliant systems

## Contributing

While this is primarily an AI experiment, you can:
1. Study the AI-human collaboration process
2. Experiment with the codebase
3. Report findings about AI-generated code
4. Suggest improvements for future AI experiments

## Disclaimer

**WARNING**: This software is:
- An experimental project
- Developed entirely with AI assistance
- NOT security audited
- NOT suitable for production use
- For educational purposes ONLY

## License

MIT License - Feel free to study and learn from this experiment, but remember: DO NOT USE IN PRODUCTION!

## Acknowledgments

- Built with AI assistance
- Serves as a case study in AI-human collaboration
- Demonstrates current state of AI coding capabilities
