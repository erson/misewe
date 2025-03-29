# Changelog

All notable changes to the Misewe project will be documented in this file.

## [1.1.0] - 2025-03-30

### Added
- MIME type detection for proper Content-Type headers
- ETag generation for improved caching
- Cache-Control headers (86400s for ETag resources, 3600s for others)
- Automatic rate limiter unblocking after a timeout period
- Comprehensive test protocol in test-improved.sh
- TEST.md documentation for testing procedures
- Enhanced documentation with improved code comments

### Changed
- Improved HTTP header formatting
- Better handling of HEAD requests
- Enhanced directory index handling
- Optimized path processing logic
- Rate limiter now bypasses localhost (127.0.0.1) for testing
- Updated README with latest features and improvements

### Fixed
- Fixed HTTP header formatting issues
- Corrected path handling for directory indexes
- Improved error handling for file paths
- Fixed potential memory leaks in ETag handling

## [1.0.0] - Initial Release

### Added
- Basic HTTP server functionality
- File serving capability
- Rate limiting based on client IP
- Simple security features
- Path traversal prevention
- File type restrictions
