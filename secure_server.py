#!/usr/bin/env python3

import http.server
import socketserver
import os
import time
from typing import Union, Tuple, Optional, Dict
from http import HTTPStatus
from collections import defaultdict
import ssl

class RateLimiter:
    def __init__(self, requests_per_second: int = 10):
        self.requests_per_second = requests_per_second
        self.requests: Dict[str, list] = defaultdict(list)
    
    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        # Remove requests older than 1 second
        self.requests[client_ip] = [req_time for req_time in self.requests[client_ip] 
                                  if now - req_time < 1.0]
        
        # Check if client has exceeded rate limit
        if len(self.requests[client_ip]) >= self.requests_per_second:
            return False
        
        self.requests[client_ip].append(now)
        return True

class SecureHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    # Initialize rate limiter
    rate_limiter = RateLimiter(requests_per_second=10)
    
    def __init__(self, *args, **kwargs):
        self.request_count = 0
        super().__init__(*args, **kwargs)

    def do_GET(self) -> None:
        # Get client IP
        client_ip = self.client_address[0]
        
        # Apply rate limiting
        if not self.rate_limiter.is_allowed(client_ip):
            self.send_error(HTTPStatus.TOO_MANY_REQUESTS, "Rate limit exceeded")
            return

        # Prevent directory traversal
        if os.path.dirname(self.path) != '' or '..' in self.path:
            self.send_error(HTTPStatus.FORBIDDEN, "Directory traversal not allowed")
            self.log_error(f"Directory traversal attempt: {self.path}")
            return

        # Only allow specific file types
        allowed_extensions = {'.html', '.txt', '.css', '.js'}
        _, ext = os.path.splitext(self.path)
        if ext not in allowed_extensions:
            self.send_error(HTTPStatus.FORBIDDEN, "File type not allowed")
            self.log_error(f"Forbidden file type attempt: {self.path}")
            return

        # Add security headers
        self.send_response(HTTPStatus.OK)
        self.send_security_headers()
        
        return super().do_GET()

    def send_security_headers(self) -> None:
        """Add security-related headers to response"""
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Content-Security-Policy': "default-src 'self'",
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Pragma': 'no-cache',
            'Server': ''
        }
        for header, value in security_headers.items():
            self.send_header(header, value)

    # Disable all methods except GET
    def do_POST(self) -> None:
        self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)
        self.log_error(f"Blocked POST request from {self.client_address[0]}")

    def do_PUT(self) -> None:
        self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)
        self.log_error(f"Blocked PUT request from {self.client_address[0]}")

    def do_DELETE(self) -> None:
        self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)
        self.log_error(f"Blocked DELETE request from {self.client_address[0]}")

    def log_error(self, format: str, *args) -> None:
        """Override to provide more detailed error logging"""
        error_msg = f"{time.strftime('%Y-%m-%d %H:%M:%S')} - ERROR - {format%args}"
        with open('server_error.log', 'a') as f:
            f.write(error_msg + '\n')
        super().log_error(format, *args)

    def log_message(self, format: str, *args) -> None:
        """Override to provide more detailed access logging"""
        log_msg = f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {self.client_address[0]} - {format%args}"
        with open('server_access.log', 'a') as f:
            f.write(log_msg + '\n')
        super().log_message(format, *args)

def create_ssl_context() -> ssl.SSLContext:
    """Create SSL context for HTTPS"""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    # Generate self-signed certificate if needed:
    # openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
    return context

def run_server(port: int = 8000, use_ssl: bool = False) -> None:
    # Bind to localhost only
    host = "127.0.0.1"
    handler = SecureHTTPRequestHandler

    # Set maximum request header size
    handler.max_headers_size = 4096

    try:
        # Create server with IPv4 only
        server = socketserver.TCPServer((host, port), handler, bind_and_activate=False)
        server.allow_reuse_address = True  # Prevent "Address already in use" errors
        server.timeout = 30  # Set timeout for connections
        
        # Configure socket options
        server.socket.setsockopt(socketserver.SOL_SOCKET, socketserver.SO_KEEPALIVE, 1)
        
        if use_ssl:
            server.socket = create_ssl_context().wrap_socket(
                server.socket, server_side=True
            )
        
        server.server_bind()
        server.server_activate()
        
        protocol = "HTTPS" if use_ssl else "HTTP"
        print(f"Serving {protocol} on {host}:{port}")
        server.serve_forever()
        
    except PermissionError:
        print(f"Error: No permission to bind to port {port}")
        print("Try running with sudo for ports < 1024")
    except OSError as e:
        print(f"Error: Could not start server: {e}")
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.shutdown()
    finally:
        if 'server' in locals():
            server.server_close()

if __name__ == "__main__":
    # To enable HTTPS, set use_ssl=True and ensure you have cert.pem and key.pem files
    run_server(port=8000, use_ssl=False)