#!/usr/bin/env python3

import http.server
import socketserver
import os
from typing import Union, Tuple, Optional
from http import HTTPStatus

class SecureHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    # Disable directory listings
    def do_GET(self) -> None:
        # Only serve files from current directory
        if os.path.dirname(self.path) != '':
            self.send_error(HTTPStatus.FORBIDDEN, "Directory traversal not allowed")
            return
            
        # Only allow specific file types
        allowed_extensions = {'.html', '.txt', '.css', '.js'}
        _, ext = os.path.splitext(self.path)
        if ext not in allowed_extensions:
            self.send_error(HTTPStatus.FORBIDDEN, "File type not allowed")
            return
            
        return super().do_GET()
    
    # Disable all methods except GET
    def do_POST(self) -> None:
        self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)
    
    def do_PUT(self) -> None:
        self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)
        
    def do_DELETE(self) -> None:
        self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)
    
    # Remove server information from headers
    def version_string(self) -> str:
        return ""
    
    def send_response(self, code: int, message: Optional[str] = None) -> None:
        self.send_response_only(code, message)
        self.send_header('Server', '')
        self.send_header('Date', self.date_time_string())

def run_server(port: int = 8000) -> None:
    # Bind to localhost only
    host = "127.0.0.1"
    
    handler = SecureHTTPRequestHandler
    
    # Set maximum request header size
    handler.max_headers_size = 4096
    
    try:
        with socketserver.TCPServer((host, port), handler) as httpd:
            print(f"Serving on {host}:{port}")
            # Set timeout for connections
            httpd.timeout = 30
            httpd.serve_forever()
    except PermissionError:
        print(f"Error: No permission to bind to port {port}")
        print("Try running with sudo for ports < 1024")
    except OSError as e:
        print(f"Error: Could not start server: {e}")

if __name__ == "__main__":
    run_server()