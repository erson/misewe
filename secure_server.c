#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <ctype.h>
#include <limits.h>

#define PORT 8000
#define BUFFER_SIZE 4096
#define MAX_REQUESTS_PER_SEC 10
#define MAX_CLIENTS 1000
#define TIMEOUT_SECONDS 30
#define MAX_PATH_LENGTH 256

// Rate limiting structure
typedef struct {
    char ip[INET_ADDRSTRLEN];
    time_t requests[MAX_REQUESTS_PER_SEC];
    int count;
} RateLimit;

// Global variables
static volatile int keep_running = 1;
static RateLimit rate_limits[MAX_CLIENTS];
static int rate_limit_count = 0;

// Function prototypes
void handle_signal(int sig);
int setup_server(void);
void handle_client(int client_sock, struct sockaddr_in client_addr);
int check_rate_limit(const char* ip);
int is_allowed_file_type(const char* path);
void send_error(int client_sock, int status_code, const char* message);
void send_response(int client_sock, const char* content_type, const char* body, size_t body_len);
void log_message(const char* format, ...);
int sanitize_path(char* path);

// Signal handler for graceful shutdown
void handle_signal(int sig) {
    keep_running = 0;
}

// Check if file type is allowed
int is_allowed_file_type(const char* path) {
    const char* allowed_extensions[] = {".html", ".txt", ".css", ".js"};
    const char* ext = strrchr(path, '.');
    if (!ext) return 0;
    
    for (size_t i = 0; i < sizeof(allowed_extensions) / sizeof(allowed_extensions[0]); i++) {
        if (strcmp(ext, allowed_extensions[i]) == 0) return 1;
    }
    return 0;
}

// Rate limiting implementation
int check_rate_limit(const char* ip) {
    time_t current_time = time(NULL);
    int i;
    
    // Find or create rate limit entry
    for (i = 0; i < rate_limit_count; i++) {
        if (strcmp(rate_limits[i].ip, ip) == 0) {
            // Remove old requests
            int valid_count = 0;
            for (int j = 0; j < rate_limits[i].count; j++) {
                if (current_time - rate_limits[i].requests[j] < 1) {
                    rate_limits[i].requests[valid_count++] = rate_limits[i].requests[j];
                }
            }
            rate_limits[i].count = valid_count;
            
            // Check if limit exceeded
            if (rate_limits[i].count >= MAX_REQUESTS_PER_SEC) {
                return 0;
            }
            
            // Add new request
            rate_limits[i].requests[rate_limits[i].count++] = current_time;
            return 1;
        }
    }
    
    // Add new IP if not found
    if (rate_limit_count < MAX_CLIENTS) {
        strncpy(rate_limits[rate_limit_count].ip, ip, INET_ADDRSTRLEN);
        rate_limits[rate_limit_count].count = 1;
        rate_limits[rate_limit_count].requests[0] = current_time;
        rate_limit_count++;
        return 1;
    }
    
    return 0;
}

// Sanitize and validate path
int sanitize_path(char* path) {
    char* ptr = path;
    
    // Remove leading /
    if (*ptr == '/') ptr++;
    
    // Check for directory traversal attempts
    if (strstr(ptr, "..") != NULL) return 0;
    
    // Check path length
    if (strlen(ptr) > MAX_PATH_LENGTH) return 0;
    
    // Only allow alphanumeric chars, -, _, ., and /
    while (*ptr) {
        if (!isalnum(*ptr) && *ptr != '-' && *ptr != '_' && 
            *ptr != '.' && *ptr != '/') {
            return 0;
        }
        ptr++;
    }
    
    return 1;
}

// Send HTTP error response
void send_error(int client_sock, int status_code, const char* message) {
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: text/plain\r\n"
             "Connection: close\r\n"
             "Server: \r\n"
             "\r\n"
             "Error: %s",
             status_code, message, message);
    write(client_sock, response, strlen(response));
}

// Send HTTP response
void send_response(int client_sock, const char* content_type, const char* body, size_t body_len) {
    char header[BUFFER_SIZE];
    snprintf(header, sizeof(header),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "Server: \r\n"
             "X-Content-Type-Options: nosniff\r\n"
             "X-Frame-Options: DENY\r\n"
             "X-XSS-Protection: 1; mode=block\r\n"
             "Content-Security-Policy: default-src 'self'\r\n"
             "\r\n",
             content_type, body_len);
    
    write(client_sock, header, strlen(header));
    write(client_sock, body, body_len);
}

// Handle client connection
void handle_client(int client_sock, struct sockaddr_in client_addr) {
    char buffer[BUFFER_SIZE];
    char client_ip[INET_ADDRSTRLEN];
    ssize_t bytes_read;
    
    // Get client IP
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    
    // Check rate limit
    if (!check_rate_limit(client_ip)) {
        send_error(client_sock, 429, "Too Many Requests");
        return;
    }
    
    // Read request
    bytes_read = read(client_sock, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0) return;
    buffer[bytes_read] = '\0';
    
    // Parse request line
    char method[16], path[MAX_PATH_LENGTH], protocol[16];
    if (sscanf(buffer, "%15s %255s %15s", method, path, protocol) != 3) {
        send_error(client_sock, 400, "Bad Request");
        return;
    }
    
    // Only allow GET method
    if (strcmp(method, "GET") != 0) {
        send_error(client_sock, 405, "Method Not Allowed");
        return;
    }
    
    // Sanitize and validate path
    if (!sanitize_path(path)) {
        send_error(client_sock, 403, "Forbidden");
        return;
    }
    
    // Check file type
    if (!is_allowed_file_type(path)) {
        send_error(client_sock, 403, "File type not allowed");
        return;
    }
    
    // Open and send file
    int fd = open(path + 1, O_RDONLY);  // +1 to skip leading /
    if (fd < 0) {
        send_error(client_sock, 404, "Not Found");
        return;
    }
    
    // Get file size
    struct stat st;
    fstat(fd, &st);
    
    // Read and send file
    char* file_buffer = malloc(st.st_size);
    if (!file_buffer) {
        send_error(client_sock, 500, "Internal Server Error");
        close(fd);
        return;
    }
    
    read(fd, file_buffer, st.st_size);
    
    // Determine content type
    const char* content_type = "text/plain";
    if (strstr(path, ".html")) content_type = "text/html";
    else if (strstr(path, ".css")) content_type = "text/css";
    else if (strstr(path, ".js")) content_type = "application/javascript";
    
    send_response(client_sock, content_type, file_buffer, st.st_size);
    
    free(file_buffer);
    close(fd);
}

// Set up server socket
int setup_server(void) {
    int server_sock;
    struct sockaddr_in server_addr;
    int opt = 1;
    
    // Create socket
    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // Set socket options
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }
    
    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");  // localhost only
    server_addr.sin_port = htons(PORT);
    
    // Bind socket
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    
    // Listen for connections
    if (listen(server_sock, 10) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    
    return server_sock;
}

int main(void) {
    int server_sock, client_sock;
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    struct timeval timeout;
    
    // Set up signal handler
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // Initialize server
    server_sock = setup_server();
    printf("Server running on port %d\n", PORT);
    
    // Set timeout
    timeout.tv_sec = TIMEOUT_SECONDS;
    timeout.tv_usec = 0;
    
    while (keep_running) {
        // Accept connection
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addr_len);
        if (client_sock < 0) {
            if (errno == EINTR) continue;  // Interrupted system call
            perror("Accept failed");
            continue;
        }
        
        // Set socket timeout
        if (setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            perror("Set receive timeout failed");
        }
        if (setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
            perror("Set send timeout failed");
        }
        
        // Handle client
        handle_client(client_sock, client_addr);
        close(client_sock);
    }
    
    // Cleanup
    close(server_sock);
    printf("\nServer shutdown complete\n");
    
    return 0;
}