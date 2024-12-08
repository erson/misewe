/* ... previous includes ... */
#include "security.h"

/* Get client IP from socket */
static void get_client_ip(int client_fd, char *ip, size_t size) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(client_fd, (struct sockaddr*)&addr, &addr_len);
    inet_ntop(AF_INET, &addr.sin_addr, ip, size);
}

/* Handle client connection */
static void handle_client(server_t *server, int client_fd) {
    char client_ip[16];
    get_client_ip(client_fd, client_ip, sizeof(client_ip));

    /* Check rate limit */
    if (!check_rate_limit(client_ip)) {
        http_send_error(client_fd, 429, "Too Many Requests");
        log_error(client_ip, "Rate limit exceeded");
        return;
    }

    /* ... rest of request reading code ... */

    /* Parse request */
    http_request_t request;
    if (!http_parse_request(buffer, total_read, &request)) {
        http_send_error(client_fd, 400, "Bad request");
        log_error(client_ip, "Bad request format");
        return;
    }

    /* Security checks */
    if (!is_path_safe(request.path)) {
        http_send_error(client_fd, 403, "Forbidden");
        log_error(client_ip, "Invalid path requested");
        return;
    }

    /* Build file path */
    char file_path[1024];
    snprintf(file_path, sizeof(file_path), "%s/%s",
             server->root_dir,
             request.path[0] == '/' ? request.path + 1 : request.path);

    /* Open and send file */
    int fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        http_send_error(client_fd, 404, "Not Found");
        log_access(client_ip, "GET", request.path, 404);
        return;
    }

    /* ... rest of file handling code ... */

    /* Send response */
    http_response_t response = {
        .status_code = 200,
        .content_type = get_mime_type(file_path),
        .body = content,
        .body_length = size
    };

    http_send_response(client_fd, &response);
    log_access(client_ip, "GET", request.path, 200);
    free(content);
}