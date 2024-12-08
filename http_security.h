#ifndef HTTP_SECURITY_H
#define HTTP_SECURITY_H

#include "http.h"

/* Security headers */
void add_security_headers(http_response_t *resp);

/* Response filtering */
void filter_response_content(http_response_t *resp);

/* Request validation */
bool validate_request_headers(const char *headers);
bool validate_request_body(const char *body, size_t length);

#endif /* HTTP_SECURITY_H */