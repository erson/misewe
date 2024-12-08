#include "mime_types.h"
#include <string.h>

static const struct {
    const char *ext;
    const char *type;
    int allowed;
} mime_types[] = {
    {".html", "text/html", 1},
    {".htm",  "text/html", 1},
    {".css",  "text/css", 1},
    {".js",   "application/javascript", 1},
    {".txt",  "text/plain", 1},
    {".ico",  "image/x-icon", 1},
    {".php",  "application/x-httpd-php", 0},
    {".cgi",  "application/x-httpd-cgi", 0},
    {".asp",  "application/x-asp", 0},
    {NULL,    "application/octet-stream", 0}
};

const char *get_mime_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";
    
    for (int i = 0; mime_types[i].ext; i++) {
        if (strcasecmp(ext, mime_types[i].ext) == 0) {
            return mime_types[i].type;
        }
    }
    
    return "application/octet-stream";
}

int is_allowed_file_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return 0;
    
    for (int i = 0; mime_types[i].ext; i++) {
        if (strcasecmp(ext, mime_types[i].ext) == 0) {
            return mime_types[i].allowed;
        }
    }
    
    return 0;
}