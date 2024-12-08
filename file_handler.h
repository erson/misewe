#ifndef FILE_HANDLER_H
#define FILE_HANDLER_H

#include "http.h"
#include <stdbool.h>
#include <stddef.h>

/* File handler context */
typedef struct file_handler file_handler_t;

/* Function prototypes */
file_handler_t *file_handler_create(const char *root_dir);
void file_handler_destroy(file_handler_t *handler);
bool file_handler_serve(file_handler_t *handler, const char *path, int fd);

#endif /* FILE_HANDLER_H */