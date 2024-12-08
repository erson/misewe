#ifndef MIME_TYPES_H
#define MIME_TYPES_H

/* Get MIME type for file */
const char *get_mime_type(const char *path);

/* Check if file type is allowed */
int is_allowed_file_type(const char *path);

#endif /* MIME_TYPES_H */