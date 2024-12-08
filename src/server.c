/* Add this function to server.c */
static bool is_allowed_file_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return false;

    const char *allowed_exts[] = {
        ".html", ".css", ".js", ".txt", ".ico",
        NULL
    };

    for (const char **allowed = allowed_exts; *allowed; allowed++) {
        if (strcasecmp(ext, *allowed) == 0) {
            return true;
        }
    }

    return false;
}