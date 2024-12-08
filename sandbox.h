#ifndef SANDBOX_H
#define SANDBOX_H

#include <stdbool.h>
#include <sys/types.h>

/* Sandbox configuration */
typedef struct {
    uid_t uid;                  /* User ID to run as */
    gid_t gid;                  /* Group ID to run as */
    char *chroot_dir;           /* Chroot directory */
    char **allowed_paths;       /* Allowed paths */
    size_t path_count;
    bool no_new_privs;          /* Prevent privilege escalation */
    bool restrict_namespaces;   /* Use Linux namespaces */
} sandbox_config_t;

/* Function prototypes */
bool sandbox_init(const sandbox_config_t *config);
bool sandbox_enable(void);
void sandbox_cleanup(void);

#endif /* SANDBOX_H */