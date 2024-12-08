#ifndef SECURITY_HARDENING_H
#define SECURITY_HARDENING_H

#include <stdint.h>
#include <sys/types.h>

/* Security context for process hardening */
typedef struct {
    uid_t run_uid;              /* User ID to run as */
    gid_t run_gid;              /* Group ID to run as */
    char *chroot_dir;           /* Chroot directory */
    uint64_t memory_limit;      /* Maximum memory usage */
    uint64_t file_size_limit;   /* Maximum file size */
    int cpu_limit;              /* CPU usage limit % */
    char **allowed_syscalls;    /* Allowed syscalls for seccomp */
    size_t syscall_count;
} hardening_ctx_t;

/* Initialization flags */
typedef enum {
    HARDEN_CHROOT = 1 << 0,
    HARDEN_PRIVILEGES = 1 << 1,
    HARDEN_MEMORY = 1 << 2,
    HARDEN_SECCOMP = 1 << 3,
    HARDEN_NETWORK = 1 << 4,
    HARDEN_ALL = 0xFFFF
} harden_flags_t;

/* Function prototypes */
hardening_ctx_t *hardening_init(const char *config_path);
int harden_process(hardening_ctx_t *ctx, harden_flags_t flags);
int secure_memory_regions(void);
int setup_seccomp_filter(void);
int drop_privileges(uid_t uid, gid_t gid);
int secure_networking(void);
void hardening_cleanup(hardening_ctx_t *ctx);

#endif /* SECURITY_HARDENING_H */