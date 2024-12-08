#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/capability.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include "security_hardening.h"
#include "logger.h"

/* Seccomp BPF helpers */
#define syscall_nr (offsetof(struct seccomp_data, nr))
#define ALLOW_SYSCALL(name) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

/* Initialize hardening context */
hardening_ctx_t *hardening_init(const char *config_path) {
    hardening_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        ERROR_LOG("Failed to allocate hardening context");
        return NULL;
    }

    /* Set secure defaults */
    ctx->run_uid = 65534;  /* nobody */
    ctx->run_gid = 65534;  /* nobody */
    ctx->memory_limit = 100 * 1024 * 1024;  /* 100MB */
    ctx->file_size_limit = 10 * 1024 * 1024;  /* 10MB */
    ctx->cpu_limit = 50;  /* 50% CPU */

    /* Load configuration if provided */
    if (config_path) {
        /* TODO: Implement config loading */
    }

    return ctx;
}

/* Set up seccomp-bpf filter */
static int setup_seccomp_bpf(void) {
    struct sock_filter filter[] = {
        /* Validate architecture */
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 
                (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

        /* Load syscall number */
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),

        /* Allow specific syscalls */
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(open),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(fstat),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(mprotect),
        ALLOW_SYSCALL(munmap),
        ALLOW_SYSCALL(exit),
        ALLOW_SYSCALL(exit_group),

        /* Deny everything else */
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        ERROR_LOG("Failed to set no new privs: %s", strerror(errno));
        return -1;
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        ERROR_LOG("Failed to set seccomp filter: %s", strerror(errno));
        return -1;
    }

    return 0;
}

/* Secure memory regions */
int secure_memory_regions(void) {
    /* Disable core dumps */
    if (prctl(PR_SET_DUMPABLE, 0) < 0) {
        ERROR_LOG("Failed to disable core dumps: %s", strerror(errno));
        return -1;
    }

    /* Lock memory to prevent swapping */
    if (mlockall(MCL_CURRENT | MCL_FUTURE) < 0) {
        ERROR_LOG("Failed to lock memory: %s", strerror(errno));
        return -1;
    }

    /* Set strict memory protections */
    if (prctl(PR_SET_MMAP_MIN_ADDR, 65536) < 0) {
        ERROR_LOG("Failed to set MMAP_MIN_ADDR: %s", strerror(errno));
        return -1;
    }

    return 0;
}

/* Drop privileges */
int drop_privileges(uid_t uid, gid_t gid) {
    /* Remove all capabilities */
    cap_t caps = cap_init();
    if (!caps) {
        ERROR_LOG("Failed to initialize capabilities: %s", strerror(errno));
        return -1;
    }
    if (cap_set_proc(caps) < 0) {
        ERROR_LOG("Failed to set capabilities: %s", strerror(errno));
        cap_free(caps);
        return -1;
    }
    cap_free(caps);

    /* Set resource limits */
    struct rlimit limit;
    limit.rlim_cur = limit.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &limit) < 0) {
        ERROR_LOG("Failed to set core limit: %s", strerror(errno));
        return -1;
    }

    /* Drop supplementary groups */
    if (setgroups(0, NULL) < 0) {
        ERROR_LOG("Failed to drop groups: %s", strerror(errno));
        return -1;
    }

    /* Set strict umask */
    umask(0077);

    /* Change GID and UID */
    if (setgid(gid) < 0 || setuid(uid) < 0) {
        ERROR_LOG("Failed to drop privileges: %s", strerror(errno));
        return -1;
    }

    /* Verify privileges were dropped */
    if (getuid() != uid || geteuid() != uid ||
        getgid() != gid || getegid() != gid) {
        ERROR_LOG("Failed to verify privilege drop");
        return -1;
    }

    return 0;
}

/* Set up secure networking */
int secure_networking(void) {
    /* Disable IPv6 if not needed */
    if (system("echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6") != 0) {
        WARN_LOG("Failed to disable IPv6");
    }

    /* Set strict TCP parameters */
    if (system("sysctl -w net.ipv4.tcp_syncookies=1") != 0 ||
        system("sysctl -w net.ipv4.tcp_max_syn_backlog=2048") != 0 ||
        system("sysctl -w net.ipv4.tcp_synack_retries=2") != 0 ||
        system("sysctl -w net.ipv4.tcp_syn_retries=2") != 0) {
        WARN_LOG("Failed to set TCP parameters");
    }

    return 0;
}

/* Apply all hardening measures */
int harden_process(hardening_ctx_t *ctx, harden_flags_t flags) {
    if (!ctx) return -1;

    if (flags & HARDEN_PRIVILEGES) {
        if (drop_privileges(ctx->run_uid, ctx->run_gid) < 0) {
            ERROR_LOG("Failed to drop privileges");
            return -1;
        }
    }

    if (flags & HARDEN_MEMORY) {
        if (secure_memory_regions() < 0) {
            ERROR_LOG("Failed to secure memory regions");
            return -1;
        }
    }

    if (flags & HARDEN_SECCOMP) {
        if (setup_seccomp_bpf() < 0) {
            ERROR_LOG("Failed to set up seccomp filter");
            return -1;
        }
    }

    if (flags & HARDEN_NETWORK) {
        if (secure_networking() < 0) {
            ERROR_LOG("Failed to secure networking");
            return -1;
        }
    }

    return 0;
}

/* Clean up hardening context */
void hardening_cleanup(hardening_ctx_t *ctx) {
    if (!ctx) return;
    free(ctx->chroot_dir);
    free(ctx->allowed_syscalls);
    free(ctx);
}