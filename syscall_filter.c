#include "syscall_filter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

static filter_config_t g_config;
static bool g_initialized = false;

/* Convert filter to BPF */
static struct sock_filter *create_filter_program(size_t *prog_len) {
    /* Basic structure:
     * 1. Validate architecture
     * 2. Load syscall number
     * 3. Compare against whitelist
     * 4. Apply default action
     */
    size_t len = 4 + (g_config.filter_count * 2);
    struct sock_filter *filter = calloc(len, sizeof(struct sock_filter));
    if (!filter) return NULL;

    size_t pos = 0;

    /* Validate architecture */
    filter[pos++] = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
        (offsetof(struct seccomp_data, arch)));
    filter[pos++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,
        AUDIT_ARCH_X86_64, 1, 0);
    filter[pos++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K,
        SECCOMP_RET_KILL);

    /* Load syscall number */
    filter[pos++] = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
        (offsetof(struct seccomp_data, nr)));

    /* Add filters */
    for (size_t i = 0; i < g_config.filter_count; i++) {
        syscall_filter_t *f = &g_config.filters[i];

        /* Compare syscall number */
        filter[pos++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,
            f->nr, 0, 1);

        /* Apply action */
        uint32_t action;
        switch (f->action) {
            case FILTER_ALLOW:
                action = SECCOMP_RET_ALLOW;
                break;
            case FILTER_DENY:
                action = g_config.kill_on_violation ?
                        SECCOMP_RET_KILL : SECCOMP_RET_ERRNO;
                break;
            case FILTER_LOG:
                action = SECCOMP_RET_LOG;
                break;
            default:
                action = SECCOMP_RET_KILL;
        }
        filter[pos++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, action);
    }

    /* Default action: kill process */
    filter[pos++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K,
        SECCOMP_RET_KILL);

    *prog_len = pos;
    return filter;
}

/* Initialize syscall filter */
bool syscall_filter_init(const filter_config_t *config) {
    if (g_initialized) return false;

    /* Copy configuration */
    g_config = *config;

    g_config.filters = calloc(config->filter_count, sizeof(syscall_filter_t));
    if (!g_config.filters) return false;

    for (size_t i = 0; i < config->filter_count; i++) {
        g_config.filters[i] = config->filters[i];
        if (config->filters[i].name) {
            g_config.filters[i].name = strdup(config->filters[i].name);
            if (!g_config.filters[i].name) {
                for (size_t j = 0; j < i; j++) {
                    free(g_config.filters[j].name);
                }
                free(g_config.filters);
                return false;
            }
        }
    }

    g_initialized = true;
    return true;
}

/* Enable syscall filtering */
bool syscall_filter_enable(void) {
    if (!g_initialized) return false;

    /* Create filter program */
    size_t prog_len;
    struct sock_filter *filter = create_filter_program(&prog_len);
    if (!filter) return false;

    /* Create filter structure */
    struct sock_fprog prog = {
        .len = prog_len,
        .filter = filter
    };

    /* Set no new privileges */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        free(filter);
        return false;
    }

    /* Enable seccomp filtering */
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        free(filter);
        return false;
    }

    free(filter);
    return true;
}