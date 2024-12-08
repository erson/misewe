#ifndef SYSCALL_FILTER_H
#define SYSCALL_FILTER_H

#include <stdbool.h>
#include <linux/seccomp.h>

/* Filter action */
typedef enum {
    FILTER_ALLOW,
    FILTER_DENY,
    FILTER_LOG
} filter_action_t;

/* Syscall filter */
typedef struct {
    unsigned int nr;           /* Syscall number */
    filter_action_t action;    /* Action to take */
    char *name;               /* Syscall name (for logging) */
} syscall_filter_t;

/* Filter configuration */
typedef struct {
    syscall_filter_t *filters;
    size_t filter_count;
    bool log_violations;
    bool kill_on_violation;
} filter_config_t;

/* Function prototypes */
bool syscall_filter_init(const filter_config_t *config);
bool syscall_filter_enable(void);

#endif /* SYSCALL_FILTER_H */