#include "sandbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <linux/securebits.h>

static sandbox_config_t g_config;
static bool g_initialized = false;

/* Drop all capabilities */
static bool drop_capabilities(void) {
    cap_t caps = cap_init();
    if (!caps) return false;

    if (cap_set_proc(caps) < 0) {
        cap_free(caps);
        return false;
    }

    cap_free(caps);
    return true;
}

/* Set up mount namespace */
static bool setup_mount_namespace(void) {
    /* Make root read-only */
    if (mount(NULL, "/", NULL, MS_REMOUNT | MS_RDONLY, NULL) < 0) {
        return false;
    }

    /* Mount private /tmp */
    if (mount("none", "/tmp", "tmpfs",
             MS_NOSUID | MS_NODEV | MS_NOEXEC,
             "size=16M,mode=1777") < 0) {
        return false;
    }

    return true;
}

/* Initialize sandbox */
bool sandbox_init(const sandbox_config_t *config) {
    if (g_initialized) return false;

    /* Copy configuration */
    g_config = *config;
    g_config.chroot_dir = strdup(config->chroot_dir);
    if (!g_config.chroot_dir) return false;

    g_config.allowed_paths = calloc(config->path_count, sizeof(char*));
    if (!g_config.allowed_paths) {
        free(g_config.chroot_dir);
        return false;
    }

    for (size_t i = 0; i < config->path_count; i++) {
        g_config.allowed_paths[i] = strdup(config->allowed_paths[i]);
        if (!g_config.allowed_paths[i]) {
            for (size_t j = 0; j < i; j++) {
                free(g_config.allowed_paths[j]);
            }
            free(g_config.allowed_paths);
            free(g_config.chroot_dir);
            return false;
        }
    }

    g_initialized = true;
    return true;
}

/* Enable sandbox restrictions */
bool sandbox_enable(void) {
    if (!g_initialized) return false;

    /* Prevent privilege escalation */
    if (g_config.no_new_privs) {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
            return false;
        }
    }

    /* Set up mount namespace if requested */
    if (g_config.restrict_namespaces) {
        if (!setup_mount_namespace()) {
            return false;
        }
    }

    /* Change root directory */
    if (chdir(g_config.chroot_dir) < 0 ||
        chroot(g_config.chroot_dir) < 0) {
        return false;
    }

    /* Drop group privileges */
    if (setgroups(0, NULL) < 0 ||
        setgid(g_config.gid) < 0) {
        return false;
    }

    /* Drop user privileges */
    if (setuid(g_config.uid) < 0) {
        return false;
    }

    /* Drop capabilities */
    if (!drop_capabilities()) {
        return false;
    }

    return true;
}

/* Clean up sandbox */
void sandbox_cleanup(void) {
    if (!g_initialized) return;

    for (size_t i = 0; i < g_config.path_count; i++) {
        free(g_config.allowed_paths[i]);
    }
    free(g_config.allowed_paths);
    free(g_config.chroot_dir);

    g_initialized = false;
}