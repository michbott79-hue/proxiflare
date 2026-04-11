#include "cgroup.h"
#include "logger.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal helpers
 * ───────────────────────────────────────────────────────────────────────────── */

/* Write a string to a file, returns 0 on success, -1 on error */
static int write_file(const char *path, const char *data)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        pf_log_error("cgroup: open(%s) failed: %s", path, strerror(errno));
        return -1;
    }

    size_t  len = strlen(data);
    ssize_t w   = write(fd, data, len);
    close(fd);

    if (w < 0 || (size_t)w != len) {
        pf_log_error("cgroup: write(%s) failed: %s", path, strerror(errno));
        return -1;
    }
    return 0;
}

/* Build the path for a rule's cgroup dir */
static void rule_path(int rule_id, char *buf, size_t bufsz)
{
    snprintf(buf, bufsz, PF_CGROUP_BASE "/rule_%d", rule_id);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_cgroup_init
 *
 * Creates /sys/fs/cgroup/proxiflare and enables the cgroup.procs controller.
 * Requires the process to have write access to the cgroup hierarchy
 * (typically needs root or CAP_SYS_ADMIN).
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_cgroup_init(void)
{
    if (mkdir(PF_CGROUP_BASE, 0755) < 0 && errno != EEXIST) {
        pf_log_error("cgroup: mkdir(%s) failed: %s", PF_CGROUP_BASE, strerror(errno));
        return PF_ERR;
    }

    /* For cgroupv2 nftables socket matching, we only need the cgroup hierarchy
     * to exist — no controllers need to be enabled in subtree_control.
     * The nftables "socket cgroupv2" matcher works purely based on the
     * cgroup directory membership, not on any specific controller. */

    pf_log_info("cgroup: base hierarchy created at %s", PF_CGROUP_BASE);
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_cgroup_create_rule
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_cgroup_create_rule(int rule_id)
{
    char path[PF_PATH_MAX];
    rule_path(rule_id, path, sizeof(path));

    if (mkdir(path, 0755) < 0 && errno != EEXIST) {
        pf_log_error("cgroup: mkdir(%s) failed: %s", path, strerror(errno));
        return PF_ERR;
    }

    pf_log_info("cgroup: created rule cgroup %s", path);
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_cgroup_remove_rule
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_cgroup_remove_rule(int rule_id)
{
    char path[PF_PATH_MAX];
    rule_path(rule_id, path, sizeof(path));

    if (rmdir(path) < 0 && errno != ENOENT) {
        pf_log_error("cgroup: rmdir(%s) failed: %s", path, strerror(errno));
        return PF_ERR;
    }

    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_cgroup_assign_pid
 *
 * Writes the PID to the rule cgroup's cgroup.procs file.
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_cgroup_assign_pid(int rule_id, pid_t pid)
{
    char path[PF_PATH_MAX];
    char pidstr[32];

    rule_path(rule_id, path, sizeof(path));
    strncat(path, "/cgroup.procs", sizeof(path) - strlen(path) - 1);

    snprintf(pidstr, sizeof(pidstr), "%d", (int)pid);

    if (write_file(path, pidstr) < 0) {
        pf_log_error("cgroup: failed to assign pid %d to rule %d", (int)pid, rule_id);
        return PF_ERR;
    }

    pf_log_info("cgroup: assigned pid %d to rule_%d", (int)pid, rule_id);
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_cgroup_remove_pid
 *
 * Scans all rule_* cgroup dirs.  If the PID is found in cgroup.procs,
 * moves it to the parent (base) cgroup by writing PID to its cgroup.procs.
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_cgroup_remove_pid(pid_t pid)
{
    DIR *dir = opendir(PF_CGROUP_BASE);
    if (!dir) {
        pf_log_error("cgroup: opendir(%s) failed: %s", PF_CGROUP_BASE, strerror(errno));
        return PF_ERR;
    }

    char pidstr[32];
    snprintf(pidstr, sizeof(pidstr), "%d", (int)pid);

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strncmp(ent->d_name, "rule_", 5) != 0) continue;

        char procs_path[PF_PATH_MAX];
        snprintf(procs_path, sizeof(procs_path),
                 PF_CGROUP_BASE "/%s/cgroup.procs", ent->d_name);

        /* Read cgroup.procs to check if our PID is in it */
        int fd = open(procs_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;

        char buf[4096];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);

        if (n <= 0) continue;
        buf[n] = '\0';

        /* Search for the PID as a complete token */
        char *p = buf;
        while (*p) {
            char *end = p;
            while (*end && *end != '\n') end++;
            size_t toklen = (size_t)(end - p);
            if (toklen == strlen(pidstr) && memcmp(p, pidstr, toklen) == 0) {
                /* Found: move PID to parent cgroup */
                write_file(PF_CGROUP_BASE "/cgroup.procs", pidstr);
                closedir(dir);
                pf_log_info("cgroup: removed pid %d from %s", (int)pid, ent->d_name);
                return PF_OK;
            }
            p = (*end == '\n') ? end + 1 : end;
        }
    }

    closedir(dir);
    return PF_OK;  /* not found is not an error */
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_cgroup_cleanup
 *
 * Removes all rule_* subdirectories, then the base directory.
 * ───────────────────────────────────────────────────────────────────────────── */

void pf_cgroup_cleanup(void)
{
    DIR *dir = opendir(PF_CGROUP_BASE);
    if (!dir) return;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strncmp(ent->d_name, "rule_", 5) != 0) continue;

        char rule_dir[PF_PATH_MAX];
        snprintf(rule_dir, sizeof(rule_dir), PF_CGROUP_BASE "/%s", ent->d_name);
        rmdir(rule_dir);
    }

    closedir(dir);
    rmdir(PF_CGROUP_BASE);
    pf_log_info("cgroup: hierarchy removed");
}
