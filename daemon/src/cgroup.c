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

/* Build the path for a rule's cgroup dir. rule_id must be positive — negative
 * values would produce `rule_-N` which still lives under PF_CGROUP_BASE so
 * there is no traversal, but rejecting early catches garbage early. */
static int rule_path(int rule_id, char *buf, size_t bufsz)
{
    if (rule_id <= 0) return -1;
    int n = snprintf(buf, bufsz, PF_CGROUP_BASE "/rule_%d", rule_id);
    if (n < 0 || (size_t)n >= bufsz) return -1;
    return 0;
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
    if (rule_path(rule_id, path, sizeof(path)) < 0) return PF_ERR;

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
    if (rule_path(rule_id, path, sizeof(path)) < 0) return PF_ERR;

    /* Try rmdir first — fast path when cgroup is empty */
    if (rmdir(path) == 0) return PF_OK;
    if (errno == ENOENT)  return PF_OK;
    if (errno != EBUSY && errno != ENOTEMPTY) {
        pf_log_error("cgroup: rmdir(%s) failed: %s", path, strerror(errno));
        return PF_ERR;
    }

    /* Cgroup still has PIDs — move them to the parent (base) cgroup so the
     * kernel lets us rmdir. Reading cgroup.procs and writing each PID to
     * PF_CGROUP_BASE/cgroup.procs is the documented v2 way to empty it. */
    char procs[PF_PATH_MAX];
    if (snprintf(procs, sizeof(procs), "%s/cgroup.procs", path) >= (int)sizeof(procs))
        return PF_ERR;

    FILE *fp = fopen(procs, "r");
    if (fp) {
        char pidbuf[32];
        while (fgets(pidbuf, sizeof(pidbuf), fp)) {
            /* trim newline */
            size_t l = strlen(pidbuf);
            if (l && pidbuf[l-1] == '\n') pidbuf[l-1] = '\0';
            if (pidbuf[0]) write_file(PF_CGROUP_BASE "/cgroup.procs", pidbuf);
        }
        fclose(fp);
    }

    if (rmdir(path) < 0 && errno != ENOENT) {
        pf_log_warn("cgroup: rmdir(%s) still failed after drain: %s",
                     path, strerror(errno));
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

    if (rule_path(rule_id, path, sizeof(path)) < 0) return PF_ERR;
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
 * pf_cgroup_assign_running_pids
 *
 * Scan /proc and assign every running PID whose /proc/N/exe target matches
 * app_pattern (full path OR basename) to rule_id's cgroup. Used when a rule
 * is added or re-enabled so apps already running (e.g. a Firefox window left
 * open by the user) get intercepted without needing to be restarted.
 * ───────────────────────────────────────────────────────────────────────────── */

#include "rules.h" /* for pf_match_app */

int pf_cgroup_assign_running_pids(int rule_id, const char *app_pattern)
{
    if (!app_pattern || !*app_pattern) return 0;

    DIR *proc = opendir("/proc");
    if (!proc) {
        pf_log_error("cgroup: opendir(/proc) failed: %s", strerror(errno));
        return 0;
    }

    int assigned = 0;
    struct dirent *ent;
    while ((ent = readdir(proc)) != NULL) {
        /* PID dirs are all-digits */
        const char *p = ent->d_name;
        if (!*p) continue;
        for (const char *c = p; *c; c++) if (*c < '0' || *c > '9') { p = NULL; break; }
        if (!p) continue;

        char exe_link[64], exe_path[PF_PATH_MAX];
        snprintf(exe_link, sizeof(exe_link), "/proc/%s/exe", ent->d_name);
        ssize_t n = readlink(exe_link, exe_path, sizeof(exe_path) - 1);
        if (n <= 0) continue;          /* kernel thread or permission denied */
        exe_path[n] = '\0';

        /* Try full path, then basename — mirrors on_process_event's
         * fallback logic so snap paths like /snap/firefox/X/.../firefox
         * match a rule configured as /snap/bin/firefox (the launcher). */
        if (!pf_match_app(app_pattern, exe_path)) {
            const char *base = strrchr(exe_path, '/');
            base = base ? base + 1 : exe_path;
            const char *pat_base = strrchr(app_pattern, '/');
            pat_base = pat_base ? pat_base + 1 : app_pattern;
            if (strcmp(base, pat_base) != 0) continue;
        }

        pid_t pid = (pid_t)atoi(ent->d_name);
        if (pf_cgroup_assign_pid(rule_id, pid) == PF_OK) assigned++;
    }
    closedir(proc);

    if (assigned > 0)
        pf_log_info("cgroup: assigned %d already-running PID(s) matching '%s' to rule_%d",
                    assigned, app_pattern, rule_id);
    return assigned;
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
