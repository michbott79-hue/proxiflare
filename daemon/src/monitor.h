#ifndef PF_MONITOR_H
#define PF_MONITOR_H

#include "proxiflare.h"
#include "rules.h"
#include <sys/types.h>
#include <stdbool.h>

typedef void (*pf_monitor_cb)(pid_t pid, const char *exe_path, bool is_exec, void *userdata);

typedef struct {
    int             nl_fd;      /* netlink socket */
    pf_monitor_cb   callback;
    void           *userdata;
} pf_monitor_t;

int  pf_monitor_init(pf_monitor_t *mon, pf_monitor_cb callback, void *userdata);
void pf_monitor_close(pf_monitor_t *mon);
int  pf_monitor_get_fd(pf_monitor_t *mon);
int  pf_monitor_process(pf_monitor_t *mon);   /* Call when fd readable */

/* Helper: read /proc/<pid>/exe */
int  pf_monitor_get_exe(pid_t pid, char *buf, size_t buf_len);

#endif /* PF_MONITOR_H */
