#ifndef PF_CGROUP_H
#define PF_CGROUP_H

#include "proxiflare.h"
#include <sys/types.h>

#define PF_CGROUP_BASE "/sys/fs/cgroup/proxiflare"

int  pf_cgroup_init(void);                    /* Create base hierarchy */
int  pf_cgroup_create_rule(int rule_id);      /* Create cgroup for rule */
int  pf_cgroup_remove_rule(int rule_id);
int  pf_cgroup_assign_pid(int rule_id, pid_t pid);
int  pf_cgroup_remove_pid(pid_t pid);         /* Remove from all proxiflare cgroups */

/* Scan /proc and assign all running processes whose exe path or basename
 * matches app_pattern to rule_id's cgroup. Returns the number of PIDs
 * assigned. Called when a rule is added/enabled so already-running apps
 * get intercepted without needing to re-exec. */
int  pf_cgroup_assign_running_pids(int rule_id, const char *app_pattern);
void pf_cgroup_cleanup(void);                 /* Remove entire hierarchy */

#endif /* PF_CGROUP_H */
