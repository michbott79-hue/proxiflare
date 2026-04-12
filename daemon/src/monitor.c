#include "monitor.h"
#include "logger.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <linux/netlink.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * NETLINK_CONNECTOR message helpers
 * ───────────────────────────────────────────────────────────────────────────── */

/* Total buffer needed for a connector message with payload of size N */
#define CN_MSG_SIZE(n) (NLMSG_SPACE(sizeof(struct cn_msg) + (n)))

/* Build and send the PROC_CN_MCAST_LISTEN subscription message */
static int proc_cn_subscribe(int nl_fd)
{
    char buf[CN_MSG_SIZE(sizeof(enum proc_cn_mcast_op))] __attribute__((aligned(NLMSG_ALIGNTO)));
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nl = (struct nlmsghdr *)buf;
    nl->nlmsg_len   = sizeof(buf);
    nl->nlmsg_type  = NLMSG_DONE;
    nl->nlmsg_flags = 0;
    nl->nlmsg_seq   = 0;
    nl->nlmsg_pid   = (uint32_t)getpid();

    struct cn_msg *cm = (struct cn_msg *)NLMSG_DATA(nl);
    cm->id.idx = CN_IDX_PROC;
    cm->id.val = CN_VAL_PROC;
    cm->seq    = 0;
    cm->ack    = 0;
    cm->len    = sizeof(enum proc_cn_mcast_op);

    enum proc_cn_mcast_op *op = (enum proc_cn_mcast_op *)(cm + 1);
    *op = PROC_CN_MCAST_LISTEN;

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        .nl_pid    = 0,
        .nl_groups = 0,
    };

    if (sendto(nl_fd, buf, sizeof(buf), 0,
               (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        pf_log_error("monitor: sendto(PROC_CN_MCAST_LISTEN) failed: %s",
                     strerror(errno));
        return -1;
    }

    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_monitor_init
 *
 * Creates a NETLINK_CONNECTOR socket, binds with CN_IDX_PROC multicast group,
 * and sends PROC_CN_MCAST_LISTEN to start receiving process events.
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_monitor_init(pf_monitor_t *mon, pf_monitor_cb callback, void *userdata)
{
    if (!mon || !callback) return PF_ERR;

    memset(mon, 0, sizeof(*mon));
    mon->nl_fd    = -1;
    mon->callback = callback;
    mon->userdata = userdata;

    int fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (fd < 0) {
        pf_log_error("monitor: socket(NETLINK_CONNECTOR) failed: %s", strerror(errno));
        return PF_ERR_NET;
    }

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        .nl_pid    = (uint32_t)getpid(),
        .nl_groups = CN_IDX_PROC,
    };

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        pf_log_error("monitor: bind(NETLINK_CONNECTOR) failed: %s", strerror(errno));
        close(fd);
        return PF_ERR_NET;
    }

    if (proc_cn_subscribe(fd) < 0) {
        close(fd);
        return PF_ERR_NET;
    }

    mon->nl_fd = fd;
    pf_log_info("monitor: proc connector active (NETLINK_CONNECTOR, CN_IDX_PROC)");
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_monitor_close
 * ───────────────────────────────────────────────────────────────────────────── */

void pf_monitor_close(pf_monitor_t *mon)
{
    if (!mon) return;

    if (mon->nl_fd >= 0) {
        close(mon->nl_fd);
        mon->nl_fd = -1;
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_monitor_get_fd
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_monitor_get_fd(pf_monitor_t *mon)
{
    return mon ? mon->nl_fd : -1;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_monitor_get_exe
 *
 * Reads /proc/<pid>/exe via readlink.
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_monitor_get_exe(pid_t pid, char *buf, size_t buf_len)
{
    if (!buf || buf_len == 0) return -1;

    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", (int)pid);

    ssize_t n = readlink(proc_path, buf, buf_len - 1);
    if (n < 0) {
        buf[0] = '\0';
        return -1;
    }

    buf[n] = '\0';
    return (int)n;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_monitor_process
 *
 * Reads one netlink message from the connector socket and dispatches proc
 * events to the callback.  Should be called when nl_fd is readable.
 *
 * We handle:
 *   PROC_EVENT_EXEC  — new process exec'd (is_exec=true)
 *   PROC_EVENT_EXIT  — process exited  (is_exec=false)
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_monitor_process(pf_monitor_t *mon)
{
    if (!mon || mon->nl_fd < 0) return PF_ERR;

    /* Buffer large enough for the netlink + cn_msg + proc_event */
    char buf[4096] __attribute__((aligned(NLMSG_ALIGNTO)));

    ssize_t n = recv(mon->nl_fd, buf, sizeof(buf), 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return PF_OK;
        pf_log_error("monitor: recv() failed: %s", strerror(errno));
        return PF_ERR_NET;
    }

    /* Walk all netlink messages in the datagram */
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

    for (; NLMSG_OK(nlh, (unsigned int)n); nlh = NLMSG_NEXT(nlh, n)) {
        if (nlh->nlmsg_type == NLMSG_ERROR || nlh->nlmsg_type == NLMSG_NOOP)
            continue;

        /* Only trust messages from the kernel (pid 0). A malicious local
         * process could unicast a crafted netlink datagram to our socket; in
         * practice Linux won't deliver user-origin connector messages on
         * NETLINK_CONNECTOR, but defense-in-depth. */
        if (nlh->nlmsg_pid != 0)
            continue;

        if ((size_t)NLMSG_PAYLOAD(nlh, 0) < sizeof(struct cn_msg))
            continue;

        struct cn_msg    *cm = (struct cn_msg *)NLMSG_DATA(nlh);
        struct proc_event *ev = (struct proc_event *)(cm + 1);

        if (cm->id.idx != CN_IDX_PROC || cm->id.val != CN_VAL_PROC)
            continue;

        if (cm->len < sizeof(struct proc_event))
            continue;

        pid_t  pid    = 0;
        bool   is_exec = false;

        switch (ev->what) {
        case PROC_EVENT_EXEC:
            pid     = ev->event_data.exec.process_pid;
            is_exec = true;
            break;

        case PROC_EVENT_EXIT:
            pid     = ev->event_data.exit.process_pid;
            is_exec = false;
            break;

        default:
            continue;
        }

        if (pid <= 0) continue;

        char exe_path[PF_PATH_MAX] = {0};
        if (is_exec) {
            /* Resolve exe path — may fail if process already exited */
            pf_monitor_get_exe(pid, exe_path, sizeof(exe_path));
        }

        mon->callback(pid, exe_path, is_exec, mon->userdata);
    }

    return PF_OK;
}
