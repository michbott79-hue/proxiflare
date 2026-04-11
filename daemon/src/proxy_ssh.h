#ifndef PF_PROXY_SSH_H
#define PF_PROXY_SSH_H

#include "proxiflare.h"
#include <libssh2.h>
#include <stdbool.h>

/* Single SSH session */
typedef struct {
    LIBSSH2_SESSION *session;
    int sock_fd;
    int proxy_id;
    bool connected;
} pf_ssh_session_t;

/* Pool of SSH sessions — one per SSH proxy, reused for multiple connections */
typedef struct {
    pf_ssh_session_t sessions[PF_MAX_PROXIES];
    int count;
} pf_ssh_pool_t;

/* Init/cleanup pool */
int pf_ssh_pool_init(pf_ssh_pool_t *pool);
void pf_ssh_pool_close(pf_ssh_pool_t *pool);

/* Get or create SSH session for a proxy */
pf_ssh_session_t *pf_ssh_get_session(pf_ssh_pool_t *pool, const pf_proxy_t *proxy);

/* Open a direct-tcpip channel through an SSH session to dst_host:dst_port.
   Returns a LIBSSH2_CHANNEL* that can be used for read/write, or NULL on error.
   The caller must call libssh2_channel_free() when done. */
LIBSSH2_CHANNEL *pf_ssh_connect(pf_ssh_pool_t *pool, const pf_proxy_t *proxy,
                                 const char *dst_host, int dst_port);

/* Get the underlying socket fd for a session (for epoll/select) */
int pf_ssh_get_fd(pf_ssh_session_t *sess);

/* Test SSH proxy — returns latency ms or -1 */
int pf_ssh_test(pf_ssh_pool_t *pool, const pf_proxy_t *proxy);

#endif /* PF_PROXY_SSH_H */
