#ifndef PF_TPROXY_H
#define PF_TPROXY_H

#include "proxiflare.h"
#include <stdbool.h>

#define PF_TPROXY_PORT       12345
#define PF_MAX_CONNECTIONS   1024

/* Connection relay pair */
typedef struct {
    int      client_fd;
    int      proxy_fd;       /* fd connected through proxy to destination */
    char     domain[PF_DOMAIN_MAX];
    char     dst_ip[46];
    int      dst_port;
    int      proxy_id;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    bool     active;
} pf_connection_t;

/*
 * Callback for main.c to provide proxy connection.
 * Called after accept with (dst_ip, dst_port, domain, userdata).
 * Returns: connected fd (>= 0), -1 for direct (no proxy), -2 for block.
 */
typedef int (*pf_tproxy_connect_cb)(const char *dst_ip, int dst_port,
                                    const char *domain, void *userdata);

typedef struct {
    int                   listen_fd;
    int                   epoll_fd;
    pf_connection_t       conns[PF_MAX_CONNECTIONS];
    int                   conn_count;
    pf_tproxy_connect_cb  connect_cb;      /* proxy connector callback */
    void                 *connect_userdata; /* opaque context for callback */
} pf_tproxy_t;

int  pf_tproxy_init(pf_tproxy_t *tp, int port);
void pf_tproxy_close(pf_tproxy_t *tp);
int  pf_tproxy_get_fd(pf_tproxy_t *tp);
int  pf_tproxy_accept(pf_tproxy_t *tp);           /* Accept new redirected connection */
int  pf_tproxy_relay(pf_tproxy_t *tp, int conn_idx);  /* Relay data for a connection */
void pf_tproxy_close_conn(pf_tproxy_t *tp, int conn_idx);

/* Set the proxy connect callback (called from main.c after init) */
void pf_tproxy_set_connect_cb(pf_tproxy_t *tp, pf_tproxy_connect_cb cb, void *userdata);

#endif /* PF_TPROXY_H */
