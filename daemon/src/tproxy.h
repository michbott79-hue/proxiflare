#ifndef PF_TPROXY_H
#define PF_TPROXY_H

#include "proxiflare.h"
#include <stdbool.h>

#define PF_TPROXY_PORT       12345
#define PF_MAX_CONNECTIONS   1024

/* Connection relay pair */
typedef struct {
    int      client_fd;
    int      proxy_fd;
    char     domain[PF_DOMAIN_MAX];
    char     dst_ip[46];
    int      dst_port;
    int      proxy_id;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    bool     active;
} pf_connection_t;

typedef struct {
    int              listen_fd;
    int              epoll_fd;
    pf_connection_t  conns[PF_MAX_CONNECTIONS];
    int              conn_count;
} pf_tproxy_t;

int  pf_tproxy_init(pf_tproxy_t *tp, int port);
void pf_tproxy_close(pf_tproxy_t *tp);
int  pf_tproxy_get_fd(pf_tproxy_t *tp);
int  pf_tproxy_accept(pf_tproxy_t *tp);           /* Accept new redirected connection */
int  pf_tproxy_relay(pf_tproxy_t *tp, int conn_idx);  /* Relay data for a connection */
void pf_tproxy_close_conn(pf_tproxy_t *tp, int conn_idx);

#endif /* PF_TPROXY_H */
