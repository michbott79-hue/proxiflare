#ifndef PF_DNS_RESOLVER_H
#define PF_DNS_RESOLVER_H

#include "proxiflare.h"
#include "config.h"

#define PF_DNS_RESOLVER_PORT        5353
#define PF_DNS_RESOLVER_DEFAULT_DOH "cloudflare-dns.com"

typedef struct pf_dns_resolver {
    int          udp_fd;        /* listening UDP socket (127.0.0.1:port) */
    int          port;          /* local bind port */
    pf_config_t *config;        /* read-only ref for proxy lookup */
    char         doh_host[128]; /* DoH server FQDN (default: dns.quad9.net) */
    int          doh_port;      /* always 443 */
} pf_dns_resolver_t;

/* Bind the UDP listener on 127.0.0.1:port. Does not start any thread by itself;
 * the main loop must dispatch incoming packets via pf_dns_resolver_process(). */
int  pf_dns_resolver_init(pf_dns_resolver_t *r, pf_config_t *config, int port);

/* Close the socket and free state. Safe to call on a partially-initialised r. */
void pf_dns_resolver_close(pf_dns_resolver_t *r);

/* Called from the main epoll loop when udp_fd is readable. Reads one UDP
 * packet and spawns a detached thread to handle it (DoH via proxy). */
int  pf_dns_resolver_process(pf_dns_resolver_t *r);

#endif /* PF_DNS_RESOLVER_H */
