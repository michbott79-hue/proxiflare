#ifndef PF_CHAIN_H
#define PF_CHAIN_H

#include "proxiflare.h"
#include "proxy_socks.h"
#include "proxy_http.h"
#include "proxy_ssh.h"

/* Connect to destination through a chain of proxies.
   proxies array must contain all proxy definitions (indexed by id).
   Returns connected fd or -1 on error.
   For SSH hops, the returned fd is from the SSH session's socket (channel-based I/O needed). */
int pf_chain_connect(const pf_chain_t *chain, const pf_proxy_t *proxies, int proxy_count,
                     const char *dst_host, int dst_port);

/* Test a chain end-to-end — returns total latency ms or -1 */
int pf_chain_test(const pf_chain_t *chain, const pf_proxy_t *proxies, int proxy_count);

#endif /* PF_CHAIN_H */
