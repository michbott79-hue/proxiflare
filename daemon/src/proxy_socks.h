#ifndef PF_PROXY_SOCKS_H
#define PF_PROXY_SOCKS_H

#include "proxiflare.h"

/* Connect through SOCKS4/4a proxy. Returns connected fd or -1 */
int pf_socks4_connect(const char *proxy_host, int proxy_port,
                      const char *dst_host, int dst_port,
                      const char *userid);

/* Connect through SOCKS5 proxy. Returns connected fd or -1 */
int pf_socks5_connect(const char *proxy_host, int proxy_port,
                      const char *dst_host, int dst_port,
                      const char *username, const char *password);

/* Test proxy connectivity — returns latency in ms or -1 */
int pf_socks_test(const pf_proxy_t *proxy);

#endif /* PF_PROXY_SOCKS_H */
