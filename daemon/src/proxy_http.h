#ifndef PF_PROXY_HTTP_H
#define PF_PROXY_HTTP_H

#include "proxiflare.h"

/* Connect through HTTP CONNECT proxy. Returns tunneled fd or -1 */
int pf_http_connect(const char *proxy_host, int proxy_port,
                    const char *dst_host, int dst_port,
                    const char *username, const char *password);

/* Test proxy — returns latency ms or -1 */
int pf_http_test(const pf_proxy_t *proxy);

#endif /* PF_PROXY_HTTP_H */
