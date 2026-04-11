#include <stdio.h>
#include <string.h>
#include "proxiflare.h"

/* ──────────────────────────────────────────────────────────────────────────
 * String conversion helpers
 * ────────────────────────────────────────────────────────────────────────── */

const char *pf_proxy_type_str(pf_proxy_type_t t)
{
    switch (t) {
        case PF_PROXY_SOCKS4: return "socks4";
        case PF_PROXY_SOCKS5: return "socks5";
        case PF_PROXY_HTTP:   return "http";
        case PF_PROXY_SSH:    return "ssh";
        default:              return "unknown";
    }
}

const char *pf_health_str(pf_health_t h)
{
    switch (h) {
        case PF_HEALTH_UNKNOWN: return "unknown";
        case PF_HEALTH_ONLINE:  return "online";
        case PF_HEALTH_OFFLINE: return "offline";
        case PF_HEALTH_SLOW:    return "slow";
        case PF_HEALTH_ERROR:   return "error";
        default:                return "unknown";
    }
}

const char *pf_action_str(pf_action_t a)
{
    switch (a) {
        case PF_ACTION_DIRECT: return "direct";
        case PF_ACTION_PROXY:  return "proxy";
        case PF_ACTION_CHAIN:  return "chain";
        case PF_ACTION_BLOCK:  return "block";
        case PF_ACTION_REJECT: return "reject";
        default:               return "unknown";
    }
}

pf_proxy_type_t pf_proxy_type_from_str(const char *s)
{
    if (!s) return PF_PROXY_SOCKS5;
    if (strcmp(s, "socks4") == 0) return PF_PROXY_SOCKS4;
    if (strcmp(s, "socks5") == 0) return PF_PROXY_SOCKS5;
    if (strcmp(s, "http")   == 0) return PF_PROXY_HTTP;
    if (strcmp(s, "ssh")    == 0) return PF_PROXY_SSH;
    return PF_PROXY_SOCKS5; /* default */
}

pf_action_t pf_action_from_str(const char *s)
{
    if (!s) return PF_ACTION_DIRECT;
    if (strcmp(s, "direct") == 0) return PF_ACTION_DIRECT;
    if (strcmp(s, "proxy")  == 0) return PF_ACTION_PROXY;
    if (strcmp(s, "chain")  == 0) return PF_ACTION_CHAIN;
    if (strcmp(s, "block")  == 0) return PF_ACTION_BLOCK;
    if (strcmp(s, "reject") == 0) return PF_ACTION_REJECT;
    return PF_ACTION_DIRECT; /* default */
}

/* ──────────────────────────────────────────────────────────────────────────
 * Entry point
 * ────────────────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("ProxiFlare daemon v%s\n", PF_VERSION);
    return 0;
}
