#include "rules.h"

#include <string.h>
#include <strings.h>     /* strcasecmp, strncasecmp */
#include <stdlib.h>
#include <stdio.h>
#include <fnmatch.h>
#include <arpa/inet.h>   /* inet_pton */
#include <netinet/in.h>  /* struct in_addr */
#include <libgen.h>      /* basename */
#include <ctype.h>       /* tolower */

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_match_domain
 *
 * Patterns:
 *   "*foo*"    — contains (both ends start/end with *)
 *   "*.foo.ch" — subdomain wildcard (also matches bare "foo.ch")
 *   "sky.ch"   — exact (case-insensitive)
 *   other      — fnmatch(FNM_CASEFOLD) fallback
 * ───────────────────────────────────────────────────────────────────────────── */
bool pf_match_domain(const char *pattern, const char *domain)
{
    if (!pattern || !domain) return false;

    size_t plen = strlen(pattern);
    size_t dlen = strlen(domain);

    /* Contains pattern: starts AND ends with '*', e.g. "*streaming*" */
    if (plen >= 2 && pattern[0] == '*' && pattern[plen - 1] == '*') {
        /* extract the inner needle */
        char needle[PF_DOMAIN_MAX + 1];
        size_t nlen = plen - 2;
        if (nlen == 0) return true;          /* "*" matches everything */
        if (nlen >= sizeof(needle)) return false;
        memcpy(needle, pattern + 1, nlen);
        needle[nlen] = '\0';
        /* case-insensitive substring search */
        if (dlen < nlen) return false;
        for (size_t i = 0; i <= dlen - nlen; i++) {
            if (strncasecmp(domain + i, needle, nlen) == 0) return true;
        }
        return false;
    }

    /* Subdomain wildcard: "*.foo.ch" */
    if (plen > 2 && pattern[0] == '*' && pattern[1] == '.') {
        const char *suffix = pattern + 1;   /* ".foo.ch" */
        size_t slen = plen - 1;

        /* Exact bare domain: "foo.ch" matches "*.foo.ch" */
        if (strcasecmp(domain, suffix + 1) == 0) return true;

        /* Subdomain: domain must end with the suffix */
        if (dlen > slen && strcasecmp(domain + dlen - slen, suffix) == 0) return true;

        return false;
    }

    /* Exact match (case-insensitive) — no wildcards */
    if (strchr(pattern, '*') == NULL && strchr(pattern, '?') == NULL)
        return strcasecmp(pattern, domain) == 0;

    /* Fallback: generic glob via fnmatch */
#ifdef FNM_CASEFOLD
    return fnmatch(pattern, domain, FNM_CASEFOLD) == 0;
#else
    /* Portable fallback: lowercase both and match */
    char lp[PF_DOMAIN_MAX + 1], ld[PF_DOMAIN_MAX + 1];
    size_t i;
    for (i = 0; i < plen && i < sizeof(lp) - 1; i++) lp[i] = (char)tolower((unsigned char)pattern[i]);
    lp[i] = '\0';
    for (i = 0; i < dlen && i < sizeof(ld) - 1; i++) ld[i] = (char)tolower((unsigned char)domain[i]);
    ld[i] = '\0';
    return fnmatch(lp, ld, 0) == 0;
#endif
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_match_app
 *
 * Patterns:
 *   "/usr/bin/firefox" — exact path
 *   "firefox"          — compare against basename(app_path) (no '/' in pattern)
 *   "/opt/google/x*"   — fnmatch()
 * ───────────────────────────────────────────────────────────────────────────── */
bool pf_match_app(const char *pattern, const char *app_path)
{
    if (!pattern || !app_path) return false;

    /* No '/' in pattern → compare against basename only */
    if (strchr(pattern, '/') == NULL) {
        /* We need a mutable copy for basename(3) which may modify the string */
        char tmp[PF_PATH_MAX];
        snprintf(tmp, sizeof(tmp), "%s", app_path);
        const char *base = basename(tmp);
        return strcmp(pattern, base) == 0;
    }

    /* Exact path or glob */
    if (strchr(pattern, '*') == NULL && strchr(pattern, '?') == NULL)
        return strcmp(pattern, app_path) == 0;

    return fnmatch(pattern, app_path, 0) == 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_match_ip  (IPv4 only)
 *
 * Patterns:
 *   "192.168.1.0/24"       — CIDR
 *   "10.0.0.1-10.0.0.255"  — range
 *   "1.2.3.4"              — exact
 * ───────────────────────────────────────────────────────────────────────────── */
bool pf_match_ip(const char *pattern, const char *ip)
{
    if (!pattern || !ip) return false;

    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) return false;
    uint32_t host_ip = ntohl(addr.s_addr);

    /* CIDR: contains '/' */
    const char *slash = strchr(pattern, '/');
    if (slash) {
        char net_str[48];
        size_t net_len = (size_t)(slash - pattern);
        if (net_len >= sizeof(net_str)) return false;
        memcpy(net_str, pattern, net_len);
        net_str[net_len] = '\0';

        int prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 32) return false;

        struct in_addr net_addr;
        if (inet_pton(AF_INET, net_str, &net_addr) != 1) return false;

        uint32_t mask = (prefix == 0) ? 0u : (~0u << (32 - prefix));
        return (host_ip & mask) == (ntohl(net_addr.s_addr) & mask);
    }

    /* Range: contains '-' */
    const char *dash = strchr(pattern, '-');
    if (dash) {
        char start_str[48], end_str[48];
        size_t start_len = (size_t)(dash - pattern);
        if (start_len >= sizeof(start_str)) return false;
        memcpy(start_str, pattern, start_len);
        start_str[start_len] = '\0';
        snprintf(end_str, sizeof(end_str), "%s", dash + 1);

        struct in_addr sa, ea;
        if (inet_pton(AF_INET, start_str, &sa) != 1) return false;
        if (inet_pton(AF_INET, end_str,   &ea) != 1) return false;

        uint32_t start_h = ntohl(sa.s_addr);
        uint32_t end_h   = ntohl(ea.s_addr);
        return host_ip >= start_h && host_ip <= end_h;
    }

    /* Exact match */
    struct in_addr pat_addr;
    if (inet_pton(AF_INET, pattern, &pat_addr) != 1) return false;
    return host_ip == ntohl(pat_addr.s_addr);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_match_port
 *
 * Patterns:
 *   ":443" or "443"         — exact
 *   ":8000-9000" or "8000-9000" — range
 * ───────────────────────────────────────────────────────────────────────────── */
bool pf_match_port(const char *pattern, int port)
{
    if (!pattern) return false;

    /* Skip optional leading ':' */
    const char *p = pattern;
    if (*p == ':') p++;

    const char *dash = strchr(p, '-');
    if (dash) {
        int lo = atoi(p);
        int hi = atoi(dash + 1);
        return port >= lo && port <= hi;
    }

    return port == atoi(p);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_rules_load
 * ───────────────────────────────────────────────────────────────────────────── */
int pf_rules_load(pf_ruleset_t *rs, pf_config_t *cfg)
{
    if (!rs || !cfg) return PF_ERR;
    rs->count = 0;
    return pf_config_rule_list(cfg, rs->rules, PF_MAX_RULES, &rs->count);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_rules_match
 *
 * Iterate rules in order (already sorted by priority ASC from DB).
 * A field is "don't care" when the rule's field is empty string / 0 (port).
 * ALL non-empty/nonzero conditions must match (AND logic).
 * First full match wins.
 * ───────────────────────────────────────────────────────────────────────────── */
const pf_rule_t *pf_rules_match(const pf_ruleset_t *rs,
                                 const char *app_path,
                                 const char *domain,
                                 const char *dst_ip,
                                 int         dst_port)
{
    if (!rs) return NULL;

    for (int i = 0; i < rs->count; i++) {
        const pf_rule_t *r = &rs->rules[i];

        if (!r->enabled) continue;

        /* Check each condition; skip if pattern field is empty/zero */
        if (r->app_path[0] != '\0') {
            if (!app_path || !pf_match_app(r->app_path, app_path)) continue;
        }
        if (r->domain[0] != '\0') {
            if (!domain || !pf_match_domain(r->domain, domain)) continue;
        }
        if (r->ip_cidr[0] != '\0') {
            if (!dst_ip || !pf_match_ip(r->ip_cidr, dst_ip)) continue;
        }
        if (r->dst_port != 0) {
            /* dst_port in pf_rule_t is a uint16_t integer (from DB INTEGER column) */
            if (dst_port != (int)r->dst_port) continue;
        }

        return r;
    }
    return NULL;
}
