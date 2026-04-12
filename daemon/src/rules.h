#ifndef PF_RULES_H
#define PF_RULES_H

#include <stdbool.h>
#include "proxiflare.h"
#include "config.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Ruleset — holds all rules sorted by priority (loaded from DB)
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    pf_rule_t rules[PF_MAX_RULES];
    int       count;
} pf_ruleset_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Load / match
 * ───────────────────────────────────────────────────────────────────────────── */

/* Populate ruleset from DB (rules already sorted by priority ASC). */
int pf_rules_load(pf_ruleset_t *rs, pf_config_t *cfg);

/*
 * Find the first enabled rule (by priority) that matches ALL non-empty criteria.
 * Fields may be NULL to mean "don't care".
 * Returns pointer into rs->rules[], or NULL if nothing matches (→ implicit DIRECT).
 */
const pf_rule_t *pf_rules_match(const pf_ruleset_t *rs,
                                 const char *app_path,
                                 const char *domain,
                                 const char *dst_ip,
                                 int         dst_port);

/*
 * Process-level match: returns the first enabled rule whose app_path matches,
 * IGNORING domain/ip/port filters. Used at exec() time to decide whether to
 * put a PID in the cgroup. Domain/IP/port filtering happens later in TPROXY.
 * Without this, a rule like app=firefox + domain=*.dazn.com would never put
 * firefox in the cgroup, so TPROXY would never see its traffic.
 */
const pf_rule_t *pf_rules_match_app_any(const pf_ruleset_t *rs,
                                         const char *app_path);

/* ─────────────────────────────────────────────────────────────────────────────
 * Individual pattern matchers (exported for unit testing)
 *
 * Domain patterns:
 *   "sky.ch"           — exact (case-insensitive)
 *   "*.sky.ch"         — subdomain wildcard; also matches bare "sky.ch"
 *   "*.ch"             — TLD wildcard
 *   "*streaming*"      — contains (starts AND ends with *)
 *   anything else      — fnmatch(FNM_CASEFOLD)
 *
 * App patterns:
 *   "/usr/bin/firefox" — exact path match
 *   "firefox"          — compare against basename(app_path)  (no '/')
 *   "/opt/google/x*"   — fnmatch()
 *
 * IP patterns (IPv4):
 *   "192.168.1.0/24"        — CIDR
 *   "10.0.0.1-10.0.0.255"   — range
 *   "1.2.3.4"               — exact
 *
 * Port patterns:
 *   "443" or ":443"         — exact
 *   "8000-9000" or ":8000-9000" — range
 * ───────────────────────────────────────────────────────────────────────────── */
bool pf_match_domain(const char *pattern, const char *domain);
bool pf_match_app   (const char *pattern, const char *app_path);
bool pf_match_ip    (const char *pattern, const char *ip);
bool pf_match_port  (const char *pattern, int port);

#endif /* PF_RULES_H */
