#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* String helpers — duplicated so we don't need to link main.c */
#include "proxiflare.h"
#include "rules.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * String helpers required by config.c / rules.c
 * ───────────────────────────────────────────────────────────────────────────── */
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
    return PF_PROXY_SOCKS5;
}
pf_action_t pf_action_from_str(const char *s)
{
    if (!s) return PF_ACTION_DIRECT;
    if (strcmp(s, "direct") == 0) return PF_ACTION_DIRECT;
    if (strcmp(s, "proxy")  == 0) return PF_ACTION_PROXY;
    if (strcmp(s, "chain")  == 0) return PF_ACTION_CHAIN;
    if (strcmp(s, "block")  == 0) return PF_ACTION_BLOCK;
    if (strcmp(s, "reject") == 0) return PF_ACTION_REJECT;
    return PF_ACTION_DIRECT;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Helper: build a pf_ruleset_t from an array of inline rules (no DB needed)
 * Returns heap-allocated ruleset; caller must free().
 * ───────────────────────────────────────────────────────────────────────────── */
static pf_ruleset_t *make_ruleset(const pf_rule_t *rules, int count)
{
    pf_ruleset_t *rs = calloc(1, sizeof(pf_ruleset_t));
    assert(rs != NULL);
    rs->count = count;
    for (int i = 0; i < count; i++) rs->rules[i] = rules[i];
    return rs;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test: pf_match_domain
 * ───────────────────────────────────────────────────────────────────────────── */
static void test_domain(void)
{
    printf("  domain: exact ...\n");
    assert(pf_match_domain("sky.ch", "sky.ch")    == true);
    assert(pf_match_domain("sky.ch", "SKY.CH")    == true);   /* case-insensitive */
    assert(pf_match_domain("SKY.CH", "sky.ch")    == true);
    assert(pf_match_domain("sky.ch", "notsky.ch") == false);
    assert(pf_match_domain("sky.ch", "sky.com")   == false);

    printf("  domain: subdomain wildcard *.sky.ch ...\n");
    assert(pf_match_domain("*.sky.ch", "api.sky.ch")   == true);
    assert(pf_match_domain("*.sky.ch", "sky.ch")       == true);   /* bare domain */
    assert(pf_match_domain("*.sky.ch", "other.ch")     == false);
    assert(pf_match_domain("*.sky.ch", "notsky.ch")    == false);
    assert(pf_match_domain("*.sky.ch", "deep.api.sky.ch") == true);

    printf("  domain: TLD wildcard *.ch ...\n");
    assert(pf_match_domain("*.ch", "sky.ch")    == true);
    assert(pf_match_domain("*.ch", "google.ch") == true);
    assert(pf_match_domain("*.ch", "google.com") == false);
    assert(pf_match_domain("*.ch", "ch")         == true);   /* bare TLD */

    printf("  domain: contains *streaming* ...\n");
    assert(pf_match_domain("*streaming*", "my-streaming-service.com") == true);
    assert(pf_match_domain("*streaming*", "STREAMING.ch")             == true);
    assert(pf_match_domain("*streaming*", "google.com")               == false);
    assert(pf_match_domain("*streaming*", "stream.io")                == false);

    printf("  domain: edge cases ...\n");
    assert(pf_match_domain("*", "anything.com") == true);
    assert(pf_match_domain("example.com", "sub.example.com") == false);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test: pf_match_app
 * ───────────────────────────────────────────────────────────────────────────── */
static void test_app(void)
{
    printf("  app: basename match ...\n");
    assert(pf_match_app("firefox", "/usr/bin/firefox")      == true);
    assert(pf_match_app("firefox", "/snap/bin/firefox")     == true);
    assert(pf_match_app("firefox", "/usr/bin/firefox-esr")  == false);  /* exact basename */
    assert(pf_match_app("curl",    "/usr/bin/firefox")      == false);

    printf("  app: exact path ...\n");
    assert(pf_match_app("/usr/bin/firefox", "/usr/bin/firefox") == true);
    assert(pf_match_app("/usr/bin/firefox", "/usr/bin/curl")    == false);
    assert(pf_match_app("/usr/bin/firefox", "/snap/bin/firefox")== false);

    printf("  app: glob path ...\n");
    assert(pf_match_app("/opt/google/**",  "/opt/google/chrome/chrome")   == true);
    assert(pf_match_app("/opt/google/**",  "/opt/google/earth/earth")     == true);
    assert(pf_match_app("/opt/google/**",  "/usr/bin/chrome")             == false);
    assert(pf_match_app("/usr/bin/*",      "/usr/bin/wget")               == true);
    assert(pf_match_app("/usr/bin/*",      "/usr/local/bin/wget")         == false);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test: pf_match_ip
 * ───────────────────────────────────────────────────────────────────────────── */
static void test_ip(void)
{
    printf("  ip: CIDR ...\n");
    assert(pf_match_ip("192.168.1.0/24",  "192.168.1.42")  == true);
    assert(pf_match_ip("192.168.1.0/24",  "192.168.1.1")   == true);
    assert(pf_match_ip("192.168.1.0/24",  "192.168.1.255") == true);
    assert(pf_match_ip("192.168.1.0/24",  "192.168.2.1")   == false);
    assert(pf_match_ip("10.0.0.0/8",      "10.255.255.255")== true);
    assert(pf_match_ip("10.0.0.0/8",      "11.0.0.1")      == false);
    assert(pf_match_ip("0.0.0.0/0",       "1.2.3.4")       == true);   /* match-all */

    printf("  ip: range ...\n");
    assert(pf_match_ip("10.0.0.1-10.0.0.255", "10.0.0.50")  == true);
    assert(pf_match_ip("10.0.0.1-10.0.0.255", "10.0.0.1")   == true);  /* inclusive */
    assert(pf_match_ip("10.0.0.1-10.0.0.255", "10.0.0.255") == true);  /* inclusive */
    assert(pf_match_ip("10.0.0.1-10.0.0.255", "10.0.1.1")   == false);
    assert(pf_match_ip("10.0.0.1-10.0.0.255", "10.0.0.0")   == false); /* before start */

    printf("  ip: exact ...\n");
    assert(pf_match_ip("1.2.3.4", "1.2.3.4") == true);
    assert(pf_match_ip("1.2.3.4", "1.2.3.5") == false);
    assert(pf_match_ip("1.2.3.4", "1.2.3.3") == false);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test: pf_match_port
 * ───────────────────────────────────────────────────────────────────────────── */
static void test_port(void)
{
    printf("  port: exact with colon prefix ...\n");
    assert(pf_match_port(":443",  443) == true);
    assert(pf_match_port(":443",  80)  == false);
    assert(pf_match_port(":80",   80)  == true);

    printf("  port: exact without colon ...\n");
    assert(pf_match_port("443",   443) == true);
    assert(pf_match_port("443",   80)  == false);
    assert(pf_match_port("8080",  8080)== true);

    printf("  port: range ...\n");
    assert(pf_match_port("8000-9000",  8500) == true);
    assert(pf_match_port("8000-9000",  8000) == true);   /* inclusive lo */
    assert(pf_match_port("8000-9000",  9000) == true);   /* inclusive hi */
    assert(pf_match_port("8000-9000",  7999) == false);
    assert(pf_match_port("8000-9000",  9001) == false);

    printf("  port: range with colon prefix ...\n");
    assert(pf_match_port(":8000-9000", 9000) == true);
    assert(pf_match_port(":8000-9000", 7999) == false);
    assert(pf_match_port(":1-65535",   1)    == true);
    assert(pf_match_port(":1-65535",   65535)== true);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test: pf_rules_match — full ruleset priority logic
 *
 * Ruleset (sorted by priority):
 *   rule 0 prio=0 — match domain "sky.ch"         → BLOCK   (disabled, must be skipped)
 *   rule 1 prio=1 — match app "firefox"            → PROXY   proxy_id=1
 *   rule 2 prio=2 — match domain "*.ch"            → CHAIN   chain_id=2
 *   rule 3 prio=9 — catch-all (all fields empty)   → DIRECT
 * ───────────────────────────────────────────────────────────────────────────── */
static void test_ruleset(void)
{
    pf_rule_t *rules = calloc(4, sizeof(pf_rule_t));
    assert(rules != NULL);

    /* Rule 0: disabled, domain=sky.ch → BLOCK */
    rules[0].id       = 10;
    rules[0].priority = 0;
    rules[0].enabled  = 0;   /* disabled */
    rules[0].action   = PF_ACTION_BLOCK;
    snprintf(rules[0].name,   sizeof(rules[0].name),   "block-sky-disabled");
    snprintf(rules[0].domain, sizeof(rules[0].domain), "sky.ch");

    /* Rule 1: prio=1, app=firefox → PROXY id=1 */
    rules[1].id       = 11;
    rules[1].priority = 1;
    rules[1].enabled  = 1;
    rules[1].action   = PF_ACTION_PROXY;
    rules[1].proxy_id = 1;
    snprintf(rules[1].name,     sizeof(rules[1].name),     "firefox-proxy");
    snprintf(rules[1].app_path, sizeof(rules[1].app_path), "firefox");

    /* Rule 2: prio=2, domain=*.ch → CHAIN id=2 */
    rules[2].id       = 12;
    rules[2].priority = 2;
    rules[2].enabled  = 1;
    rules[2].action   = PF_ACTION_CHAIN;
    rules[2].chain_id = 2;
    snprintf(rules[2].name,   sizeof(rules[2].name),   "swiss-chain");
    snprintf(rules[2].domain, sizeof(rules[2].domain), "*.ch");

    /* Rule 3: prio=9, catch-all → DIRECT */
    rules[3].id       = 13;
    rules[3].priority = 9;
    rules[3].enabled  = 1;
    rules[3].action   = PF_ACTION_DIRECT;
    snprintf(rules[3].name, sizeof(rules[3].name), "catch-all");
    /* all match fields left empty → matches everything */

    pf_ruleset_t *rs = make_ruleset(rules, 4);
    free(rules);

    printf("  ruleset: disabled rule is skipped ...\n");
    /* sky.ch + any app: rule 0 disabled, rule 1 no domain match, rule 2 matches *.ch */
    const pf_rule_t *m = pf_rules_match(rs, "/usr/bin/curl", "sky.ch", "1.2.3.4", 443);
    assert(m != NULL);
    assert(m->id == 12);              /* rule 2 — *.ch chain */
    assert(m->action == PF_ACTION_CHAIN);

    printf("  ruleset: firefox app matches rule 1 (higher prio) ...\n");
    /* firefox + any domain: rule 1 (app=firefox) fires before rule 2 (domain=*.ch) */
    m = pf_rules_match(rs, "/usr/bin/firefox", "sky.ch", "1.2.3.4", 443);
    assert(m != NULL);
    assert(m->id == 11);
    assert(m->action == PF_ACTION_PROXY);
    assert(m->proxy_id == 1);

    printf("  ruleset: non-.ch domain, non-firefox → catch-all ...\n");
    m = pf_rules_match(rs, "/usr/bin/curl", "google.com", "8.8.8.8", 443);
    assert(m != NULL);
    assert(m->id == 13);
    assert(m->action == PF_ACTION_DIRECT);

    free(rs);

    printf("  ruleset: no rules → NULL ...\n");
    pf_ruleset_t *empty_rs = calloc(1, sizeof(pf_ruleset_t));
    assert(empty_rs != NULL);
    empty_rs->count = 0;
    m = pf_rules_match(empty_rs, "/usr/bin/curl", "google.com", "8.8.8.8", 443);
    assert(m == NULL);
    free(empty_rs);

    printf("  ruleset: all conditions AND — both must match ...\n");
    /* Rule with app AND domain: only fires when both match */
    pf_rule_t *combo = calloc(2, sizeof(pf_rule_t));
    assert(combo != NULL);

    combo[0].id       = 20;
    combo[0].priority = 1;
    combo[0].enabled  = 1;
    combo[0].action   = PF_ACTION_BLOCK;
    snprintf(combo[0].name,     sizeof(combo[0].name),     "combo-rule");
    snprintf(combo[0].app_path, sizeof(combo[0].app_path), "curl");
    snprintf(combo[0].domain,   sizeof(combo[0].domain),   "evil.com");

    combo[1].id       = 21;
    combo[1].priority = 9;
    combo[1].enabled  = 1;
    combo[1].action   = PF_ACTION_DIRECT;
    snprintf(combo[1].name, sizeof(combo[1].name), "default");

    pf_ruleset_t *crs = make_ruleset(combo, 2);
    free(combo);

    /* curl + evil.com → BLOCK */
    m = pf_rules_match(crs, "/usr/bin/curl", "evil.com", NULL, 80);
    assert(m != NULL && m->id == 20 && m->action == PF_ACTION_BLOCK);

    /* curl + google.com → DIRECT (domain doesn't match combo[0]) */
    m = pf_rules_match(crs, "/usr/bin/curl", "google.com", NULL, 80);
    assert(m != NULL && m->id == 21 && m->action == PF_ACTION_DIRECT);

    /* wget + evil.com → DIRECT (app doesn't match combo[0]) */
    m = pf_rules_match(crs, "/usr/bin/wget", "evil.com", NULL, 80);
    assert(m != NULL && m->id == 21 && m->action == PF_ACTION_DIRECT);

    free(crs);

    printf("  ruleset: dst_port integer matching ...\n");
    pf_rule_t *pr = calloc(1, sizeof(pf_rule_t));
    assert(pr != NULL);
    pr[0].id       = 30;
    pr[0].priority = 1;
    pr[0].enabled  = 1;
    pr[0].action   = PF_ACTION_BLOCK;
    pr[0].dst_port = 443;
    snprintf(pr[0].name, sizeof(pr[0].name), "block-443");

    pf_ruleset_t *prs = make_ruleset(pr, 1);
    free(pr);
    m = pf_rules_match(prs, NULL, NULL, NULL, 443);
    assert(m != NULL && m->id == 30 && m->action == PF_ACTION_BLOCK);
    m = pf_rules_match(prs, NULL, NULL, NULL, 80);
    assert(m == NULL);
    free(prs);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * main
 * ───────────────────────────────────────────────────────────────────────────── */
int main(void)
{
    printf("=== ProxiFlare Rule Engine Tests ===\n\n");

    printf("[ 1 ] Domain matching\n");
    test_domain();

    printf("\n[ 2 ] App matching\n");
    test_app();

    printf("\n[ 3 ] IP matching\n");
    test_ip();

    printf("\n[ 4 ] Port matching\n");
    test_port();

    printf("\n[ 5 ] Full ruleset matching\n");
    test_ruleset();

    printf("\nALL RULES TESTS PASSED\n");
    return 0;
}
