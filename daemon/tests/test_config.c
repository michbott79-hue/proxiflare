#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* pull in string helpers from main.c equivalents — we define them locally
   so the test binary doesn't need to link main.c */
#include "proxiflare.h"
#include "config.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * String helpers (duplicated from main.c to avoid linking the full daemon)
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
 * Test helpers
 * ───────────────────────────────────────────────────────────────────────────── */

#define TEST_DB "/tmp/pf_test.db"

static int g_pass = 0;
static int g_fail = 0;

#define ASSERT(label, expr) do { \
    if (expr) { \
        printf("  [PASS] %s\n", label); \
        g_pass++; \
    } else { \
        printf("  [FAIL] %s  (line %d)\n", label, __LINE__); \
        g_fail++; \
    } \
} while (0)

/* ─────────────────────────────────────────────────────────────────────────────
 * Tests
 * ───────────────────────────────────────────────────────────────────────────── */

static void test_init(pf_config_t *cfg)
{
    printf("\n=== test_init ===\n");
    unlink(TEST_DB);

    int rc = pf_config_init(cfg, TEST_DB);
    ASSERT("init returns PF_OK",        rc == PF_OK);
    ASSERT("db handle not NULL",        cfg->db != NULL);
    ASSERT("db_path stored",            strcmp(cfg->db_path, TEST_DB) == 0);
}

static void test_proxy_crud(pf_config_t *cfg)
{
    printf("\n=== test_proxy_crud ===\n");

    /* add */
    pf_proxy_t p = {0};
    snprintf(p.name,     sizeof(p.name),     "proxy-alpha");
    snprintf(p.host,     sizeof(p.host),     "10.0.0.1");
    snprintf(p.username, sizeof(p.username), "user1");
    snprintf(p.password, sizeof(p.password), "secret");
    p.type    = PF_PROXY_SOCKS5;
    p.port    = 1080;
    p.enabled = 1;
    p.health  = PF_HEALTH_UNKNOWN;

    int rc = pf_config_proxy_add(cfg, &p);
    ASSERT("proxy_add returns PF_OK", rc == PF_OK);

    /* add a second proxy for list test */
    pf_proxy_t p2 = {0};
    snprintf(p2.name, sizeof(p2.name), "proxy-beta");
    snprintf(p2.host, sizeof(p2.host), "10.0.0.2");
    p2.type = PF_PROXY_HTTP;
    p2.port = 8080;
    p2.enabled = 1;
    pf_config_proxy_add(cfg, &p2);

    /* list */
    pf_proxy_t list[10] = {0};
    int count = 0;
    rc = pf_config_proxy_list(cfg, list, 10, &count);
    ASSERT("proxy_list returns PF_OK", rc == PF_OK);
    ASSERT("proxy_list count == 2",    count == 2);
    ASSERT("proxy_list ordered by name (alpha first)", strcmp(list[0].name, "proxy-alpha") == 0);

    /* get */
    pf_proxy_t got = {0};
    rc = pf_config_proxy_get(cfg, (int)list[0].id, &got);
    ASSERT("proxy_get returns PF_OK",           rc == PF_OK);
    ASSERT("proxy_get name matches",            strcmp(got.name, "proxy-alpha") == 0);
    ASSERT("proxy_get host matches",            strcmp(got.host, "10.0.0.1") == 0);
    ASSERT("proxy_get port matches",            got.port == 1080);
    ASSERT("proxy_get type matches",            got.type == PF_PROXY_SOCKS5);
    ASSERT("proxy_get username matches",        strcmp(got.username, "user1") == 0);

    /* update */
    got.port = 1081;
    snprintf(got.host, sizeof(got.host), "10.0.0.99");
    rc = pf_config_proxy_update(cfg, &got);
    ASSERT("proxy_update returns PF_OK", rc == PF_OK);

    pf_proxy_t updated = {0};
    pf_config_proxy_get(cfg, (int)got.id, &updated);
    ASSERT("proxy_update port persisted", updated.port == 1081);
    ASSERT("proxy_update host persisted", strcmp(updated.host, "10.0.0.99") == 0);

    /* update_health */
    rc = pf_config_proxy_update_health(cfg, (int)got.id, PF_HEALTH_ONLINE, 42);
    ASSERT("proxy_update_health returns PF_OK", rc == PF_OK);

    pf_proxy_t healthy = {0};
    pf_config_proxy_get(cfg, (int)got.id, &healthy);
    ASSERT("proxy health updated",    healthy.health == PF_HEALTH_ONLINE);
    ASSERT("proxy latency_ms updated", healthy.latency_ms == 42);

    /* delete */
    rc = pf_config_proxy_delete(cfg, (int)list[1].id);
    ASSERT("proxy_delete returns PF_OK", rc == PF_OK);

    count = 0;
    pf_config_proxy_list(cfg, list, 10, &count);
    ASSERT("proxy_list count == 1 after delete", count == 1);
}

static void test_rule_crud(pf_config_t *cfg)
{
    printf("\n=== test_rule_crud ===\n");

    /* add 3 rules with different priorities */
    pf_rule_t r1 = {0};
    snprintf(r1.name, sizeof(r1.name), "rule-low");
    r1.priority = 100;
    r1.action   = PF_ACTION_DIRECT;
    r1.enabled  = 1;

    pf_rule_t r2 = {0};
    snprintf(r2.name, sizeof(r2.name), "rule-high");
    r2.priority = 10;
    r2.action   = PF_ACTION_BLOCK;
    r2.enabled  = 1;
    snprintf(r2.domain, sizeof(r2.domain), "evil.example.com");

    pf_rule_t r3 = {0};
    snprintf(r3.name, sizeof(r3.name), "rule-mid");
    r3.priority = 50;
    r3.action   = PF_ACTION_PROXY;
    r3.enabled  = 1;
    snprintf(r3.ip_cidr, sizeof(r3.ip_cidr), "192.168.0.0/24");

    int rc = pf_config_rule_add(cfg, &r1);
    ASSERT("rule_add r1 PF_OK", rc == PF_OK);
    rc = pf_config_rule_add(cfg, &r2);
    ASSERT("rule_add r2 PF_OK", rc == PF_OK);
    rc = pf_config_rule_add(cfg, &r3);
    ASSERT("rule_add r3 PF_OK", rc == PF_OK);

    /* list — must be ordered by priority ASC */
    pf_rule_t list[10] = {0};
    int count = 0;
    rc = pf_config_rule_list(cfg, list, 10, &count);
    ASSERT("rule_list returns PF_OK",  rc == PF_OK);
    ASSERT("rule_list count == 3",     count == 3);
    ASSERT("rule priority order [0]=10", list[0].priority == 10);
    ASSERT("rule priority order [1]=50", list[1].priority == 50);
    ASSERT("rule priority order [2]=100", list[2].priority == 100);
    ASSERT("rule domain stored", strcmp(list[0].domain, "evil.example.com") == 0);
    ASSERT("rule ip_cidr stored", strcmp(list[1].ip_cidr, "192.168.0.0/24") == 0);

    /* get */
    pf_rule_t got = {0};
    rc = pf_config_rule_get(cfg, (int)list[0].id, &got);
    ASSERT("rule_get PF_OK",       rc == PF_OK);
    ASSERT("rule_get name match",  strcmp(got.name, "rule-high") == 0);
    ASSERT("rule_get action match", got.action == PF_ACTION_BLOCK);

    /* delete one */
    rc = pf_config_rule_delete(cfg, (int)list[2].id);
    ASSERT("rule_delete PF_OK", rc == PF_OK);

    count = 0;
    pf_config_rule_list(cfg, list, 10, &count);
    ASSERT("rule_list count == 2 after delete", count == 2);
}

static void test_chain_crud(pf_config_t *cfg)
{
    printf("\n=== test_chain_crud ===\n");

    /* we need proxies — add two fresh ones */
    pf_proxy_t pa = {0}, pb = {0};
    snprintf(pa.name, sizeof(pa.name), "hop-proxy-1");
    snprintf(pa.host, sizeof(pa.host), "1.2.3.4");
    pa.type = PF_PROXY_SOCKS5; pa.port = 1080; pa.enabled = 1;

    snprintf(pb.name, sizeof(pb.name), "hop-proxy-2");
    snprintf(pb.host, sizeof(pb.host), "5.6.7.8");
    pb.type = PF_PROXY_HTTP; pb.port = 8080; pb.enabled = 1;

    pf_config_proxy_add(cfg, &pa);
    pf_config_proxy_add(cfg, &pb);

    /* get their IDs */
    pf_proxy_t plist[10] = {0};
    int pcount = 0;
    pf_config_proxy_list(cfg, plist, 10, &pcount);

    /* find our two by name */
    uint32_t id_a = 0, id_b = 0;
    for (int i = 0; i < pcount; i++) {
        if (strcmp(plist[i].name, "hop-proxy-1") == 0) id_a = plist[i].id;
        if (strcmp(plist[i].name, "hop-proxy-2") == 0) id_b = plist[i].id;
    }
    ASSERT("hop-proxy-1 found", id_a != 0);
    ASSERT("hop-proxy-2 found", id_b != 0);

    /* add chain with 2 hops */
    pf_chain_t chain = {0};
    snprintf(chain.name, sizeof(chain.name), "test-chain");
    chain.enabled   = 1;
    chain.hops[0]   = id_a;
    chain.hops[1]   = id_b;
    chain.hop_count = 2;

    int rc = pf_config_chain_add(cfg, &chain);
    ASSERT("chain_add PF_OK", rc == PF_OK);

    /* list */
    pf_chain_t clist[10] = {0};
    int ccount = 0;
    rc = pf_config_chain_list(cfg, clist, 10, &ccount);
    ASSERT("chain_list PF_OK",    rc == PF_OK);
    ASSERT("chain_list count==1", ccount == 1);
    ASSERT("chain name match",    strcmp(clist[0].name, "test-chain") == 0);
    ASSERT("chain hop_count==2",  clist[0].hop_count == 2);
    ASSERT("chain hops[0] correct", clist[0].hops[0] == id_a);
    ASSERT("chain hops[1] correct", clist[0].hops[1] == id_b);

    /* get */
    pf_chain_t got = {0};
    rc = pf_config_chain_get(cfg, (int)clist[0].id, &got);
    ASSERT("chain_get PF_OK",       rc == PF_OK);
    ASSERT("chain_get hops loaded", got.hop_count == 2);
    ASSERT("chain_get hop[0]",      got.hops[0] == id_a);
    ASSERT("chain_get hop[1]",      got.hops[1] == id_b);

    /* update — reverse hop order */
    got.hops[0]   = id_b;
    got.hops[1]   = id_a;
    got.hop_count = 2;
    rc = pf_config_chain_update(cfg, &got);
    ASSERT("chain_update PF_OK", rc == PF_OK);

    pf_chain_t updated = {0};
    pf_config_chain_get(cfg, (int)got.id, &updated);
    ASSERT("chain_update hops reversed [0]", updated.hops[0] == id_b);
    ASSERT("chain_update hops reversed [1]", updated.hops[1] == id_a);

    /* delete — should cascade to chain_hops */
    rc = pf_config_chain_delete(cfg, (int)got.id);
    ASSERT("chain_delete PF_OK", rc == PF_OK);

    ccount = 0;
    pf_config_chain_list(cfg, clist, 10, &ccount);
    ASSERT("chain_list count==0 after delete", ccount == 0);

    /* verify cascade: get on deleted id returns error */
    pf_chain_t gone = {0};
    rc = pf_config_chain_get(cfg, (int)got.id, &gone);
    ASSERT("chain_get on deleted returns error", rc == PF_ERR_DB);
}

static void test_keyvalue(pf_config_t *cfg)
{
    printf("\n=== test_keyvalue ===\n");

    int rc = pf_config_set(cfg, "log_level", "debug");
    ASSERT("config_set PF_OK", rc == PF_OK);

    char val[64] = {0};
    rc = pf_config_get(cfg, "log_level", val, sizeof(val));
    ASSERT("config_get PF_OK",       rc == PF_OK);
    ASSERT("config_get value match", strcmp(val, "debug") == 0);

    /* overwrite */
    rc = pf_config_set(cfg, "log_level", "info");
    ASSERT("config_set overwrite PF_OK", rc == PF_OK);

    memset(val, 0, sizeof(val));
    pf_config_get(cfg, "log_level", val, sizeof(val));
    ASSERT("config overwrite persisted", strcmp(val, "info") == 0);

    /* missing key */
    memset(val, 0, sizeof(val));
    rc = pf_config_get(cfg, "nonexistent_key", val, sizeof(val));
    ASSERT("config_get missing key returns error", rc == PF_ERR_DB);

    /* multiple keys */
    pf_config_set(cfg, "version",  "1.0.0");
    pf_config_set(cfg, "max_conn", "100");

    char v2[32] = {0}, v3[32] = {0};
    pf_config_get(cfg, "version",  v2, sizeof(v2));
    pf_config_get(cfg, "max_conn", v3, sizeof(v3));
    ASSERT("config version stored",  strcmp(v2, "1.0.0") == 0);
    ASSERT("config max_conn stored", strcmp(v3, "100") == 0);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Main
 * ───────────────────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("ProxiFlare config module tests\n");
    printf("DB: %s\n", TEST_DB);

    pf_config_t cfg = {0};

    test_init(&cfg);
    test_proxy_crud(&cfg);
    test_rule_crud(&cfg);
    test_chain_crud(&cfg);
    test_keyvalue(&cfg);

    pf_config_close(&cfg);
    unlink(TEST_DB);

    printf("\n─────────────────────────────────────────\n");
    printf("Results: %d passed, %d failed\n", g_pass, g_fail);

    if (g_fail == 0) {
        printf("ALL TESTS PASSED\n");
        return 0;
    } else {
        printf("SOME TESTS FAILED\n");
        return 1;
    }
}
