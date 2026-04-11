/* ──────────────────────────────────────────────────────────────────────────
 * ProxiFlare Daemon — main.c
 * Event loop glue: wires all modules together via epoll.
 * ────────────────────────────────────────────────────────────────────────── */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "proxiflare.h"
#include "config.h"
#include "crypto.h"
#include "ipc.h"
#include "dns.h"
#include "sni.h"
#include "rules.h"
#include "proxy_socks.h"
#include "proxy_http.h"
#include "proxy_ssh.h"
#include "chain.h"
#include "tproxy.h"
#include "cgroup.h"
#include "nft.h"
#include "monitor.h"
#include "logger.h"
#include "stats.h"
#include "mitm.h"
#include "http_parser.h"
#include <cJSON.h>

/* ──────────────────────────────────────────────────────────────────────────
 * Log ring buffer — last 500 entries, sequence-numbered for polling
 * ────────────────────────────────────────────────────────────────────────── */

#define PF_LOG_RING_SIZE 500

static cJSON   *g_log_ring[PF_LOG_RING_SIZE];
static int      g_log_ring_head  = 0;   /* next write position */
static int      g_log_ring_count = 0;
static uint64_t g_log_seq        = 0;   /* monotonic sequence number */

/* ──────────────────────────────────────────────────────────────────────────
 * Global context
 * ────────────────────────────────────────────────────────────────────────── */

struct pf_ctx {
    pf_config_t    config;
    pf_crypto_t    crypto;
    pf_ipc_t       ipc;
    pf_dns_t       dns;
    pf_tproxy_t    tproxy;
    pf_logger_t    logger;
    pf_ruleset_t  *ruleset;   /* heap-allocated: ~4.5MB (PF_MAX_RULES * sizeof(pf_rule_t)) */
    pf_ssh_pool_t  ssh_pool;
    pf_stats_t     stats;
    pf_monitor_t   monitor;
    pf_mitm_t      mitm;
    int            epoll_fd;
    volatile int   running;   /* volatile int, not bool, for signal safety */
};

/* Single static instance — avoids putting ~6MB on the stack */
static struct pf_ctx g_ctx;

/* ──────────────────────────────────────────────────────────────────────────
 * HTTP inspect ring buffer — stores intercepted request/response summaries
 * ────────────────────────────────────────────────────────────────────────── */

#define PF_INSPECT_RING_SIZE 200

static cJSON   *g_inspect_ring[PF_INSPECT_RING_SIZE];
static int      g_inspect_ring_head  = 0;
static int      g_inspect_ring_count = 0;
static uint64_t g_inspect_seq        = 0;

/* Callback from tproxy relay — parse HTTP and store in ring */
static void on_inspect_data(const uint8_t *data, size_t len, int is_request,
                            const pf_connection_t *conn, void *userdata)
{
    (void)userdata;
    if (!data || len < 4) return;

    pf_http_msg_t msg;
    int rc;

    if (is_request)
        rc = pf_http_parse_request((const char *)data, len, &msg);
    else
        rc = pf_http_parse_response((const char *)data, len, &msg);

    if (rc != 0) return; /* not a complete HTTP message (yet) */

    cJSON *entry = cJSON_CreateObject();
    cJSON_AddNumberToObject(entry, "seq", (double)(++g_inspect_seq));
    cJSON_AddNumberToObject(entry, "ts", (double)time(NULL));
    cJSON_AddStringToObject(entry, "domain", conn->domain[0] ? conn->domain : conn->dst_ip);
    cJSON_AddStringToObject(entry, "dst_ip", conn->dst_ip);
    cJSON_AddNumberToObject(entry, "dst_port", (double)conn->dst_port);
    cJSON_AddBoolToObject(entry, "is_request", is_request ? 1 : 0);
    cJSON_AddBoolToObject(entry, "tls", conn->is_tls ? 1 : 0);

    if (is_request) {
        cJSON_AddStringToObject(entry, "method", msg.method);
        cJSON_AddStringToObject(entry, "url", msg.url);
        cJSON_AddStringToObject(entry, "version", msg.version);
    } else {
        cJSON_AddNumberToObject(entry, "status", msg.status_code);
        cJSON_AddStringToObject(entry, "status_text", msg.status_text);
        cJSON_AddStringToObject(entry, "version", msg.version);
    }

    /* Headers as object */
    cJSON *hdrs = cJSON_CreateObject();
    for (int i = 0; i < msg.header_count; i++)
        cJSON_AddStringToObject(hdrs, msg.headers[i].key, msg.headers[i].value);
    cJSON_AddItemToObject(entry, "headers", hdrs);

    /* Body (truncated to 4KB for JSON transport) */
    if (msg.body && msg.body_len > 0) {
        size_t cap = msg.body_len < 4096 ? msg.body_len : 4096;
        char *body_str = (char *)malloc(cap + 1);
        if (body_str) {
            memcpy(body_str, msg.body, cap);
            body_str[cap] = '\0';
            cJSON_AddStringToObject(entry, "body", body_str);
            cJSON_AddNumberToObject(entry, "body_len", (double)msg.body_len);
            free(body_str);
        }
    }

    cJSON_AddNumberToObject(entry, "content_length", (double)msg.content_length);

    /* Store in ring buffer */
    if (g_inspect_ring[g_inspect_ring_head])
        cJSON_Delete(g_inspect_ring[g_inspect_ring_head]);
    g_inspect_ring[g_inspect_ring_head] = entry;
    g_inspect_ring_head = (g_inspect_ring_head + 1) % PF_INSPECT_RING_SIZE;
    if (g_inspect_ring_count < PF_INSPECT_RING_SIZE) g_inspect_ring_count++;
}

/* ──────────────────────────────────────────────────────────────────────────
 * String conversion helpers (referenced by proxiflare.h, used by all modules)
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
        case PF_ACTION_DIRECT: return "DIRECT";
        case PF_ACTION_PROXY:  return "PROXY";
        case PF_ACTION_CHAIN:  return "CHAIN";
        case PF_ACTION_BLOCK:  return "BLOCK";
        case PF_ACTION_REJECT: return "REJECT";
        default:               return "DIRECT";
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
    if (strcasecmp(s, "direct") == 0) return PF_ACTION_DIRECT;
    if (strcasecmp(s, "proxy")  == 0) return PF_ACTION_PROXY;
    if (strcasecmp(s, "chain")  == 0) return PF_ACTION_CHAIN;
    if (strcasecmp(s, "block")  == 0) return PF_ACTION_BLOCK;
    if (strcasecmp(s, "reject") == 0) return PF_ACTION_REJECT;
    return PF_ACTION_DIRECT;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Signal handling
 * ────────────────────────────────────────────────────────────────────────── */

static void sig_handler(int signum)
{
    if (signum == SIGTERM || signum == SIGINT) {
        g_ctx.running = 0;
    }
    /* SIGHUP → reload is handled in the main loop via a flag */
}

static volatile int g_reload = 0;

static void sig_hup(int signum)
{
    (void)signum;
    g_reload = 1;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Process monitor callback
 * ────────────────────────────────────────────────────────────────────────── */

static void on_process_event(pid_t pid, const char *exe_path, bool is_exec, void *userdata)
{
    pf_ctx_t *ctx = (pf_ctx_t *)userdata;

    if (is_exec) {
        if (!ctx->ruleset) return;
        /* Match by full path first, then by basename for snap/flatpak apps */
        const pf_rule_t *rule = pf_rules_match(ctx->ruleset, exe_path, NULL, NULL, 0);
        if (!rule || rule->action == PF_ACTION_DIRECT) {
            /* Extract basename and retry — handles snap paths like
             * /snap/firefox/8054/usr/lib/firefox/firefox matching "firefox" */
            const char *base = strrchr(exe_path, '/');
            base = base ? base + 1 : exe_path;
            rule = pf_rules_match(ctx->ruleset, base, NULL, NULL, 0);
        }
        if (rule && rule->action != PF_ACTION_DIRECT && rule->app_path[0]) {
            pf_cgroup_assign_pid((int)rule->id, pid);
            pf_log_info("process_monitor: PID %d (%s) → rule '%s' (proxy_id=%u)",
                        pid, exe_path, rule->name, rule->proxy_id);
        }
    } else {
        pf_cgroup_remove_pid(pid);
    }
}

/* ──────────────────────────────────────────────────────────────────────────
 * Helpers: proxy / rule / chain JSON serialization
 * ────────────────────────────────────────────────────────────────────────── */

static cJSON *proxy_to_json(const pf_proxy_t *p)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "id",         (double)p->id);
    cJSON_AddStringToObject(obj, "name",       p->name);
    cJSON_AddStringToObject(obj, "type",       pf_proxy_type_str(p->type));
    cJSON_AddStringToObject(obj, "host",       p->host);
    cJSON_AddNumberToObject(obj, "port",       p->port);
    cJSON_AddStringToObject(obj, "username",   p->username);
    cJSON_AddStringToObject(obj, "password",   p->password);
    cJSON_AddStringToObject(obj, "health",     pf_health_str(p->health));
    cJSON_AddNumberToObject(obj, "latency_ms", (double)p->latency_ms);
    cJSON_AddBoolToObject  (obj, "enabled",    p->enabled);
    return obj;
}

static cJSON *rule_to_json(const pf_rule_t *r)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "id",           (double)r->id);
    cJSON_AddStringToObject(obj, "name",         r->name);
    cJSON_AddNumberToObject(obj, "priority",     r->priority);
    cJSON_AddStringToObject(obj, "match_app",    r->app_path);
    cJSON_AddStringToObject(obj, "match_domain", r->domain);
    cJSON_AddStringToObject(obj, "match_ip",     r->ip_cidr);
    if (r->dst_port > 0) {
        char ps[8]; snprintf(ps, sizeof(ps), "%u", r->dst_port);
        cJSON_AddStringToObject(obj, "match_port", ps);
    } else {
        cJSON_AddStringToObject(obj, "match_port", "");
    }
    cJSON_AddStringToObject(obj, "action",   pf_action_str(r->action));
    cJSON_AddNumberToObject(obj, "proxy_id", (double)r->proxy_id);
    cJSON_AddNumberToObject(obj, "chain_id", (double)r->chain_id);
    cJSON_AddBoolToObject  (obj, "enabled",  r->enabled);
    return obj;
}

static cJSON *chain_to_json(const pf_chain_t *c)
{
    cJSON *obj  = cJSON_CreateObject();
    cJSON *hops = cJSON_CreateArray();
    cJSON_AddNumberToObject(obj, "id",      (double)c->id);
    cJSON_AddStringToObject(obj, "name",    c->name);
    cJSON_AddBoolToObject  (obj, "enabled", c->enabled);
    for (int i = 0; i < c->hop_count; i++)
        cJSON_AddItemToArray(hops, cJSON_CreateNumber((double)c->hops[i]));
    cJSON_AddItemToObject(obj, "hop_proxy_ids", hops);
    return obj;
}

/* Convenience: parse a proxy from cJSON params */
static void proxy_from_json(pf_proxy_t *p, cJSON *params)
{
    cJSON *v;
    memset(p, 0, sizeof(*p));
    if ((v = cJSON_GetObjectItem(params, "id")))
        p->id = (uint32_t)v->valuedouble;
    if ((v = cJSON_GetObjectItem(params, "name")))
        snprintf(p->name, sizeof(p->name), "%s", v->valuestring);
    if ((v = cJSON_GetObjectItem(params, "type")))
        p->type = pf_proxy_type_from_str(v->valuestring);
    if ((v = cJSON_GetObjectItem(params, "host")))
        snprintf(p->host, sizeof(p->host), "%s", v->valuestring);
    if ((v = cJSON_GetObjectItem(params, "port")))
        p->port = (uint16_t)v->valuedouble;
    if ((v = cJSON_GetObjectItem(params, "username")))
        snprintf(p->username, sizeof(p->username), "%s", v->valuestring);
    if ((v = cJSON_GetObjectItem(params, "password")))
        snprintf(p->password, sizeof(p->password), "%s", v->valuestring);
    if ((v = cJSON_GetObjectItem(params, "ssh_key_path")))
        snprintf(p->ssh_key_path, sizeof(p->ssh_key_path), "%s", v->valuestring);
    p->enabled = 1;
    if ((v = cJSON_GetObjectItem(params, "enabled")))
        p->enabled = cJSON_IsTrue(v) ? 1 : 0;
}

static void rule_from_json(pf_rule_t *r, cJSON *params)
{
    cJSON *v;
    memset(r, 0, sizeof(*r));
    if ((v = cJSON_GetObjectItem(params, "id")))
        r->id = (uint32_t)v->valuedouble;
    if ((v = cJSON_GetObjectItem(params, "name")))
        snprintf(r->name, sizeof(r->name), "%s", v->valuestring);
    if ((v = cJSON_GetObjectItem(params, "priority")))
        r->priority = (int)v->valuedouble;
    /* Accept both frontend names (match_app) and internal names (app_path) */
    if ((v = cJSON_GetObjectItem(params, "match_app")) || (v = cJSON_GetObjectItem(params, "app_path")))
        if (v->valuestring) snprintf(r->app_path, sizeof(r->app_path), "%s", v->valuestring);
    if ((v = cJSON_GetObjectItem(params, "match_domain")) || (v = cJSON_GetObjectItem(params, "domain")))
        if (v->valuestring) snprintf(r->domain, sizeof(r->domain), "%s", v->valuestring);
    if ((v = cJSON_GetObjectItem(params, "match_ip")) || (v = cJSON_GetObjectItem(params, "ip_cidr")))
        if (v->valuestring) snprintf(r->ip_cidr, sizeof(r->ip_cidr), "%s", v->valuestring);
    /* match_port: accept string ("443") or number */
    if ((v = cJSON_GetObjectItem(params, "match_port")) || (v = cJSON_GetObjectItem(params, "dst_port"))) {
        if (cJSON_IsString(v) && v->valuestring && v->valuestring[0])
            r->dst_port = (uint16_t)atoi(v->valuestring);
        else if (cJSON_IsNumber(v))
            r->dst_port = (uint16_t)v->valuedouble;
    }
    if ((v = cJSON_GetObjectItem(params, "action")))
        r->action = pf_action_from_str(v->valuestring);
    if ((v = cJSON_GetObjectItem(params, "proxy_id")))
        r->proxy_id = v->valuedouble > 0 ? (uint32_t)v->valuedouble : 0;
    if ((v = cJSON_GetObjectItem(params, "chain_id")))
        r->chain_id = v->valuedouble > 0 ? (uint32_t)v->valuedouble : 0;
    r->enabled = 1;
    if ((v = cJSON_GetObjectItem(params, "enabled")))
        r->enabled = cJSON_IsTrue(v) ? 1 : 0;
}

static void chain_from_json(pf_chain_t *c, cJSON *params)
{
    cJSON *v;
    memset(c, 0, sizeof(*c));
    if ((v = cJSON_GetObjectItem(params, "id")))
        c->id = (uint32_t)v->valuedouble;
    if ((v = cJSON_GetObjectItem(params, "name")))
        snprintf(c->name, sizeof(c->name), "%s", v->valuestring);
    c->enabled = 1;
    if ((v = cJSON_GetObjectItem(params, "enabled")))
        c->enabled = cJSON_IsTrue(v) ? 1 : 0;
    cJSON *hops = cJSON_GetObjectItem(params, "hop_proxy_ids");
    if (!hops) hops = cJSON_GetObjectItem(params, "hops");
    if (hops && cJSON_IsArray(hops)) {
        int n = cJSON_GetArraySize(hops);
        if (n > PF_MAX_HOPS) n = PF_MAX_HOPS;
        c->hop_count = n;
        for (int i = 0; i < n; i++)
            c->hops[i] = (uint32_t)cJSON_GetArrayItem(hops, i)->valuedouble;
    }
}

/* ──────────────────────────────────────────────────────────────────────────
 * TPROXY proxy connect callback
 *
 * Called by tproxy.c when a new redirected connection is accepted.
 * Looks up the destination in the DNS cache and rules to determine
 * which proxy (if any) to route through.
 *
 * Returns: connected fd (>= 0) on proxy success,
 *          -1 for DIRECT (no proxy match),
 *          -2 for BLOCK.
 * ────────────────────────────────────────────────────────────────────────── */

static int proxy_connect_for_tproxy(const char *dst_ip, int dst_port,
                                    const char *domain, void *userdata)
{
    pf_ctx_t *ctx = (pf_ctx_t *)userdata;
    if (!ctx || !ctx->ruleset) return -1;

    /* Traffic arrives at TPROXY because nftables cgroup match marked it.
     * This means a process in a proxiflare cgroup initiated this connection.
     * Strategy:
     *   1. Resolve domain from SNI or DNS cache
     *   2. Try domain-only rules (no app constraint) first
     *   3. If no match, iterate ALL app-based PROXY rules and find the best:
     *      - "specific" rules (have domain/ip/port constraints that match) win
     *      - "catch-all" rules (app-only, no domain/ip/port) are fallback
     *      This handles the multi-rule scenario: e.g. "Firefox IT" (catch-all)
     *      + "SKY.IT via CH" (domain-specific) — SKY domains use CH proxy. */
    const char *match_domain = (domain && domain[0]) ? domain : NULL;

    if (!match_domain && dst_ip && dst_ip[0]) {
        const pf_dns_entry_t *dns_entry = pf_dns_lookup(&ctx->dns, dst_ip);
        if (dns_entry && dns_entry->domain[0])
            match_domain = dns_entry->domain;
    }

    /* First try: match by domain/IP only (for rules without app constraint) */
    const pf_rule_t *rule = pf_rules_match(ctx->ruleset, NULL, match_domain,
                                           dst_ip, dst_port);

    /* If no match or DIRECT, scan all app-based PROXY rules.
     * Since we don't know which app sent this (TPROXY lost PID info),
     * we check domain/ip/port criteria to find the most specific match. */
    if (!rule || rule->action == PF_ACTION_DIRECT) {
        const pf_rule_t *best_specific = NULL;
        const pf_rule_t *best_catchall = NULL;

        for (int i = 0; i < ctx->ruleset->count; i++) {
            const pf_rule_t *r = &ctx->ruleset->rules[i];
            if (!r->enabled || r->action != PF_ACTION_PROXY ||
                !r->app_path[0] || r->proxy_id == 0)
                continue;

            /* Check optional domain/ip/port criteria (empty = don't care) */
            bool domain_ok = (r->domain[0] == '\0') ||
                             (match_domain && pf_match_domain(r->domain, match_domain));
            bool ip_ok     = (r->ip_cidr[0] == '\0') ||
                             (dst_ip && pf_match_ip(r->ip_cidr, dst_ip));
            bool port_ok   = (r->dst_port == 0) ||
                             (dst_port == (int)r->dst_port);

            if (!domain_ok || !ip_ok || !port_ok) continue;

            /* Specific rule: has at least one domain/ip/port constraint */
            bool has_specifics = (r->domain[0] || r->ip_cidr[0] || r->dst_port != 0);

            if (has_specifics) {
                if (!best_specific) best_specific = r;
                /* first specific match wins (rules sorted by priority ASC) */
            } else {
                if (!best_catchall) best_catchall = r;
            }
        }

        /* Prefer specific match over catch-all */
        rule = best_specific ? best_specific : best_catchall;
    }

    if (!rule || rule->action == PF_ACTION_DIRECT)
        return -1;

    if (rule->action == PF_ACTION_BLOCK || rule->action == PF_ACTION_REJECT)
        return -2;

    /* Target: prefer domain over raw IP for DNS-capable proxies */
    const char *target = (match_domain && match_domain[0]) ? match_domain : dst_ip;
    const char *via_name = "?";
    int fd = -1;

    if (rule->action == PF_ACTION_PROXY && rule->proxy_id > 0) {
        /* ── Single proxy routing ─────────────────────────────────────────── */
        pf_proxy_t proxy;
        if (pf_config_proxy_get(&ctx->config, (int)rule->proxy_id, &proxy) != PF_OK) {
            pf_log_warn("tproxy: proxy_id %u from rule '%s' not found in DB",
                        rule->proxy_id, rule->name);
            return -1;
        }
        if (!proxy.enabled) {
            pf_log_warn("tproxy: proxy '%s' (id=%u) is disabled", proxy.name, proxy.id);
            return -1;
        }
        via_name = proxy.name;
        switch (proxy.type) {
            case PF_PROXY_SOCKS5:
                fd = pf_socks5_connect(proxy.host, proxy.port, target, dst_port,
                                       proxy.username, proxy.password);
                break;
            case PF_PROXY_SOCKS4:
                fd = pf_socks4_connect(proxy.host, proxy.port, target, dst_port,
                                       proxy.username);
                break;
            case PF_PROXY_HTTP:
                fd = pf_http_connect(proxy.host, proxy.port, target, dst_port,
                                     proxy.username, proxy.password);
                break;
            case PF_PROXY_SSH:
                fd = pf_ssh_connect(&ctx->ssh_pool, &proxy, target, dst_port);
                break;
        }

    } else if (rule->action == PF_ACTION_CHAIN && rule->chain_id > 0) {
        /* ── Chain proxy routing ──────────────────────────────────────────── */
        pf_chain_t chain;
        if (pf_config_chain_get(&ctx->config, (int)rule->chain_id, &chain) != PF_OK) {
            pf_log_warn("tproxy: chain_id %u from rule '%s' not found in DB",
                        rule->chain_id, rule->name);
            return -1;
        }
        if (!chain.enabled) {
            pf_log_warn("tproxy: chain '%s' (id=%u) is disabled", chain.name, chain.id);
            return -1;
        }
        via_name = chain.name;
        pf_proxy_t pbuf[PF_MAX_PROXIES];
        int pcount = 0;
        pf_config_proxy_list(&ctx->config, pbuf, PF_MAX_PROXIES, &pcount);
        fd = pf_chain_connect(&chain, pbuf, pcount, target, dst_port);

    } else {
        return -1;
    }

    if (fd >= 0) {
        pf_log_info("tproxy: [%s] %s:%d via %s",
                    rule->name, target, dst_port, via_name);

        /* Build rich log entry for IPC + ring buffer */
        cJSON *event = cJSON_CreateObject();
        cJSON_AddNumberToObject(event, "ts", (double)time(NULL));
        cJSON_AddStringToObject(event, "app", rule->app_path[0] ? rule->app_path : rule->name);
        cJSON_AddStringToObject(event, "rule", rule->name);
        cJSON_AddStringToObject(event, "proxy", via_name);
        cJSON_AddNumberToObject(event, "proxy_id", (double)rule->proxy_id);
        cJSON_AddStringToObject(event, "domain", match_domain ? match_domain : "");
        cJSON_AddStringToObject(event, "dst_ip", dst_ip ? dst_ip : "");
        cJSON_AddNumberToObject(event, "dst_port", (double)dst_port);
        cJSON_AddStringToObject(event, "action", pf_action_str(rule->action));
        cJSON_AddNumberToObject(event, "success", 1);
        cJSON_AddNumberToObject(event, "bytes_tx", 0);
        cJSON_AddNumberToObject(event, "bytes_rx", 0);
        cJSON_AddNumberToObject(event, "latency_ms", 0);
        if (event) {
            pf_ipc_broadcast_log(&ctx->ipc, event);

            /* Store in ring buffer with sequence number for polling */
            cJSON *copy = cJSON_Duplicate(event, 1);
            if (copy) {
                cJSON_AddNumberToObject(copy, "seq", (double)(++g_log_seq));
                if (g_log_ring[g_log_ring_head])
                    cJSON_Delete(g_log_ring[g_log_ring_head]);
                g_log_ring[g_log_ring_head] = copy;
                g_log_ring_head = (g_log_ring_head + 1) % PF_LOG_RING_SIZE;
                if (g_log_ring_count < PF_LOG_RING_SIZE) g_log_ring_count++;
            }

            cJSON_Delete(event);
        }
    } else {
        pf_log_error("tproxy: FAILED [%s] %s:%d via %s",
                     rule->name, target, dst_port, via_name);

        cJSON *event = cJSON_CreateObject();
        cJSON_AddNumberToObject(event, "ts", (double)time(NULL));
        cJSON_AddStringToObject(event, "app", rule->app_path[0] ? rule->app_path : rule->name);
        cJSON_AddStringToObject(event, "rule", rule->name);
        cJSON_AddStringToObject(event, "proxy", via_name);
        cJSON_AddNumberToObject(event, "proxy_id", (double)rule->proxy_id);
        cJSON_AddStringToObject(event, "domain", match_domain ? match_domain : "");
        cJSON_AddStringToObject(event, "dst_ip", dst_ip ? dst_ip : "");
        cJSON_AddNumberToObject(event, "dst_port", (double)dst_port);
        cJSON_AddStringToObject(event, "action", pf_action_str(rule->action));
        cJSON_AddNumberToObject(event, "success", 0);
        cJSON_AddNumberToObject(event, "bytes_tx", 0);
        cJSON_AddNumberToObject(event, "bytes_rx", 0);
        cJSON_AddNumberToObject(event, "latency_ms", 0);
        if (event) {
            pf_ipc_broadcast_log(&ctx->ipc, event);

            /* Store in ring buffer with sequence number for polling */
            cJSON *copy = cJSON_Duplicate(event, 1);
            if (copy) {
                cJSON_AddNumberToObject(copy, "seq", (double)(++g_log_seq));
                if (g_log_ring[g_log_ring_head])
                    cJSON_Delete(g_log_ring[g_log_ring_head]);
                g_log_ring[g_log_ring_head] = copy;
                g_log_ring_head = (g_log_ring_head + 1) % PF_LOG_RING_SIZE;
                if (g_log_ring_count < PF_LOG_RING_SIZE) g_log_ring_count++;
            }

            cJSON_Delete(event);
        }
    }

    return fd;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Setup cgroups + nftables marks for all existing app-based rules
 * Called at daemon startup to restore routing state.
 * ────────────────────────────────────────────────────────────────────────── */

static void setup_cgroups_for_existing_rules(pf_ctx_t *ctx)
{
    if (!ctx->ruleset) return;

    int count = 0;
    for (int i = 0; i < ctx->ruleset->count; i++) {
        const pf_rule_t *r = &ctx->ruleset->rules[i];
        if (r->app_path[0] && r->enabled && r->action != PF_ACTION_DIRECT) {
            pf_cgroup_create_rule((int)r->id);
            pf_nft_add_cgroup_mark((int)r->id);
            count++;
        }
    }

    if (count > 0)
        pf_log_info("cgroup/nft: restored %d app-based rule cgroups", count);
}

/* ──────────────────────────────────────────────────────────────────────────
 * IPC request handler
 * ────────────────────────────────────────────────────────────────────────── */

static cJSON *pf_handle_request(pf_ctx_t *ctx, const char *method,
                                 cJSON *params, pf_ipc_client_t *client)
{
    (void)client; /* used selectively */

    cJSON *resp = cJSON_CreateObject();

    /* ── proxy.list ──────────────────────────────────────────────────────── */
    if (strcmp(method, "proxy.list") == 0) {
        pf_proxy_t buf[PF_MAX_PROXIES];
        int count = 0;
        if (pf_config_proxy_list(&ctx->config, buf, PF_MAX_PROXIES, &count) == PF_OK) {
            cJSON *arr = cJSON_CreateArray();
            for (int i = 0; i < count; i++)
                cJSON_AddItemToArray(arr, proxy_to_json(&buf[i]));
            cJSON_AddItemToObject(resp, "result", arr);
        } else {
            cJSON_AddStringToObject(resp, "error", "db error");
        }

    /* ── proxy.add ───────────────────────────────────────────────────────── */
    } else if (strcmp(method, "proxy.add") == 0) {
        if (!params) {
            cJSON_AddStringToObject(resp, "error", "missing params");
        } else {
            pf_proxy_t p;
            proxy_from_json(&p, params);
            if (pf_config_proxy_add(&ctx->config, &p) == PF_OK)
                cJSON_AddStringToObject(resp, "result", "ok");
            else
                cJSON_AddStringToObject(resp, "error", "db error");
        }

    /* ── proxy.edit ──────────────────────────────────────────────────────── */
    } else if (strcmp(method, "proxy.edit") == 0) {
        if (!params) {
            cJSON_AddStringToObject(resp, "error", "missing params");
        } else {
            pf_proxy_t p;
            proxy_from_json(&p, params);
            if (pf_config_proxy_update(&ctx->config, &p) == PF_OK)
                cJSON_AddStringToObject(resp, "result", "ok");
            else
                cJSON_AddStringToObject(resp, "error", "db error");
        }

    /* ── proxy.delete ────────────────────────────────────────────────────── */
    } else if (strcmp(method, "proxy.delete") == 0) {
        cJSON *id_v = params ? cJSON_GetObjectItem(params, "id") : NULL;
        if (!id_v) {
            cJSON_AddStringToObject(resp, "error", "missing id");
        } else {
            int id = (int)id_v->valuedouble;
            int refs = pf_config_proxy_ref_count(&ctx->config, id);
            if (refs > 0) {
                char msg[128];
                snprintf(msg, sizeof(msg),
                         "Proxy is still used by %d rule(s)/chain(s). "
                         "Remove references first.", refs);
                cJSON_AddStringToObject(resp, "error", msg);
            } else if (pf_config_proxy_delete(&ctx->config, id) == PF_OK) {
                cJSON_AddStringToObject(resp, "result", "ok");
            } else {
                cJSON_AddStringToObject(resp, "error", "db error");
            }
        }

    /* ── proxy.test ──────────────────────────────────────────────────────── */
    } else if (strcmp(method, "proxy.test") == 0) {
        cJSON *id_v = params ? cJSON_GetObjectItem(params, "id") : NULL;
        if (!id_v) {
            cJSON_AddStringToObject(resp, "error", "missing id");
        } else {
            int id = (int)id_v->valuedouble;
            pf_proxy_t p;
            if (pf_config_proxy_get(&ctx->config, id, &p) != PF_OK) {
                cJSON_AddStringToObject(resp, "error", "proxy not found");
            } else {
                int latency = -1;
                if      (p.type == PF_PROXY_SOCKS4 || p.type == PF_PROXY_SOCKS5)
                    latency = pf_socks_test(&p);
                else if (p.type == PF_PROXY_HTTP)
                    latency = pf_http_test(&p);
                else if (p.type == PF_PROXY_SSH)
                    latency = pf_ssh_test(&ctx->ssh_pool, &p);

                cJSON *r = cJSON_CreateObject();
                cJSON_AddNumberToObject(r, "latency_ms", latency);
                cJSON_AddStringToObject(r, "health",
                    latency >= 0 ? (latency > 1000 ? "slow" : "online") : "offline");
                cJSON_AddItemToObject(resp, "result", r);

                /* update health in DB */
                pf_health_t h = (latency < 0) ? PF_HEALTH_OFFLINE
                              : (latency > 1000) ? PF_HEALTH_SLOW : PF_HEALTH_ONLINE;
                pf_config_proxy_update_health(&ctx->config, id, h, latency);
            }
        }

    /* ── rule.list ───────────────────────────────────────────────────────── */
    } else if (strcmp(method, "rule.list") == 0) {
        pf_rule_t *buf = calloc(PF_MAX_RULES, sizeof(pf_rule_t));
        int count = 0;
        if (!buf) {
            cJSON_AddStringToObject(resp, "error", "out of memory");
        } else if (pf_config_rule_list(&ctx->config, buf, PF_MAX_RULES, &count) == PF_OK) {
            cJSON *arr = cJSON_CreateArray();
            for (int i = 0; i < count; i++)
                cJSON_AddItemToArray(arr, rule_to_json(&buf[i]));
            cJSON_AddItemToObject(resp, "result", arr);
        } else {
            cJSON_AddStringToObject(resp, "error", "db error");
        }
        free(buf);

    /* ── rule.add ────────────────────────────────────────────────────────── */
    } else if (strcmp(method, "rule.add") == 0) {
        if (!params) {
            cJSON_AddStringToObject(resp, "error", "missing params");
        } else {
            pf_rule_t r;
            rule_from_json(&r, params);
            if (pf_config_rule_add(&ctx->config, &r) == PF_OK) {
                int new_id = pf_config_last_id(&ctx->config);

                /* Set up cgroup + nftables mark for app-based rules */
                if (r.app_path[0] && r.action != PF_ACTION_DIRECT) {
                    pf_cgroup_create_rule(new_id);
                    pf_nft_add_cgroup_mark(new_id);
                    pf_log_info("rule.add: cgroup+nft mark set up for rule_%d (app=%s)",
                                new_id, r.app_path);
                }

                /* reload ruleset */
                pf_rules_load(ctx->ruleset, &ctx->config);
                cJSON_AddStringToObject(resp, "result", "ok");
            } else {
                cJSON_AddStringToObject(resp, "error", "db error");
            }
        }

    /* ── rule.edit ───────────────────────────────────────────────────────── */
    } else if (strcmp(method, "rule.edit") == 0) {
        if (!params) {
            cJSON_AddStringToObject(resp, "error", "missing params");
        } else {
            pf_rule_t r;
            rule_from_json(&r, params);
            if (pf_config_rule_update(&ctx->config, &r) == PF_OK) {
                /* Sync cgroup + nft mark for app-based rules */
                if (r.app_path[0] && r.enabled && r.action != PF_ACTION_DIRECT) {
                    pf_cgroup_create_rule((int)r.id);
                    pf_nft_add_cgroup_mark((int)r.id);
                } else {
                    /* Disabled or no app — remove cgroup mark */
                    pf_nft_remove_cgroup_mark((int)r.id);
                    pf_cgroup_remove_rule((int)r.id);
                }
                pf_rules_load(ctx->ruleset, &ctx->config);
                cJSON_AddStringToObject(resp, "result", "ok");
            } else {
                cJSON_AddStringToObject(resp, "error", "db error");
            }
        }

    /* ── rule.delete ─────────────────────────────────────────────────────── */
    } else if (strcmp(method, "rule.delete") == 0) {
        cJSON *id_v = params ? cJSON_GetObjectItem(params, "id") : NULL;
        if (!id_v) {
            cJSON_AddStringToObject(resp, "error", "missing id");
        } else {
            int id = (int)id_v->valuedouble;

            /* Clean up cgroup + nft mark before deleting */
            pf_cgroup_remove_rule(id);
            pf_nft_remove_cgroup_mark(id);

            if (pf_config_rule_delete(&ctx->config, id) == PF_OK) {
                pf_rules_load(ctx->ruleset, &ctx->config);
                cJSON_AddStringToObject(resp, "result", "ok");
            } else {
                cJSON_AddStringToObject(resp, "error", "db error");
            }
        }

    /* ── chain.list ──────────────────────────────────────────────────────── */
    } else if (strcmp(method, "chain.list") == 0) {
        pf_chain_t buf[PF_MAX_CHAINS];
        int count = 0;
        if (pf_config_chain_list(&ctx->config, buf, PF_MAX_CHAINS, &count) == PF_OK) {
            cJSON *arr = cJSON_CreateArray();
            for (int i = 0; i < count; i++)
                cJSON_AddItemToArray(arr, chain_to_json(&buf[i]));
            cJSON_AddItemToObject(resp, "result", arr);
        } else {
            cJSON_AddStringToObject(resp, "error", "db error");
        }

    /* ── chain.add ───────────────────────────────────────────────────────── */
    } else if (strcmp(method, "chain.add") == 0) {
        if (!params) {
            cJSON_AddStringToObject(resp, "error", "missing params");
        } else {
            pf_chain_t c;
            chain_from_json(&c, params);
            if (pf_config_chain_add(&ctx->config, &c) == PF_OK)
                cJSON_AddStringToObject(resp, "result", "ok");
            else
                cJSON_AddStringToObject(resp, "error", "db error");
        }

    /* ── chain.edit ──────────────────────────────────────────────────────── */
    } else if (strcmp(method, "chain.edit") == 0) {
        if (!params) {
            cJSON_AddStringToObject(resp, "error", "missing params");
        } else {
            pf_chain_t c;
            chain_from_json(&c, params);
            if (pf_config_chain_update(&ctx->config, &c) == PF_OK)
                cJSON_AddStringToObject(resp, "result", "ok");
            else
                cJSON_AddStringToObject(resp, "error", "db error");
        }

    /* ── chain.delete ────────────────────────────────────────────────────── */
    } else if (strcmp(method, "chain.delete") == 0) {
        cJSON *id_v = params ? cJSON_GetObjectItem(params, "id") : NULL;
        if (!id_v) {
            cJSON_AddStringToObject(resp, "error", "missing id");
        } else {
            int id = (int)id_v->valuedouble;
            int refs = pf_config_chain_ref_count(&ctx->config, id);
            if (refs > 0) {
                char msg[128];
                snprintf(msg, sizeof(msg),
                         "Chain is still used by %d rule(s). "
                         "Remove references first.", refs);
                cJSON_AddStringToObject(resp, "error", msg);
            } else if (pf_config_chain_delete(&ctx->config, id) == PF_OK) {
                cJSON_AddStringToObject(resp, "result", "ok");
            } else {
                cJSON_AddStringToObject(resp, "error", "db error");
            }
        }

    /* ── chain.test ──────────────────────────────────────────────────────── */
    } else if (strcmp(method, "chain.test") == 0) {
        cJSON *id_v = params ? cJSON_GetObjectItem(params, "id") : NULL;
        if (!id_v) {
            cJSON_AddStringToObject(resp, "error", "missing id");
        } else {
            int id = (int)id_v->valuedouble;
            pf_chain_t c;
            if (pf_config_chain_get(&ctx->config, id, &c) != PF_OK) {
                cJSON_AddStringToObject(resp, "error", "chain not found");
            } else {
                pf_proxy_t pbuf[PF_MAX_PROXIES];
                int pcount = 0;
                pf_config_proxy_list(&ctx->config, pbuf, PF_MAX_PROXIES, &pcount);
                int latency = pf_chain_test(&c, pbuf, pcount);
                cJSON *r = cJSON_CreateObject();
                cJSON_AddNumberToObject(r, "latency_ms", latency);
                cJSON_AddStringToObject(r, "health",
                    latency >= 0 ? (latency > 2000 ? "slow" : "online") : "offline");
                cJSON_AddItemToObject(resp, "result", r);
            }
        }

    /* ── rule.reorder ───────────────────────────────────────────────────── */
    } else if (strcmp(method, "rule.reorder") == 0) {
        cJSON *ids = params ? cJSON_GetObjectItem(params, "ids") : NULL;
        if (!ids || !cJSON_IsArray(ids)) {
            cJSON_AddStringToObject(resp, "error", "missing ids array");
        } else {
            int n = cJSON_GetArraySize(ids);
            int ok = 1;
            for (int ri = 0; ri < n; ri++) {
                int rule_id = (int)cJSON_GetArrayItem(ids, ri)->valuedouble;
                /* Set priority = position in the new order */
                char sql[128];
                snprintf(sql, sizeof(sql),
                    "UPDATE rules SET priority=%d WHERE id=%d;", ri, rule_id);
                if (sqlite3_exec(ctx->config.db, sql, NULL, NULL, NULL) != SQLITE_OK)
                    ok = 0;
            }
            if (ok) {
                pf_rules_load(ctx->ruleset, &ctx->config);
                cJSON_AddStringToObject(resp, "result", "ok");
            } else {
                cJSON_AddStringToObject(resp, "error", "db error");
            }
        }

    /* ── config.get ──────────────────────────────────────────────────────── */
    } else if (strcmp(method, "config.get") == 0) {
        cJSON *key_v = params ? cJSON_GetObjectItem(params, "key") : NULL;
        if (!key_v || !key_v->valuestring) {
            cJSON_AddStringToObject(resp, "error", "missing key");
        } else {
            char value[PF_BUF_SIZE] = {0};
            if (pf_config_get(&ctx->config, key_v->valuestring, value, (int)sizeof(value)) == PF_OK)
                cJSON_AddStringToObject(resp, "result", value);
            else
                cJSON_AddStringToObject(resp, "error", "key not found");
        }

    /* ── config.set ──────────────────────────────────────────────────────── */
    } else if (strcmp(method, "config.set") == 0) {
        cJSON *key_v = params ? cJSON_GetObjectItem(params, "key")   : NULL;
        cJSON *val_v = params ? cJSON_GetObjectItem(params, "value") : NULL;
        if (!key_v || !key_v->valuestring || !val_v || !val_v->valuestring) {
            cJSON_AddStringToObject(resp, "error", "missing key or value");
        } else {
            const char *key = key_v->valuestring;
            const char *val = val_v->valuestring;

            /* special: boot_enabled → systemctl enable/disable */
            if (strcmp(key, "boot_enabled") == 0) {
                const char *cmd = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0)
                    ? "systemctl enable proxiflare.service >/dev/null 2>&1"
                    : "systemctl disable proxiflare.service >/dev/null 2>&1";
                system(cmd);
            }

            if (pf_config_set(&ctx->config, key, val) == PF_OK)
                cJSON_AddStringToObject(resp, "result", "ok");
            else
                cJSON_AddStringToObject(resp, "error", "db error");
        }

    /* ── credentials.unlock ──────────────────────────────────────────────── */
    } else if (strcmp(method, "credentials.unlock") == 0) {
        cJSON *pw_v = params ? cJSON_GetObjectItem(params, "password") : NULL;
        if (!pw_v || !pw_v->valuestring) {
            cJSON_AddStringToObject(resp, "error", "missing password");
        } else {
            /* load salt from config */
            char salt_hex[64] = {0};
            uint8_t salt[PF_SALT_LEN] = {0};
            if (pf_config_get(&ctx->config, "crypto_salt", salt_hex, (int)sizeof(salt_hex)) == PF_OK) {
                /* salt stored as hex — decode */
                for (int i = 0; i < PF_SALT_LEN && (size_t)(i * 2 + 1) < strlen(salt_hex); i++) {
                    unsigned int byte;
                    sscanf(salt_hex + i * 2, "%02x", &byte);
                    salt[i] = (uint8_t)byte;
                }
            } else {
                /* no salt yet — generate and persist */
                pf_crypto_random_salt(salt, PF_SALT_LEN);
                char new_hex[PF_SALT_LEN * 2 + 1];
                for (int i = 0; i < PF_SALT_LEN; i++)
                    snprintf(new_hex + i * 2, 3, "%02x", salt[i]);
                pf_config_set(&ctx->config, "crypto_salt", new_hex);
            }

            if (pf_crypto_unlock(&ctx->crypto, pw_v->valuestring, salt) == PF_OK)
                cJSON_AddStringToObject(resp, "result", "ok");
            else
                cJSON_AddStringToObject(resp, "error", "unlock failed");
        }

    /* ── credentials.lock ────────────────────────────────────────────────── */
    } else if (strcmp(method, "credentials.lock") == 0) {
        pf_crypto_lock(&ctx->crypto);
        cJSON_AddStringToObject(resp, "result", "ok");

    /* ── system.status ───────────────────────────────────────────────────── */
    } else if (strcmp(method, "system.status") == 0) {
        char dns_leak_enabled[8] = "false";
        char dns_server_val[64]  = "1.1.1.1";
        pf_config_get(&ctx->config, "dns_leak_enabled", dns_leak_enabled, (int)sizeof(dns_leak_enabled));
        pf_config_get(&ctx->config, "dns_server",       dns_server_val,   (int)sizeof(dns_server_val));

        /* Count proxies online and rules active */
        int proxies_online = 0;
        {
            pf_proxy_t pbuf[PF_MAX_PROXIES];
            int pcount = 0;
            if (pf_config_proxy_list(&ctx->config, pbuf, PF_MAX_PROXIES, &pcount) == PF_OK) {
                for (int pi = 0; pi < pcount; pi++) {
                    if (pbuf[pi].enabled && pbuf[pi].health == PF_HEALTH_ONLINE)
                        proxies_online++;
                }
            }
        }
        int rules_active = ctx->ruleset ? 0 : 0;
        if (ctx->ruleset) {
            for (int ri = 0; ri < ctx->ruleset->count; ri++) {
                if (ctx->ruleset->rules[ri].enabled)
                    rules_active++;
            }
        }

        cJSON *r = cJSON_CreateObject();
        cJSON_AddBoolToObject  (r, "running",    ctx->running ? true : false);
        cJSON_AddStringToObject(r, "version",    PF_VERSION);
        cJSON_AddNumberToObject(r, "connections", ctx->tproxy.conn_count);
        cJSON_AddNumberToObject(r, "proxies_online", proxies_online);
        cJSON_AddNumberToObject(r, "rules_active",   rules_active);
        cJSON_AddBoolToObject  (r, "crypto_unlocked", ctx->crypto.unlocked);
        cJSON_AddBoolToObject  (r, "dns_active",  ctx->dns.fd > 0);
        cJSON_AddBoolToObject  (r, "tproxy_active", ctx->tproxy.listen_fd > 0);
        cJSON_AddBoolToObject  (r, "dns_leak_enabled", strcmp(dns_leak_enabled, "true") == 0);
        cJSON_AddStringToObject(r, "dns_server",       dns_server_val);
        cJSON_AddItemToObject  (resp, "result", r);

    /* ── system.version ──────────────────────────────────────────────────── */
    } else if (strcmp(method, "system.version") == 0) {
        cJSON_AddStringToObject(resp, "result", PF_VERSION);

    /* ── system.shutdown ─────────────────────────────────────────────────── */
    } else if (strcmp(method, "system.shutdown") == 0) {
        pf_log_info("Shutdown requested via IPC");
        cJSON_AddStringToObject(resp, "result", "shutting down");
        /* Set running=false to exit main loop after sending response */
        ctx->running = 0;

    /* ── dns_leak.enable ────────────────────────────────────────────────── */
    } else if (strcmp(method, "dns_leak.enable") == 0) {
        cJSON *server_v = params ? cJSON_GetObjectItem(params, "dns_server") : NULL;
        const char *dns = (server_v && server_v->valuestring && server_v->valuestring[0])
                          ? server_v->valuestring : "1.1.1.1";
        if (pf_nft_dns_leak_protect(dns) == PF_OK) {
            pf_config_set(&ctx->config, "dns_leak_enabled", "true");
            pf_config_set(&ctx->config, "dns_server", dns);
            cJSON_AddStringToObject(resp, "result", "ok");
        } else {
            cJSON_AddStringToObject(resp, "error", "failed to set DNS rules");
        }

    /* ── dns_leak.disable ───────────────────────────────────────────────── */
    } else if (strcmp(method, "dns_leak.disable") == 0) {
        pf_nft_dns_leak_disable();
        pf_config_set(&ctx->config, "dns_leak_enabled", "false");
        cJSON_AddStringToObject(resp, "result", "ok");

    /* ── dns_leak.status ────────────────────────────────────────────────── */
    } else if (strcmp(method, "dns_leak.status") == 0) {
        char enabled[8]  = "false";
        char server[64]  = "1.1.1.1";
        pf_config_get(&ctx->config, "dns_leak_enabled", enabled, (int)sizeof(enabled));
        pf_config_get(&ctx->config, "dns_server",       server,  (int)sizeof(server));
        cJSON *r = cJSON_CreateObject();
        cJSON_AddBoolToObject  (r, "enabled",    strcmp(enabled, "true") == 0);
        cJSON_AddStringToObject(r, "dns_server", server);
        cJSON_AddItemToObject  (resp, "result", r);

    /* ── log.recent ─────────────────────────────────────────────────────── */
    } else if (strcmp(method, "log.recent") == 0) {
        int since_seq = 0;
        cJSON *since = params ? cJSON_GetObjectItem(params, "since_seq") : NULL;
        if (since) since_seq = (int)since->valuedouble;

        cJSON *arr = cJSON_CreateArray();
        for (int i = 0; i < g_log_ring_count; i++) {
            int idx = (g_log_ring_head - g_log_ring_count + i + PF_LOG_RING_SIZE) % PF_LOG_RING_SIZE;
            if (g_log_ring[idx]) {
                cJSON *seq_item = cJSON_GetObjectItem(g_log_ring[idx], "seq");
                if (seq_item && seq_item->valuedouble > since_seq) {
                    cJSON_AddItemToArray(arr, cJSON_Duplicate(g_log_ring[idx], 1));
                }
            }
        }
        cJSON_AddItemToObject(resp, "result", arr);

    /* ── inspect.list ──────────────────────────────────────────────────── */
    } else if (strcmp(method, "inspect.list") == 0) {
        int since_seq = 0;
        cJSON *since = params ? cJSON_GetObjectItem(params, "since_seq") : NULL;
        if (since) since_seq = (int)since->valuedouble;

        cJSON *arr = cJSON_CreateArray();
        for (int ii = 0; ii < g_inspect_ring_count; ii++) {
            int idx = (g_inspect_ring_head - g_inspect_ring_count + ii + PF_INSPECT_RING_SIZE)
                      % PF_INSPECT_RING_SIZE;
            if (g_inspect_ring[idx]) {
                cJSON *seq_item = cJSON_GetObjectItem(g_inspect_ring[idx], "seq");
                if (seq_item && seq_item->valuedouble > since_seq)
                    cJSON_AddItemToArray(arr, cJSON_Duplicate(g_inspect_ring[idx], 1));
            }
        }
        cJSON_AddItemToObject(resp, "result", arr);

    /* ── inspect.enable ─────────────────────────────────────────────────── */
    } else if (strcmp(method, "inspect.enable") == 0) {
        if (!ctx->mitm.ca_key) {
            cJSON_AddStringToObject(resp, "error",
                "CA not generated. Run: sudo proxiflare-daemon --generate-ca");
        } else {
            ctx->mitm.enabled = 1;
            pf_config_set(&ctx->config, "inspect_enabled", "true");
            cJSON_AddStringToObject(resp, "result", "ok");
            pf_log_info("mitm: inspection ENABLED");
        }

    /* ── inspect.disable ────────────────────────────────────────────────── */
    } else if (strcmp(method, "inspect.disable") == 0) {
        ctx->mitm.enabled = 0;
        pf_config_set(&ctx->config, "inspect_enabled", "false");
        cJSON_AddStringToObject(resp, "result", "ok");
        pf_log_info("mitm: inspection DISABLED");

    /* ── inspect.status ─────────────────────────────────────────────────── */
    } else if (strcmp(method, "inspect.status") == 0) {
        cJSON *r = cJSON_CreateObject();
        cJSON_AddBoolToObject(r, "enabled", ctx->mitm.enabled ? 1 : 0);
        cJSON_AddBoolToObject(r, "ca_installed", ctx->mitm.ca_key ? 1 : 0);
        cJSON_AddStringToObject(r, "ca_cert_path", PF_MITM_CA_CERT_PATH);
        cJSON_AddNumberToObject(r, "cached_certs", ctx->mitm.cache_count);
        cJSON_AddItemToObject(resp, "result", r);

    /* ── inspect.generate_ca ────────────────────────────────────────────── */
    } else if (strcmp(method, "inspect.generate_ca") == 0) {
        if (pf_mitm_generate_ca() == PF_OK) {
            /* Reload CA into the running engine */
            pf_mitm_close(&ctx->mitm);
            if (pf_mitm_init(&ctx->mitm) == PF_OK)
                cJSON_AddStringToObject(resp, "result", "ok");
            else
                cJSON_AddStringToObject(resp, "error", "CA generated but init failed");
        } else {
            cJSON_AddStringToObject(resp, "error", "CA generation failed");
        }

    /* ── unknown ─────────────────────────────────────────────────────────── */
    } else {
        cJSON_AddStringToObject(resp, "error", "unknown method");
    }

    return resp;
}

/* ──────────────────────────────────────────────────────────────────────────
 * epoll helpers
 * ────────────────────────────────────────────────────────────────────────── */

static int epoll_add(int epfd, int fd, uint32_t events)
{
    if (fd < 0) return -1;
    struct epoll_event ev;
    ev.events  = events;
    ev.data.fd = fd;
    return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
}

static int epoll_del(int epfd, int fd)
{
    if (fd < 0) return -1;
    return epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
}

/* ──────────────────────────────────────────────────────────────────────────
 * MITM handshake thread — runs SSL handshakes without blocking epoll loop
 *
 * The thread makes fds blocking, does SSL_connect + SSL_accept, then
 * makes fds non-blocking again and registers them in the main epoll.
 * If handshake fails, the connection proceeds without MITM (passthrough).
 * ────────────────────────────────────────────────────────────────────────── */

typedef struct {
    pf_mitm_t       *mitm;
    pf_connection_t *conn;
    int              epoll_fd;
    int              slot;
    pf_tproxy_t     *tproxy;
} mitm_thread_arg_t;

static void *mitm_handshake_thread(void *arg_raw)
{
    mitm_thread_arg_t *arg = (mitm_thread_arg_t *)arg_raw;
    pf_connection_t *c = arg->conn;
    int fl;

    /* Set blocking + timeout for handshake */
    fl = fcntl(c->proxy_fd, F_GETFL, 0);
    fcntl(c->proxy_fd, F_SETFL, fl & ~O_NONBLOCK);
    fl = fcntl(c->client_fd, F_GETFL, 0);
    fcntl(c->client_fd, F_SETFL, fl & ~O_NONBLOCK);

    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(c->proxy_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(c->proxy_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(c->client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(c->client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* 1. Connect TLS to real server (via proxy tunnel) */
    c->server_ssl = pf_mitm_wrap_server(arg->mitm, c->proxy_fd, c->domain);
    if (c->server_ssl) {
        /* 2. Accept TLS from client (present fake cert) */
        c->client_ssl = pf_mitm_wrap_client(arg->mitm, c->client_fd, c->domain);
        if (c->client_ssl) {
            c->inspect = true;
            pf_log_info("mitm: INSPECT active for %s:%d", c->domain, c->dst_port);
        } else {
            SSL_free(c->server_ssl);
            c->server_ssl = NULL;
            pf_log_warn("mitm: client wrap failed for %s (passthrough)", c->domain);
        }
    } else {
        pf_log_warn("mitm: server wrap failed for %s (passthrough)", c->domain);
    }

    /* Restore non-blocking + clear timeout */
    struct timeval notv = { .tv_sec = 0, .tv_usec = 0 };
    fl = fcntl(c->proxy_fd, F_GETFL, 0);
    fcntl(c->proxy_fd, F_SETFL, fl | O_NONBLOCK);
    fl = fcntl(c->client_fd, F_GETFL, 0);
    fcntl(c->client_fd, F_SETFL, fl | O_NONBLOCK);
    setsockopt(c->proxy_fd, SOL_SOCKET, SO_RCVTIMEO, &notv, sizeof(notv));
    setsockopt(c->proxy_fd, SOL_SOCKET, SO_SNDTIMEO, &notv, sizeof(notv));
    setsockopt(c->client_fd, SOL_SOCKET, SO_RCVTIMEO, &notv, sizeof(notv));
    setsockopt(c->client_fd, SOL_SOCKET, SO_SNDTIMEO, &notv, sizeof(notv));

    /* Register fds in epoll — thread-safe for EPOLL_CTL_ADD */
    if (c->active) {
        struct epoll_event ev;
        ev.events  = EPOLLIN;
        ev.data.fd = c->client_fd;
        epoll_ctl(arg->epoll_fd, EPOLL_CTL_ADD, c->client_fd, &ev);
        ev.data.fd = c->proxy_fd;
        epoll_ctl(arg->epoll_fd, EPOLL_CTL_ADD, c->proxy_fd, &ev);
    }

    free(arg);
    return NULL;
}

/* ──────────────────────────────────────────────────────────────────────────
 * PID file
 * ────────────────────────────────────────────────────────────────────────── */

static int write_pid_file(const char *path)
{
    /* ensure directory exists */
    char dir[PF_PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        mkdir(dir, 0755);
    }

    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "%d\n", getpid());
    fclose(f);
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * main()
 * ────────────────────────────────────────────────────────────────────────── */

#define MAX_EVENTS 64

int main(int argc, char *argv[])
{
    int foreground = 0;
    const char *config_dir = PF_CONFIG_DIR;
    char db_path[PF_PATH_MAX];
    char sock_path[PF_PATH_MAX];
    char log_path[PF_PATH_MAX];

    /* ── 1. Parse args ─────────────────────────────────────────────────── */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--foreground") == 0) {
            foreground = 1;
        } else if (strcmp(argv[i], "--config-dir") == 0 && i + 1 < argc) {
            config_dir = argv[++i];
        } else if (strcmp(argv[i], "--generate-ca") == 0) {
            /* Generate CA cert and exit */
            if (pf_mitm_generate_ca() == PF_OK) {
                printf("CA generated:\n  Key:  %s\n  Cert: %s\n\n"
                       "Import the cert in your browser to enable HTTPS inspection.\n"
                       "Firefox: Preferences → Certificates → Import\n"
                       "System:  sudo cp %s /usr/local/share/ca-certificates/proxiflare.crt "
                       "&& sudo update-ca-certificates\n",
                       PF_MITM_CA_KEY_PATH, PF_MITM_CA_CERT_PATH, PF_MITM_CA_CERT_PATH);
                return 0;
            } else {
                fprintf(stderr, "ERROR: CA generation failed\n");
                return 1;
            }
        } else {
            fprintf(stderr, "Usage: %s [--foreground] [--config-dir PATH] [--generate-ca]\n", argv[0]);
            return 1;
        }
    }

    /* Use compiled-in default paths (config_dir reserved for future override) */
    snprintf(db_path,   sizeof(db_path),   "%s", PF_DB_PATH);
    snprintf(sock_path, sizeof(sock_path), "%s", PF_SOCKET_PATH);
    snprintf(log_path,  sizeof(log_path),  "%s", PF_LOG_PATH);
    (void)config_dir; /* reserved for future config file override */

    /* ── 2. Root check ─────────────────────────────────────────────────── */
    if (getuid() != 0) {
        fprintf(stderr, "[proxiflare] WARNING: not running as root — "
                        "kernel features (NFQUEUE, tproxy, cgroups) will be disabled\n");
    }

    /* ── 3. Daemonize (unless --foreground) ───────────────────────────── */
    if (!foreground) {
        /* Don't daemonize when run under systemd (it manages the process).
         * For standalone use: fork + setsid + close stdio.
         * We leave it simple: daemonize only when explicitly not foreground.
         * Currently a no-op placeholder — systemd unit uses --foreground. */
        (void)0;
    }

    /* ── 4. PID file ───────────────────────────────────────────────────── */
    if (write_pid_file(PF_PID_FILE) < 0) {
        fprintf(stderr, "[proxiflare] WARNING: cannot write PID file %s: %s\n",
                PF_PID_FILE, strerror(errno));
    }

    /* ── 5. Signal handlers ────────────────────────────────────────────── */
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sig_handler;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGINT,  &sa, NULL);
        sa.sa_handler = sig_hup;
        sigaction(SIGHUP,  &sa, NULL);
        /* ignore SIGPIPE — write() on closed sockets returns EPIPE */
        signal(SIGPIPE, SIG_IGN);
    }

    /* ── 6. Init context ───────────────────────────────────────────────── */
    memset(&g_ctx, 0, sizeof(g_ctx));
    pf_ctx_t *ctx = &g_ctx;
    ctx->running = 1;

    /* 5a. Config (SQLite) */
    if (pf_config_init(&ctx->config, db_path) != PF_OK) {
        fprintf(stderr, "[proxiflare] FATAL: config_init failed (%s)\n", db_path);
        return 1;
    }
    pf_log_info("Config DB opened: %s", db_path);

    /* 5b. Crypto */
    if (pf_crypto_init(&ctx->crypto) != PF_OK) {
        fprintf(stderr, "[proxiflare] FATAL: crypto_init failed\n");
        pf_config_close(&ctx->config);
        return 1;
    }
    pf_log_info("Crypto subsystem ready (locked)");

    /* 5c. Logger */
    if (pf_logger_init(&ctx->logger, log_path) != PF_OK) {
        fprintf(stderr, "[proxiflare] WARNING: logger_init failed — disk logging disabled\n");
    } else {
        pf_log_info("Logger ready: %s", log_path);
    }

    /* 5d. Ruleset (heap) */
    ctx->ruleset = calloc(1, sizeof(pf_ruleset_t));
    if (!ctx->ruleset) {
        fprintf(stderr, "[proxiflare] FATAL: cannot allocate ruleset (%zu bytes)\n",
                sizeof(pf_ruleset_t));
        pf_logger_close(&ctx->logger);
        pf_config_close(&ctx->config);
        return 1;
    }
    if (pf_rules_load(ctx->ruleset, &ctx->config) != PF_OK) {
        pf_log_warn("rules_load failed — starting with empty ruleset");
    } else {
        pf_log_info("Rules loaded: %d rules", ctx->ruleset->count);
    }

    /* 5e. IPC server (must always succeed) */
    if (pf_ipc_init(&ctx->ipc, sock_path, ctx, pf_handle_request) < 0) {
        fprintf(stderr, "[proxiflare] FATAL: ipc_init failed (%s)\n", sock_path);
        free(ctx->ruleset);
        pf_logger_close(&ctx->logger);
        pf_config_close(&ctx->config);
        return 1;
    }
    pf_log_info("IPC listening on %s", sock_path);

    /* 5f. Stats */
    if (pf_stats_init(&ctx->stats) != PF_OK)
        pf_log_warn("stats_init failed — stats disabled");

    /* 5g. SSH pool */
    if (pf_ssh_pool_init(&ctx->ssh_pool) != PF_OK)
        pf_log_warn("ssh_pool_init failed — SSH proxies will not work");

    /* 5g-bis. MITM engine */
    if (pf_mitm_init(&ctx->mitm) != PF_OK) {
        pf_log_warn("mitm_init failed — HTTPS interception disabled");
    } else {
        pf_tproxy_set_inspect_cb(on_inspect_data, ctx);
        /* Restore inspect state from config */
        char inspect_val[8] = "false";
        pf_config_get(&ctx->config, "inspect_enabled", inspect_val, (int)sizeof(inspect_val));
        if (strcmp(inspect_val, "true") == 0 && ctx->mitm.ca_key) {
            ctx->mitm.enabled = 1;
            pf_log_info("mitm: inspection restored (enabled)");
        }
    }

    /* 5h. DNS (NFQUEUE) — optional, requires root + kernel module */
    if (pf_dns_init(&ctx->dns, ctx->ruleset) != PF_OK) {
        pf_log_warn("dns_init failed — DNS-based routing disabled "
                    "(requires root and nf_queue kernel module)");
        ctx->dns.fd = -1;
    } else {
        pf_log_info("DNS NFQUEUE active (fd=%d)", ctx->dns.fd);
    }

    /* 5i. nftables — optional, requires root */
    if (pf_nft_init() != PF_OK) {
        pf_log_warn("nft_init failed — nftables rules not installed "
                    "(requires root and nftables)");
    } else {
        if (pf_nft_setup_dns_redirect() != PF_OK)
            pf_log_warn("nft_setup_dns_redirect failed");
        if (pf_nft_setup_tproxy(PF_TPROXY_PORT) != PF_OK)
            pf_log_warn("nft_setup_tproxy failed");
        pf_log_info("nftables rules installed");

        /* Restore DNS leak protection if it was active before daemon restart */
        {
            char dns_leak[8]    = "false";
            char dns_server[64] = "1.1.1.1";
            pf_config_get(&ctx->config, "dns_leak_enabled", dns_leak, (int)sizeof(dns_leak));
            if (strcmp(dns_leak, "true") == 0) {
                pf_config_get(&ctx->config, "dns_server", dns_server, (int)sizeof(dns_server));
                if (pf_nft_dns_leak_protect(dns_server) == PF_OK)
                    pf_log_info("DNS leak protection restored (server: %s)", dns_server);
                else
                    pf_log_warn("DNS leak protection restore failed");
            }
        }
    }

    /* 5j. cgroups — optional, requires root */
    if (pf_cgroup_init() != PF_OK) {
        pf_log_warn("cgroup_init failed — per-app routing disabled "
                    "(requires root and cgroup v2)");
    } else {
        pf_log_info("cgroup hierarchy ready at %s", PF_CGROUP_BASE);
    }

    /* 5k. TPROXY — optional, requires root + nft setup */
    if (pf_tproxy_init(&ctx->tproxy, PF_TPROXY_PORT) != PF_OK) {
        pf_log_warn("tproxy_init failed — transparent proxy disabled "
                    "(requires root and IP_TRANSPARENT)");
        ctx->tproxy.listen_fd = -1;
    } else {
        /* Wire up the proxy connect callback so TPROXY can route through proxies */
        pf_tproxy_set_connect_cb(&ctx->tproxy, proxy_connect_for_tproxy, ctx);
        pf_log_info("TPROXY listening on port %d (proxy routing active)", PF_TPROXY_PORT);
    }

    /* 5k-bis. Restore cgroup + nft marks for all existing app-based rules */
    setup_cgroups_for_existing_rules(ctx);

    /* 5l. Process monitor (netlink) — optional, requires root */
    if (pf_monitor_init(&ctx->monitor, on_process_event, ctx) != PF_OK) {
        pf_log_warn("monitor_init failed — process exec monitoring disabled "
                    "(requires root and CN_PROC netlink)");
        ctx->monitor.nl_fd = -1;
    } else {
        pf_log_info("Process monitor active (fd=%d)", ctx->monitor.nl_fd);
    }

    /* ── 7. Create epoll, register fds ────────────────────────────────── */
    ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (ctx->epoll_fd < 0) {
        pf_log_error("epoll_create1 failed: %s", strerror(errno));
        goto shutdown;
    }

    /* IPC listen fd — always present */
    if (epoll_add(ctx->epoll_fd, ctx->ipc.listen_fd, EPOLLIN) < 0)
        pf_log_error("epoll_add ipc.listen_fd failed: %s", strerror(errno));

    /* DNS fd */
    if (ctx->dns.fd > 0)
        epoll_add(ctx->epoll_fd, ctx->dns.fd, EPOLLIN);

    /* TPROXY listen fd */
    if (ctx->tproxy.listen_fd > 0)
        epoll_add(ctx->epoll_fd, ctx->tproxy.listen_fd, EPOLLIN);

    /* Monitor netlink fd */
    if (ctx->monitor.nl_fd > 0)
        epoll_add(ctx->epoll_fd, ctx->monitor.nl_fd, EPOLLIN);

    pf_log_info("ProxiFlare daemon v%s started (pid=%d)", PF_VERSION, getpid());

    /* ── 8. Main event loop ────────────────────────────────────────────── */
    {
        struct epoll_event events[MAX_EVENTS];

        while (ctx->running) {

            /* Check for config reload (SIGHUP) */
            if (g_reload) {
                g_reload = 0;
                pf_log_info("SIGHUP received — reloading config and ruleset");
                pf_rules_load(ctx->ruleset, &ctx->config);
            }

            int nev = epoll_wait(ctx->epoll_fd, events, MAX_EVENTS, 1000 /* ms */);
            if (nev < 0) {
                if (errno == EINTR) continue;
                pf_log_error("epoll_wait: %s", strerror(errno));
                break;
            }

            for (int i = 0; i < nev; i++) {
                int fd = events[i].data.fd;

                /* ── IPC: new client connection ────────────────────────── */
                if (fd == ctx->ipc.listen_fd) {
                    int idx = pf_ipc_accept(&ctx->ipc);
                    if (idx >= 0) {
                        int cfd = ctx->ipc.clients[idx].fd;
                        if (epoll_add(ctx->epoll_fd, cfd, EPOLLIN) < 0)
                            pf_log_warn("epoll_add ipc client fd failed");
                    }
                    continue;
                }

                /* ── DNS NFQUEUE ───────────────────────────────────────── */
                if (ctx->dns.fd > 0 && fd == ctx->dns.fd) {
                    pf_dns_process(&ctx->dns);
                    continue;
                }

                /* ── TPROXY: new connection ────────────────────────────── */
                /* The entire accept+proxy_connect+MITM runs in a thread
                 * to keep the main epoll loop responsive for DNS/IPC. */
                if (ctx->tproxy.listen_fd > 0 && fd == ctx->tproxy.listen_fd) {
                    int slot = pf_tproxy_accept(&ctx->tproxy);
                    if (slot >= 0 && ctx->tproxy.conns[slot].active) {
                        pf_connection_t *c = &ctx->tproxy.conns[slot];

                        /* MITM TLS: handshake in thread */
                        if (ctx->mitm.enabled && ctx->mitm.ca_key && c->is_tls && c->domain[0]) {
                            mitm_thread_arg_t *arg = malloc(sizeof(mitm_thread_arg_t));
                            if (arg) {
                                arg->mitm     = &ctx->mitm;
                                arg->conn     = c;
                                arg->epoll_fd = ctx->epoll_fd;
                                arg->slot     = slot;
                                arg->tproxy   = &ctx->tproxy;
                                pthread_t tid;
                                if (pthread_create(&tid, NULL, mitm_handshake_thread, arg) == 0) {
                                    pthread_detach(tid);
                                } else {
                                    free(arg);
                                    epoll_add(ctx->epoll_fd, c->client_fd, EPOLLIN);
                                    epoll_add(ctx->epoll_fd, c->proxy_fd,  EPOLLIN);
                                }
                            } else {
                                epoll_add(ctx->epoll_fd, c->client_fd, EPOLLIN);
                                epoll_add(ctx->epoll_fd, c->proxy_fd,  EPOLLIN);
                            }
                        } else {
                            /* Non-TLS or no MITM — register immediately */
                            if (ctx->mitm.enabled && !c->is_tls) c->inspect = true;
                            epoll_add(ctx->epoll_fd, c->client_fd, EPOLLIN);
                            epoll_add(ctx->epoll_fd, c->proxy_fd,  EPOLLIN);
                        }
                    }
                    continue;
                }

                /* ── Monitor netlink ───────────────────────────────────── */
                if (ctx->monitor.nl_fd > 0 && fd == ctx->monitor.nl_fd) {
                    pf_monitor_process(&ctx->monitor);
                    continue;
                }

                /* ── IPC: data from existing client ────────────────────── */
                {
                    int found = 0;
                    for (int j = 0; j < ctx->ipc.client_count; j++) {
                        if (ctx->ipc.clients[j].fd == fd) {
                            found = 1;
                            int rc = pf_ipc_process(&ctx->ipc, j);
                            if (rc < 0) {
                                /* client disconnected or error */
                                epoll_del(ctx->epoll_fd, fd);
                            }
                            break;
                        }
                    }

                    /* ── TPROXY: relay existing connection ─────────────── */
                    if (!found) {
                        for (int j = 0; j < PF_MAX_CONNECTIONS; j++) {
                            if (ctx->tproxy.conns[j].active &&
                                (ctx->tproxy.conns[j].client_fd == fd ||
                                 ctx->tproxy.conns[j].proxy_fd  == fd))
                            {
                                int rc = pf_tproxy_relay(&ctx->tproxy, j);
                                if (rc < 0) {
                                    epoll_del(ctx->epoll_fd, ctx->tproxy.conns[j].client_fd);
                                    epoll_del(ctx->epoll_fd, ctx->tproxy.conns[j].proxy_fd);
                                    pf_tproxy_close_conn(&ctx->tproxy, j);
                                }
                                break;
                            }
                        }
                    }
                }
            } /* for each event */
        } /* while running */
    }

shutdown:
    pf_log_info("Shutting down...");

    /* ── 9. Cleanup in reverse order ───────────────────────────────────── */
    if (ctx->epoll_fd >= 0)
        close(ctx->epoll_fd);

    pf_nft_cleanup();
    pf_cgroup_cleanup();

    if (ctx->monitor.nl_fd >= 0)
        pf_monitor_close(&ctx->monitor);

    if (ctx->tproxy.listen_fd >= 0)
        pf_tproxy_close(&ctx->tproxy);

    if (ctx->dns.fd >= 0)
        pf_dns_close(&ctx->dns);

    pf_mitm_close(&ctx->mitm);
    pf_ssh_pool_close(&ctx->ssh_pool);
    pf_ipc_close(&ctx->ipc);
    pf_logger_close(&ctx->logger);
    pf_config_close(&ctx->config);

    free(ctx->ruleset);
    ctx->ruleset = NULL;

    unlink(PF_PID_FILE);

    pf_log_info("ProxiFlare daemon stopped");
    return 0;
}
