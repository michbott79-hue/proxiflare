#ifndef PROXIFLARE_H
#define PROXIFLARE_H

#include <stdint.h>
#include <time.h>

/* ──────────────────────────────────────────────────────────────────────────
 * Version
 * ────────────────────────────────────────────────────────────────────────── */
#define PF_VERSION "0.4.1-alpha"

/* ──────────────────────────────────────────────────────────────────────────
 * Paths
 * ────────────────────────────────────────────────────────────────────────── */
#define PF_SOCKET_PATH  "/run/proxiflare/proxiflare.sock"
#define PF_DB_PATH      "/var/lib/proxiflare/proxiflare.db"
#define PF_LOG_PATH     "/var/log/proxiflare/proxiflare.log"
#define PF_CONFIG_DIR   "/etc/proxiflare"
#define PF_PID_FILE     "/run/proxiflare/proxiflare.pid"

/* ──────────────────────────────────────────────────────────────────────────
 * Limits
 * ────────────────────────────────────────────────────────────────────────── */
#define PF_MAX_PROXIES  256
#define PF_MAX_RULES    1024
#define PF_MAX_CHAINS   64
#define PF_MAX_HOPS     8
#define PF_MAX_CLIENTS  16
#define PF_BUF_SIZE     8192
#define PF_DOMAIN_MAX   253
#define PF_PATH_MAX     4096

/* ──────────────────────────────────────────────────────────────────────────
 * Error codes
 * ────────────────────────────────────────────────────────────────────────── */
#define PF_OK           0
#define PF_ERR         (-1)
#define PF_ERR_NOMEM   (-2)
#define PF_ERR_DB      (-3)
#define PF_ERR_CRYPTO  (-4)
#define PF_ERR_NET     (-5)
#define PF_ERR_AUTH    (-6)
#define PF_ERR_LOCKED  (-7)

/* ──────────────────────────────────────────────────────────────────────────
 * Enums
 * ────────────────────────────────────────────────────────────────────────── */
typedef enum {
    PF_PROXY_SOCKS4 = 0,
    PF_PROXY_SOCKS5,
    PF_PROXY_HTTP,
    PF_PROXY_SSH
} pf_proxy_type_t;

typedef enum {
    PF_HEALTH_UNKNOWN = 0,
    PF_HEALTH_ONLINE,
    PF_HEALTH_OFFLINE,
    PF_HEALTH_SLOW,
    PF_HEALTH_ERROR
} pf_health_t;

typedef enum {
    PF_ACTION_DIRECT = 0,
    PF_ACTION_PROXY,
    PF_ACTION_CHAIN,
    PF_ACTION_BLOCK,
    PF_ACTION_REJECT
} pf_action_t;

/* ──────────────────────────────────────────────────────────────────────────
 * Structs
 * ────────────────────────────────────────────────────────────────────────── */

typedef struct pf_proxy {
    uint32_t        id;
    char            name[64];
    pf_proxy_type_t type;
    char            host[PF_DOMAIN_MAX + 1];
    uint16_t        port;
    char            username[128];
    char            password[128];   /* stored encrypted in DB */
    char            ssh_key_path[PF_PATH_MAX];
    pf_health_t     health;
    uint32_t        latency_ms;
    time_t          last_check;
    uint64_t        bytes_sent;
    uint64_t        bytes_recv;
    int             enabled;
} pf_proxy_t;

typedef struct pf_rule {
    uint32_t     id;
    char         name[64];
    int          priority;           /* lower = higher priority */
    /* match criteria */
    char         app_path[PF_PATH_MAX];
    uint32_t     uid;
    uint32_t     gid;
    char         domain[PF_DOMAIN_MAX + 1];
    char         ip_cidr[48];        /* IPv4 or IPv6 CIDR */
    uint16_t     dst_port;
    uint8_t      proto;              /* IPPROTO_TCP / IPPROTO_UDP / 0=any */
    /* action */
    pf_action_t  action;
    uint32_t     proxy_id;           /* used when action == PF_ACTION_PROXY */
    uint32_t     chain_id;           /* used when action == PF_ACTION_CHAIN */
    int          enabled;
} pf_rule_t;

typedef struct pf_chain {
    uint32_t  id;
    char      name[64];
    uint32_t  hops[PF_MAX_HOPS];    /* proxy IDs in order */
    int       hop_count;
    int       enabled;
} pf_chain_t;

typedef struct pf_log_entry {
    time_t      ts;
    uint32_t    rule_id;
    uint32_t    proxy_id;
    uint32_t    uid;
    char        app_path[PF_PATH_MAX];
    char        domain[PF_DOMAIN_MAX + 1];
    char        dst_ip[48];
    uint16_t    dst_port;
    pf_action_t action;
    int         success;
    uint32_t    latency_ms;
    uint64_t    bytes_sent;
    uint64_t    bytes_recv;
} pf_log_entry_t;

/* ──────────────────────────────────────────────────────────────────────────
 * Forward declaration
 * ────────────────────────────────────────────────────────────────────────── */
typedef struct pf_ctx pf_ctx_t;

/* ──────────────────────────────────────────────────────────────────────────
 * String conversion helpers — implemented in main.c
 * ────────────────────────────────────────────────────────────────────────── */
const char     *pf_proxy_type_str(pf_proxy_type_t t);
const char     *pf_health_str(pf_health_t h);
const char     *pf_action_str(pf_action_t a);
pf_proxy_type_t pf_proxy_type_from_str(const char *s);
pf_action_t     pf_action_from_str(const char *s);

#endif /* PROXIFLARE_H */
