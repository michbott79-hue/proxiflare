# ProxiFlare Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a professional per-app and per-domain proxy router for Linux with a C daemon and Tauri/React GUI.

**Architecture:** C daemon runs as root, manages nftables/cgroups/DNS/TPROXY. Tauri GUI runs as user, communicates via Unix socket with JSON-NL protocol. SQLite stores config, AES-256-GCM encrypts credentials.

**Tech Stack:** C (daemon), Rust (Tauri shell), React + TypeScript + Tailwind (GUI), SQLite, OpenSSL, libnetfilter_queue, libssh2, libargon2, nftables, cgroups v2.

**Spec:** `docs/superpowers/specs/2026-04-11-proxiflare-design.md`

---

## Phase 1: Foundation

### Task 1: Install Dependencies and Build System

**Files:**
- Create: `daemon/CMakeLists.txt`
- Create: `daemon/include/proxiflare.h`
- Create: `daemon/vendor/cJSON/cJSON.c`
- Create: `daemon/vendor/cJSON/cJSON.h`

- [ ] **Step 1: Install missing system dependencies**

```bash
sudo apt-get install -y cmake libnetfilter-queue-dev libnfnetlink-dev \
  libssh2-1-dev libargon2-dev libappindicator3-dev pkg-config
```

Verify all found:
```bash
pkg-config --modversion sqlite3 libssl libnetfilter_queue libnfnetlink libssh2
```

- [ ] **Step 2: Install Rust toolchain (needed for Tauri later)**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
rustc --version  # expect >= 1.70
```

- [ ] **Step 3: Vendor cJSON**

```bash
cd ~/projects/proxiflare
mkdir -p daemon/vendor/cJSON
curl -sL https://raw.githubusercontent.com/DaveGamble/cJSON/v1.7.18/cJSON.c -o daemon/vendor/cJSON/cJSON.c
curl -sL https://raw.githubusercontent.com/DaveGamble/cJSON/v1.7.18/cJSON.h -o daemon/vendor/cJSON/cJSON.h
```

- [ ] **Step 4: Create shared header `daemon/include/proxiflare.h`**

```c
#ifndef PROXIFLARE_H
#define PROXIFLARE_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define PF_VERSION "1.0.0"
#define PF_SOCKET_PATH "/run/proxiflare.sock"
#define PF_DB_PATH "/var/lib/proxiflare/proxiflare.db"
#define PF_LOG_PATH "/var/log/proxiflare/proxiflare.log"
#define PF_CONFIG_DIR "/etc/proxiflare"
#define PF_PID_FILE "/run/proxiflare.pid"

#define PF_MAX_PROXIES 256
#define PF_MAX_RULES 1024
#define PF_MAX_CHAINS 64
#define PF_MAX_HOPS 8
#define PF_MAX_CLIENTS 16
#define PF_BUF_SIZE 8192
#define PF_DOMAIN_MAX 253
#define PF_PATH_MAX 4096

/* Proxy types */
typedef enum {
    PF_PROXY_SOCKS4,
    PF_PROXY_SOCKS5,
    PF_PROXY_HTTP,
    PF_PROXY_SSH
} pf_proxy_type_t;

/* Proxy health status */
typedef enum {
    PF_HEALTH_UNKNOWN,
    PF_HEALTH_ONLINE,
    PF_HEALTH_OFFLINE,
    PF_HEALTH_SLOW,
    PF_HEALTH_ERROR
} pf_health_t;

/* Rule actions */
typedef enum {
    PF_ACTION_DIRECT,
    PF_ACTION_PROXY,
    PF_ACTION_CHAIN,
    PF_ACTION_BLOCK,
    PF_ACTION_REJECT
} pf_action_t;

/* Proxy definition */
typedef struct {
    int id;
    char name[64];
    pf_proxy_type_t type;
    char host[256];
    int port;
    char username[128];   /* decrypted, in-memory only */
    char password[256];   /* decrypted, in-memory only */
    char ssh_key[PF_PATH_MAX]; /* decrypted key path or key data */
    bool enabled;
    pf_health_t health;
    int latency_ms;
    int check_interval;   /* seconds */
    time_t created_at;
    time_t updated_at;
} pf_proxy_t;

/* Chain definition */
typedef struct {
    int id;
    char name[64];
    bool enabled;
    int hop_count;
    int hop_proxy_ids[PF_MAX_HOPS];
    time_t created_at;
} pf_chain_t;

/* Rule definition */
typedef struct {
    int id;
    char name[128];
    bool enabled;
    int priority;
    char match_app[PF_PATH_MAX];    /* nullable */
    char match_domain[PF_DOMAIN_MAX]; /* nullable */
    char match_ip[64];               /* nullable */
    char match_port[32];             /* nullable */
    pf_action_t action;
    int proxy_id;                    /* -1 if not used */
    int chain_id;                    /* -1 if not used */
    time_t created_at;
    time_t updated_at;
} pf_rule_t;

/* Log entry */
typedef struct {
    time_t ts;
    char app[256];
    pid_t pid;
    char domain[PF_DOMAIN_MAX];
    char dst_ip[46];
    int dst_port;
    char proxy_name[64];
    pf_action_t action;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    int latency_ms;
} pf_log_entry_t;

/* Global daemon context */
typedef struct pf_ctx pf_ctx_t;

/* Error codes */
#define PF_OK           0
#define PF_ERR         -1
#define PF_ERR_NOMEM   -2
#define PF_ERR_DB      -3
#define PF_ERR_CRYPTO  -4
#define PF_ERR_NET     -5
#define PF_ERR_AUTH    -6
#define PF_ERR_LOCKED  -7

/* String conversion helpers */
const char *pf_proxy_type_str(pf_proxy_type_t t);
const char *pf_health_str(pf_health_t h);
const char *pf_action_str(pf_action_t a);
pf_proxy_type_t pf_proxy_type_from_str(const char *s);
pf_action_t pf_action_from_str(const char *s);

#endif /* PROXIFLARE_H */
```

- [ ] **Step 5: Create CMakeLists.txt**

```cmake
cmake_minimum_required(VERSION 3.16)
project(proxiflare-daemon C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(NFQ REQUIRED libnetfilter_queue)
pkg_check_modules(NFNL REQUIRED libnfnetlink)
pkg_check_modules(SSH2 REQUIRED libssh2)

# Find libargon2 (no pkg-config)
find_library(ARGON2_LIB argon2 REQUIRED)
find_path(ARGON2_INCLUDE argon2.h PATH_SUFFIXES include)

# Sources
set(DAEMON_SOURCES
    src/main.c
    src/config.c
    src/crypto.c
    src/ipc.c
    src/dns.c
    src/sni.c
    src/rules.c
    src/proxy_socks.c
    src/proxy_http.c
    src/proxy_ssh.c
    src/chain.c
    src/tproxy.c
    src/cgroup.c
    src/nft.c
    src/monitor.c
    src/logger.c
    src/stats.c
    vendor/cJSON/cJSON.c
)

add_executable(proxiflare-daemon ${DAEMON_SOURCES})

target_include_directories(proxiflare-daemon PRIVATE
    include
    vendor/cJSON
    ${SQLITE3_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${NFQ_INCLUDE_DIRS}
    ${NFNL_INCLUDE_DIRS}
    ${SSH2_INCLUDE_DIRS}
    ${ARGON2_INCLUDE}
)

target_link_libraries(proxiflare-daemon
    ${SQLITE3_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${NFQ_LIBRARIES}
    ${NFNL_LIBRARIES}
    ${SSH2_LIBRARIES}
    ${ARGON2_LIB}
    pthread
)

# Test binary (for development)
add_executable(pf-test-config tests/test_config.c src/config.c src/crypto.c vendor/cJSON/cJSON.c)
target_include_directories(pf-test-config PRIVATE include vendor/cJSON ${SQLITE3_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIRS} ${ARGON2_INCLUDE})
target_link_libraries(pf-test-config ${SQLITE3_LIBRARIES} ${OPENSSL_LIBRARIES} ${ARGON2_LIB})
```

- [ ] **Step 6: Verify build system compiles (with stub main.c)**

Create `daemon/src/main.c`:
```c
#include "proxiflare.h"
#include <stdio.h>

const char *pf_proxy_type_str(pf_proxy_type_t t) {
    switch (t) {
        case PF_PROXY_SOCKS4: return "socks4";
        case PF_PROXY_SOCKS5: return "socks5";
        case PF_PROXY_HTTP:   return "http";
        case PF_PROXY_SSH:    return "ssh";
    }
    return "unknown";
}

const char *pf_health_str(pf_health_t h) {
    switch (h) {
        case PF_HEALTH_UNKNOWN: return "unknown";
        case PF_HEALTH_ONLINE:  return "online";
        case PF_HEALTH_OFFLINE: return "offline";
        case PF_HEALTH_SLOW:    return "slow";
        case PF_HEALTH_ERROR:   return "error";
    }
    return "unknown";
}

const char *pf_action_str(pf_action_t a) {
    switch (a) {
        case PF_ACTION_DIRECT: return "DIRECT";
        case PF_ACTION_PROXY:  return "PROXY";
        case PF_ACTION_CHAIN:  return "CHAIN";
        case PF_ACTION_BLOCK:  return "BLOCK";
        case PF_ACTION_REJECT: return "REJECT";
    }
    return "UNKNOWN";
}

pf_proxy_type_t pf_proxy_type_from_str(const char *s) {
    if (!s) return PF_PROXY_SOCKS5;
    if (strcmp(s, "socks4") == 0) return PF_PROXY_SOCKS4;
    if (strcmp(s, "socks5") == 0) return PF_PROXY_SOCKS5;
    if (strcmp(s, "http") == 0)   return PF_PROXY_HTTP;
    if (strcmp(s, "ssh") == 0)    return PF_PROXY_SSH;
    return PF_PROXY_SOCKS5;
}

pf_action_t pf_action_from_str(const char *s) {
    if (!s) return PF_ACTION_DIRECT;
    if (strcmp(s, "DIRECT") == 0) return PF_ACTION_DIRECT;
    if (strcmp(s, "PROXY") == 0)  return PF_ACTION_PROXY;
    if (strcmp(s, "CHAIN") == 0)  return PF_ACTION_CHAIN;
    if (strcmp(s, "BLOCK") == 0)  return PF_ACTION_BLOCK;
    if (strcmp(s, "REJECT") == 0) return PF_ACTION_REJECT;
    return PF_ACTION_DIRECT;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    printf("ProxiFlare daemon v%s\n", PF_VERSION);
    return 0;
}
```

Create stub files so cmake doesn't fail (each stub is just `#include "proxiflare.h"`):
```bash
for f in config crypto ipc dns sni rules proxy_socks proxy_http proxy_ssh chain tproxy cgroup nft monitor logger stats; do
    echo '#include "proxiflare.h"' > daemon/src/${f}.c
done
mkdir -p daemon/tests
echo '#include <stdio.h>
int main(void) { printf("tests placeholder\n"); return 0; }' > daemon/tests/test_config.c
```

Build:
```bash
cd ~/projects/proxiflare/daemon
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
./proxiflare-daemon  # expect: "ProxiFlare daemon v1.0.0"
```

- [ ] **Step 7: Commit**

```bash
cd ~/projects/proxiflare
git add daemon/
git commit -m "feat: daemon build system, shared types, vendored cJSON"
```

---

### Task 2: SQLite Config Module

**Files:**
- Create: `daemon/src/config.c`
- Create: `daemon/src/config.h`

- [ ] **Step 1: Create `daemon/src/config.h`**

```c
#ifndef PF_CONFIG_H
#define PF_CONFIG_H

#include "proxiflare.h"
#include <sqlite3.h>

/* Database context */
typedef struct {
    sqlite3 *db;
    char db_path[PF_PATH_MAX];
} pf_config_t;

/* Init/close */
int pf_config_init(pf_config_t *cfg, const char *db_path);
void pf_config_close(pf_config_t *cfg);

/* Proxies CRUD */
int pf_config_proxy_list(pf_config_t *cfg, pf_proxy_t *out, int max, int *count);
int pf_config_proxy_get(pf_config_t *cfg, int id, pf_proxy_t *out);
int pf_config_proxy_add(pf_config_t *cfg, const pf_proxy_t *proxy);
int pf_config_proxy_update(pf_config_t *cfg, const pf_proxy_t *proxy);
int pf_config_proxy_delete(pf_config_t *cfg, int id);
int pf_config_proxy_update_health(pf_config_t *cfg, int id, pf_health_t health, int latency_ms);

/* Rules CRUD */
int pf_config_rule_list(pf_config_t *cfg, pf_rule_t *out, int max, int *count);
int pf_config_rule_get(pf_config_t *cfg, int id, pf_rule_t *out);
int pf_config_rule_add(pf_config_t *cfg, const pf_rule_t *rule);
int pf_config_rule_update(pf_config_t *cfg, const pf_rule_t *rule);
int pf_config_rule_delete(pf_config_t *cfg, int id);

/* Chains CRUD */
int pf_config_chain_list(pf_config_t *cfg, pf_chain_t *out, int max, int *count);
int pf_config_chain_get(pf_config_t *cfg, int id, pf_chain_t *out);
int pf_config_chain_add(pf_config_t *cfg, const pf_chain_t *chain);
int pf_config_chain_update(pf_config_t *cfg, const pf_chain_t *chain);
int pf_config_chain_delete(pf_config_t *cfg, int id);

/* Key-value config */
int pf_config_get(pf_config_t *cfg, const char *key, char *value, int max_len);
int pf_config_set(pf_config_t *cfg, const char *key, const char *value);

#endif /* PF_CONFIG_H */
```

- [ ] **Step 2: Implement `daemon/src/config.c`**

Full implementation of SQLite schema init + all CRUD operations. Key points:
- `pf_config_init()` opens DB, runs `CREATE TABLE IF NOT EXISTS` for all 5 tables from the spec schema
- Proxy add/update stores username/password as BLOBs (already encrypted by crypto module before reaching here)
- Rule list returns ordered by priority ASC
- Chain get loads hop_proxy_ids from chain_hops join
- All functions return PF_OK or PF_ERR_DB

```c
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS proxies ("
    "  id INTEGER PRIMARY KEY,"
    "  name TEXT NOT NULL UNIQUE,"
    "  type TEXT NOT NULL CHECK(type IN ('socks4','socks5','http','ssh')),"
    "  host TEXT NOT NULL,"
    "  port INTEGER NOT NULL,"
    "  username BLOB,"
    "  password BLOB,"
    "  ssh_key BLOB,"
    "  enabled BOOLEAN DEFAULT 1,"
    "  health TEXT DEFAULT 'unknown',"
    "  latency_ms INTEGER,"
    "  check_interval INTEGER DEFAULT 60,"
    "  created_at INTEGER NOT NULL,"
    "  updated_at INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS chains ("
    "  id INTEGER PRIMARY KEY,"
    "  name TEXT NOT NULL UNIQUE,"
    "  enabled BOOLEAN DEFAULT 1,"
    "  created_at INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS chain_hops ("
    "  id INTEGER PRIMARY KEY,"
    "  chain_id INTEGER NOT NULL REFERENCES chains(id) ON DELETE CASCADE,"
    "  proxy_id INTEGER NOT NULL REFERENCES proxies(id),"
    "  hop_order INTEGER NOT NULL,"
    "  UNIQUE(chain_id, hop_order)"
    ");"
    "CREATE TABLE IF NOT EXISTS rules ("
    "  id INTEGER PRIMARY KEY,"
    "  name TEXT NOT NULL,"
    "  enabled BOOLEAN DEFAULT 1,"
    "  priority INTEGER NOT NULL DEFAULT 100,"
    "  match_app TEXT,"
    "  match_domain TEXT,"
    "  match_ip TEXT,"
    "  match_port TEXT,"
    "  action TEXT NOT NULL CHECK(action IN ('DIRECT','PROXY','CHAIN','BLOCK','REJECT')),"
    "  proxy_id INTEGER REFERENCES proxies(id),"
    "  chain_id INTEGER REFERENCES chains(id),"
    "  created_at INTEGER NOT NULL,"
    "  updated_at INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS config ("
    "  key TEXT PRIMARY KEY,"
    "  value TEXT NOT NULL"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_rules_priority ON rules(priority);"
    "CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled) WHERE enabled = 1;"
    "CREATE INDEX IF NOT EXISTS idx_chain_hops_chain ON chain_hops(chain_id, hop_order);";

int pf_config_init(pf_config_t *cfg, const char *db_path) {
    strncpy(cfg->db_path, db_path, PF_PATH_MAX - 1);
    int rc = sqlite3_open(db_path, &cfg->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[config] sqlite3_open failed: %s\n", sqlite3_errmsg(cfg->db));
        return PF_ERR_DB;
    }
    sqlite3_exec(cfg->db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(cfg->db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL);

    char *err = NULL;
    rc = sqlite3_exec(cfg->db, SCHEMA_SQL, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[config] schema init failed: %s\n", err);
        sqlite3_free(err);
        return PF_ERR_DB;
    }
    return PF_OK;
}

void pf_config_close(pf_config_t *cfg) {
    if (cfg->db) {
        sqlite3_close(cfg->db);
        cfg->db = NULL;
    }
}

/* --- Proxies --- */

int pf_config_proxy_list(pf_config_t *cfg, pf_proxy_t *out, int max, int *count) {
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(cfg->db,
        "SELECT id, name, type, host, port, username, password, ssh_key, "
        "enabled, health, latency_ms, check_interval, created_at, updated_at "
        "FROM proxies ORDER BY name", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return PF_ERR_DB;

    *count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && *count < max) {
        pf_proxy_t *p = &out[*count];
        memset(p, 0, sizeof(*p));
        p->id = sqlite3_column_int(stmt, 0);
        strncpy(p->name, (const char *)sqlite3_column_text(stmt, 1), sizeof(p->name) - 1);
        p->type = pf_proxy_type_from_str((const char *)sqlite3_column_text(stmt, 2));
        strncpy(p->host, (const char *)sqlite3_column_text(stmt, 3), sizeof(p->host) - 1);
        p->port = sqlite3_column_int(stmt, 4);
        /* username/password are encrypted BLOBs — stored but not decoded here */
        p->enabled = sqlite3_column_int(stmt, 8);
        const char *h = (const char *)sqlite3_column_text(stmt, 9);
        if (h) {
            if (strcmp(h, "online") == 0) p->health = PF_HEALTH_ONLINE;
            else if (strcmp(h, "offline") == 0) p->health = PF_HEALTH_OFFLINE;
            else if (strcmp(h, "slow") == 0) p->health = PF_HEALTH_SLOW;
            else if (strcmp(h, "error") == 0) p->health = PF_HEALTH_ERROR;
            else p->health = PF_HEALTH_UNKNOWN;
        }
        p->latency_ms = sqlite3_column_int(stmt, 10);
        p->check_interval = sqlite3_column_int(stmt, 11);
        p->created_at = sqlite3_column_int64(stmt, 12);
        p->updated_at = sqlite3_column_int64(stmt, 13);
        (*count)++;
    }
    sqlite3_finalize(stmt);
    return PF_OK;
}

int pf_config_proxy_get(pf_config_t *cfg, int id, pf_proxy_t *out) {
    pf_proxy_t list[1];
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(cfg->db,
        "SELECT id, name, type, host, port, username, password, ssh_key, "
        "enabled, health, latency_ms, check_interval, created_at, updated_at "
        "FROM proxies WHERE id = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return PF_ERR_DB;
    sqlite3_bind_int(stmt, 1, id);
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return PF_ERR;
    }
    memset(out, 0, sizeof(*out));
    out->id = sqlite3_column_int(stmt, 0);
    strncpy(out->name, (const char *)sqlite3_column_text(stmt, 1), sizeof(out->name) - 1);
    out->type = pf_proxy_type_from_str((const char *)sqlite3_column_text(stmt, 2));
    strncpy(out->host, (const char *)sqlite3_column_text(stmt, 3), sizeof(out->host) - 1);
    out->port = sqlite3_column_int(stmt, 4);
    out->enabled = sqlite3_column_int(stmt, 8);
    out->latency_ms = sqlite3_column_int(stmt, 10);
    out->check_interval = sqlite3_column_int(stmt, 11);
    out->created_at = sqlite3_column_int64(stmt, 12);
    out->updated_at = sqlite3_column_int64(stmt, 13);
    sqlite3_finalize(stmt);
    return PF_OK;
}

int pf_config_proxy_add(pf_config_t *cfg, const pf_proxy_t *proxy) {
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(cfg->db,
        "INSERT INTO proxies (name, type, host, port, username, password, ssh_key, "
        "enabled, check_interval, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return PF_ERR_DB;
    sqlite3_bind_text(stmt, 1, proxy->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, pf_proxy_type_str(proxy->type), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, proxy->host, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, proxy->port);
    /* username/password as blobs (pre-encrypted) */
    if (proxy->username[0])
        sqlite3_bind_blob(stmt, 5, proxy->username, strlen(proxy->username), SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 5);
    if (proxy->password[0])
        sqlite3_bind_blob(stmt, 6, proxy->password, strlen(proxy->password), SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 6);
    sqlite3_bind_null(stmt, 7); /* ssh_key */
    sqlite3_bind_int(stmt, 8, proxy->enabled);
    sqlite3_bind_int(stmt, 9, proxy->check_interval > 0 ? proxy->check_interval : 60);
    sqlite3_bind_int64(stmt, 10, time(NULL));
    sqlite3_bind_int64(stmt, 11, time(NULL));
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? PF_OK : PF_ERR_DB;
}

int pf_config_proxy_update(pf_config_t *cfg, const pf_proxy_t *proxy) {
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(cfg->db,
        "UPDATE proxies SET name=?, type=?, host=?, port=?, username=?, password=?, "
        "enabled=?, check_interval=?, updated_at=? WHERE id=?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return PF_ERR_DB;
    sqlite3_bind_text(stmt, 1, proxy->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, pf_proxy_type_str(proxy->type), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, proxy->host, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, proxy->port);
    if (proxy->username[0])
        sqlite3_bind_blob(stmt, 5, proxy->username, strlen(proxy->username), SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 5);
    if (proxy->password[0])
        sqlite3_bind_blob(stmt, 6, proxy->password, strlen(proxy->password), SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 6);
    sqlite3_bind_int(stmt, 7, proxy->enabled);
    sqlite3_bind_int(stmt, 8, proxy->check_interval);
    sqlite3_bind_int64(stmt, 9, time(NULL));
    sqlite3_bind_int(stmt, 10, proxy->id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? PF_OK : PF_ERR_DB;
}

int pf_config_proxy_delete(pf_config_t *cfg, int id) {
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(cfg->db, "DELETE FROM proxies WHERE id=?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return PF_ERR_DB;
    sqlite3_bind_int(stmt, 1, id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? PF_OK : PF_ERR_DB;
}

int pf_config_proxy_update_health(pf_config_t *cfg, int id, pf_health_t health, int latency_ms) {
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(cfg->db,
        "UPDATE proxies SET health=?, latency_ms=?, updated_at=? WHERE id=?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return PF_ERR_DB;
    sqlite3_bind_text(stmt, 1, pf_health_str(health), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, latency_ms);
    sqlite3_bind_int64(stmt, 3, time(NULL));
    sqlite3_bind_int(stmt, 4, id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? PF_OK : PF_ERR_DB;
}

/* --- Rules --- */

int pf_config_rule_list(pf_config_t *cfg, pf_rule_t *out, int max, int *count) {
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(cfg->db,
        "SELECT id, name, enabled, priority, match_app, match_domain, match_ip, "
        "match_port, action, proxy_id, chain_id, created_at, updated_at "
        "FROM rules ORDER BY priority ASC", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return PF_ERR_DB;

    *count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && *count < max) {
        pf_rule_t *r = &out[*count];
        memset(r, 0, sizeof(*r));
        r->id = sqlite3_column_int(stmt, 0);
        strncpy(r->name, (const char *)sqlite3_column_text(stmt, 1), sizeof(r->name) - 1);
        r->enabled = sqlite3_column_int(stmt, 2);
        r->priority = sqlite3_column_int(stmt, 3);
        const char *v;
        if ((v = (const char *)sqlite3_column_text(stmt, 4))) strncpy(r->match_app, v, sizeof(r->match_app) - 1);
        if ((v = (const char *)sqlite3_column_text(stmt, 5))) strncpy(r->match_domain, v, sizeof(r->match_domain) - 1);
        if ((v = (const char *)sqlite3_column_text(stmt, 6))) strncpy(r->match_ip, v, sizeof(r->match_ip) - 1);
        if ((v = (const char *)sqlite3_column_text(stmt, 7))) strncpy(r->match_port, v, sizeof(r->match_port) - 1);
        r->action = pf_action_from_str((const char *)sqlite3_column_text(stmt, 8));
        r->proxy_id = sqlite3_column_type(stmt, 9) == SQLITE_NULL ? -1 : sqlite3_column_int(stmt, 9);
        r->chain_id = sqlite3_column_type(stmt, 10) == SQLITE_NULL ? -1 : sqlite3_column_int(stmt, 10);
        r->created_at = sqlite3_column_int64(stmt, 11);
        r->updated_at = sqlite3_column_int64(stmt, 12);
        (*count)++;
    }
    sqlite3_finalize(stmt);
    return PF_OK;
}

int pf_config_rule_add(pf_config_t *cfg, const pf_rule_t *rule) {
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(cfg->db,
        "INSERT INTO rules (name, enabled, priority, match_app, match_domain, match_ip, "
        "match_port, action, proxy_id, chain_id, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return PF_ERR_DB;
    sqlite3_bind_text(stmt, 1, rule->name, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, rule->enabled);
    sqlite3_bind_int(stmt, 3, rule->priority);
    rule->match_app[0] ? sqlite3_bind_text(stmt, 4, rule->match_app, -1, SQLITE_STATIC) : sqlite3_bind_null(stmt, 4);
    rule->match_domain[0] ? sqlite3_bind_text(stmt, 5, rule->match_domain, -1, SQLITE_STATIC) : sqlite3_bind_null(stmt, 5);
    rule->match_ip[0] ? sqlite3_bind_text(stmt, 6, rule->match_ip, -1, SQLITE_STATIC) : sqlite3_bind_null(stmt, 6);
    rule->match_port[0] ? sqlite3_bind_text(stmt, 7, rule->match_port, -1, SQLITE_STATIC) : sqlite3_bind_null(stmt, 7);
    sqlite3_bind_text(stmt, 8, pf_action_str(rule->action), -1, SQLITE_STATIC);
    rule->proxy_id >= 0 ? sqlite3_bind_int(stmt, 9, rule->proxy_id) : sqlite3_bind_null(stmt, 9);
    rule->chain_id >= 0 ? sqlite3_bind_int(stmt, 10, rule->chain_id) : sqlite3_bind_null(stmt, 10);
    sqlite3_bind_int64(stmt, 11, time(NULL));
    sqlite3_bind_int64(stmt, 12, time(NULL));
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? PF_OK : PF_ERR_DB;
}

int pf_config_rule_update(pf_config_t *cfg, const pf_rule_t *rule) {
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(cfg->db,
        "UPDATE rules SET name=?, enabled=?, priority=?, match_app=?, match_domain=?, "
        "match_ip=?, match_port=?, action=?, proxy_id=?, chain_id=?, updated_at=? WHERE id=?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return PF_ERR_DB;
    sqlite3_bind_text(stmt, 1, rule->name, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, rule->enabled);
    sqlite3_bind_int(stmt, 3, rule->priority);
    rule->match_app[0] ? sqlite3_bind_text(stmt, 4, rule->match_app, -1, SQLITE_STATIC) : sqlite3_bind_null(stmt, 4);
    rule->match_domain[0] ? sqlite3_bind_text(stmt, 5, rule->match_domain, -1, SQLITE_STATIC) : sqlite3_bind_null(stmt, 5);
    rule->match_ip[0] ? sqlite3_bind_text(stmt, 6, rule->match_ip, -1, SQLITE_STATIC) : sqlite3_bind_null(stmt, 6);
    rule->match_port[0] ? sqlite3_bind_text(stmt, 7, rule->match_port, -1, SQLITE_STATIC) : sqlite3_bind_null(stmt, 7);
    sqlite3_bind_text(stmt, 8, pf_action_str(rule->action), -1, SQLITE_STATIC);
    rule->proxy_id >= 0 ? sqlite3_bind_int(stmt, 9, rule->proxy_id) : sqlite3_bind_null(stmt, 9);
    rule->chain_id >= 0 ? sqlite3_bind_int(stmt, 10, rule->chain_id) : sqlite3_bind_null(stmt, 10);
    sqlite3_bind_int64(stmt, 11, time(NULL));
    sqlite3_bind_int(stmt, 12, rule->id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? PF_OK : PF_ERR_DB;
}

int pf_config_rule_delete(pf_config_t *cfg, int id) {
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(cfg->db, "DELETE FROM rules WHERE id=?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return PF_ERR_DB;
    sqlite3_bind_int(stmt, 1, id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? PF_OK : PF_ERR_DB;
}

int pf_config_rule_get(pf_config_t *cfg, int id, pf_rule_t *out) {
    /* Same pattern as proxy_get — single row SELECT by id */
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(cfg->db,
        "SELECT id, name, enabled, priority, match_app, match_domain, match_ip, "
        "match_port, action, proxy_id, chain_id, created_at, updated_at "
        "FROM rules WHERE id = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return PF_ERR_DB;
    sqlite3_bind_int(stmt, 1, id);
    if (sqlite3_step(stmt) != SQLITE_ROW) { sqlite3_finalize(stmt); return PF_ERR; }
    memset(out, 0, sizeof(*out));
    out->id = sqlite3_column_int(stmt, 0);
    strncpy(out->name, (const char *)sqlite3_column_text(stmt, 1), sizeof(out->name) - 1);
    out->enabled = sqlite3_column_int(stmt, 2);
    out->priority = sqlite3_column_int(stmt, 3);
    const char *v;
    if ((v = (const char *)sqlite3_column_text(stmt, 4))) strncpy(out->match_app, v, sizeof(out->match_app) - 1);
    if ((v = (const char *)sqlite3_column_text(stmt, 5))) strncpy(out->match_domain, v, sizeof(out->match_domain) - 1);
    if ((v = (const char *)sqlite3_column_text(stmt, 6))) strncpy(out->match_ip, v, sizeof(out->match_ip) - 1);
    if ((v = (const char *)sqlite3_column_text(stmt, 7))) strncpy(out->match_port, v, sizeof(out->match_port) - 1);
    out->action = pf_action_from_str((const char *)sqlite3_column_text(stmt, 8));
    out->proxy_id = sqlite3_column_type(stmt, 9) == SQLITE_NULL ? -1 : sqlite3_column_int(stmt, 9);
    out->chain_id = sqlite3_column_type(stmt, 10) == SQLITE_NULL ? -1 : sqlite3_column_int(stmt, 10);
    out->created_at = sqlite3_column_int64(stmt, 11);
    out->updated_at = sqlite3_column_int64(stmt, 12);
    sqlite3_finalize(stmt);
    return PF_OK;
}

/* --- Chains --- */

int pf_config_chain_list(pf_config_t *cfg, pf_chain_t *out, int max, int *count) {
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(cfg->db,
        "SELECT id, name, enabled, created_at FROM chains ORDER BY name", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return PF_ERR_DB;
    *count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && *count < max) {
        pf_chain_t *c = &out[*count];
        memset(c, 0, sizeof(*c));
        c->id = sqlite3_column_int(stmt, 0);
        strncpy(c->name, (const char *)sqlite3_column_text(stmt, 1), sizeof(c->name) - 1);
        c->enabled = sqlite3_column_int(stmt, 2);
        c->created_at = sqlite3_column_int64(stmt, 3);
        /* Load hops */
        sqlite3_stmt *hs;
        sqlite3_prepare_v2(cfg->db,
            "SELECT proxy_id FROM chain_hops WHERE chain_id=? ORDER BY hop_order", -1, &hs, NULL);
        sqlite3_bind_int(hs, 1, c->id);
        c->hop_count = 0;
        while (sqlite3_step(hs) == SQLITE_ROW && c->hop_count < PF_MAX_HOPS) {
            c->hop_proxy_ids[c->hop_count++] = sqlite3_column_int(hs, 0);
        }
        sqlite3_finalize(hs);
        (*count)++;
    }
    sqlite3_finalize(stmt);
    return PF_OK;
}

int pf_config_chain_get(pf_config_t *cfg, int id, pf_chain_t *out) {
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(cfg->db,
        "SELECT id, name, enabled, created_at FROM chains WHERE id=?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return PF_ERR_DB;
    sqlite3_bind_int(stmt, 1, id);
    if (sqlite3_step(stmt) != SQLITE_ROW) { sqlite3_finalize(stmt); return PF_ERR; }
    memset(out, 0, sizeof(*out));
    out->id = sqlite3_column_int(stmt, 0);
    strncpy(out->name, (const char *)sqlite3_column_text(stmt, 1), sizeof(out->name) - 1);
    out->enabled = sqlite3_column_int(stmt, 2);
    out->created_at = sqlite3_column_int64(stmt, 3);
    sqlite3_finalize(stmt);
    /* Load hops */
    sqlite3_prepare_v2(cfg->db,
        "SELECT proxy_id FROM chain_hops WHERE chain_id=? ORDER BY hop_order", -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, id);
    out->hop_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && out->hop_count < PF_MAX_HOPS)
        out->hop_proxy_ids[out->hop_count++] = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return PF_OK;
}

int pf_config_chain_add(pf_config_t *cfg, const pf_chain_t *chain) {
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(cfg->db,
        "INSERT INTO chains (name, enabled, created_at) VALUES (?, ?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return PF_ERR_DB;
    sqlite3_bind_text(stmt, 1, chain->name, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, chain->enabled);
    sqlite3_bind_int64(stmt, 3, time(NULL));
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return PF_ERR_DB;

    int chain_id = (int)sqlite3_last_insert_rowid(cfg->db);
    for (int i = 0; i < chain->hop_count; i++) {
        sqlite3_prepare_v2(cfg->db,
            "INSERT INTO chain_hops (chain_id, proxy_id, hop_order) VALUES (?, ?, ?)",
            -1, &stmt, NULL);
        sqlite3_bind_int(stmt, 1, chain_id);
        sqlite3_bind_int(stmt, 2, chain->hop_proxy_ids[i]);
        sqlite3_bind_int(stmt, 3, i);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    return PF_OK;
}

int pf_config_chain_update(pf_config_t *cfg, const pf_chain_t *chain) {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(cfg->db, "UPDATE chains SET name=?, enabled=? WHERE id=?", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, chain->name, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, chain->enabled);
    sqlite3_bind_int(stmt, 3, chain->id);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    /* Rebuild hops */
    sqlite3_prepare_v2(cfg->db, "DELETE FROM chain_hops WHERE chain_id=?", -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, chain->id);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    for (int i = 0; i < chain->hop_count; i++) {
        sqlite3_prepare_v2(cfg->db,
            "INSERT INTO chain_hops (chain_id, proxy_id, hop_order) VALUES (?, ?, ?)",
            -1, &stmt, NULL);
        sqlite3_bind_int(stmt, 1, chain->id);
        sqlite3_bind_int(stmt, 2, chain->hop_proxy_ids[i]);
        sqlite3_bind_int(stmt, 3, i);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    return PF_OK;
}

int pf_config_chain_delete(pf_config_t *cfg, int id) {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(cfg->db, "DELETE FROM chains WHERE id=?", -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, id);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return PF_OK;
}

/* --- Key-Value Config --- */

int pf_config_get(pf_config_t *cfg, const char *key, char *value, int max_len) {
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(cfg->db, "SELECT value FROM config WHERE key=?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return PF_ERR_DB;
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_ROW) { sqlite3_finalize(stmt); return PF_ERR; }
    strncpy(value, (const char *)sqlite3_column_text(stmt, 0), max_len - 1);
    sqlite3_finalize(stmt);
    return PF_OK;
}

int pf_config_set(pf_config_t *cfg, const char *key, const char *value) {
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(cfg->db,
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return PF_ERR_DB;
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, value, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? PF_OK : PF_ERR_DB;
}
```

- [ ] **Step 3: Write test for config module**

Create `daemon/tests/test_config.c`:
```c
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include "config.h"

#define TEST_DB "/tmp/pf_test.db"

int main(void) {
    unlink(TEST_DB);
    pf_config_t cfg;
    assert(pf_config_init(&cfg, TEST_DB) == PF_OK);

    /* Test proxy CRUD */
    pf_proxy_t p = {0};
    strncpy(p.name, "TestProxy", sizeof(p.name));
    p.type = PF_PROXY_SOCKS5;
    strncpy(p.host, "1.2.3.4", sizeof(p.host));
    p.port = 1080;
    p.enabled = true;
    assert(pf_config_proxy_add(&cfg, &p) == PF_OK);

    int count = 0;
    pf_proxy_t list[10];
    assert(pf_config_proxy_list(&cfg, list, 10, &count) == PF_OK);
    assert(count == 1);
    assert(strcmp(list[0].name, "TestProxy") == 0);
    assert(list[0].port == 1080);
    printf("PASS: proxy CRUD\n");

    /* Test rule CRUD */
    pf_rule_t r = {0};
    strncpy(r.name, "Block ads", sizeof(r.name));
    r.enabled = true;
    r.priority = 10;
    strncpy(r.match_domain, "*.ads.com", sizeof(r.match_domain));
    r.action = PF_ACTION_BLOCK;
    r.proxy_id = -1;
    r.chain_id = -1;
    assert(pf_config_rule_add(&cfg, &r) == PF_OK);

    pf_rule_t rules[10];
    assert(pf_config_rule_list(&cfg, rules, 10, &count) == PF_OK);
    assert(count == 1);
    assert(rules[0].action == PF_ACTION_BLOCK);
    printf("PASS: rule CRUD\n");

    /* Test key-value config */
    assert(pf_config_set(&cfg, "log_to_disk", "true") == PF_OK);
    char val[64];
    assert(pf_config_get(&cfg, "log_to_disk", val, sizeof(val)) == PF_OK);
    assert(strcmp(val, "true") == 0);
    printf("PASS: key-value config\n");

    pf_config_close(&cfg);
    unlink(TEST_DB);
    printf("ALL TESTS PASSED\n");
    return 0;
}
```

Run:
```bash
cd ~/projects/proxiflare/daemon/build
cmake .. -DCMAKE_BUILD_TYPE=Debug && make pf-test-config -j$(nproc)
./pf-test-config
```
Expected: ALL TESTS PASSED

- [ ] **Step 4: Commit**

```bash
git add daemon/src/config.c daemon/src/config.h daemon/tests/test_config.c
git commit -m "feat: SQLite config module with proxy/rule/chain CRUD"
```

---

### Task 3: Crypto Module (AES-256-GCM + Argon2id)

**Files:**
- Create: `daemon/src/crypto.h`
- Create: `daemon/src/crypto.c`

- [ ] **Step 1: Create `daemon/src/crypto.h`**

```c
#ifndef PF_CRYPTO_H
#define PF_CRYPTO_H

#include "proxiflare.h"
#include <stddef.h>

#define PF_SALT_LEN 16
#define PF_IV_LEN 12
#define PF_TAG_LEN 16
#define PF_KEY_LEN 32  /* AES-256 */

/* Crypto context — holds derived key in memory */
typedef struct {
    uint8_t key[PF_KEY_LEN];
    uint8_t salt[PF_SALT_LEN];
    bool unlocked;
} pf_crypto_t;

/* Initialize crypto subsystem */
int pf_crypto_init(pf_crypto_t *ctx);

/* Set master password — derives key with Argon2id, stores salt in config */
int pf_crypto_set_master(pf_crypto_t *ctx, const char *password, const uint8_t *salt);

/* Unlock with existing salt (loaded from DB) */
int pf_crypto_unlock(pf_crypto_t *ctx, const char *password, const uint8_t *salt);

/* Lock — zeroes key from memory */
void pf_crypto_lock(pf_crypto_t *ctx);

/* Encrypt plaintext → ciphertext (IV || ciphertext || tag)
   out_len = in_len + PF_IV_LEN + PF_TAG_LEN */
int pf_crypto_encrypt(pf_crypto_t *ctx, const uint8_t *in, size_t in_len,
                      uint8_t *out, size_t *out_len);

/* Decrypt (IV || ciphertext || tag) → plaintext */
int pf_crypto_decrypt(pf_crypto_t *ctx, const uint8_t *in, size_t in_len,
                      uint8_t *out, size_t *out_len);

/* Generate random salt */
int pf_crypto_random_salt(uint8_t *salt, size_t len);

/* Export config encrypted with separate password */
int pf_crypto_export_encrypt(const char *password, const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t *out_len);
int pf_crypto_export_decrypt(const char *password, const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t *out_len);

#endif /* PF_CRYPTO_H */
```

- [ ] **Step 2: Implement `daemon/src/crypto.c`**

Key implementation details:
- Argon2id key derivation: memory=64MB, iterations=3, parallelism=4
- AES-256-GCM via OpenSSL EVP API
- Random IV generated per encryption call via `RAND_bytes()`
- Wire format: `[16 salt][12 IV][N ciphertext][16 tag]`
- `pf_crypto_lock()` uses `explicit_bzero()` to clear key

```c
#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <argon2.h>
#include <string.h>
#include <stdio.h>

#define ARGON2_T_COST 3
#define ARGON2_M_COST (64 * 1024)  /* 64 MB */
#define ARGON2_PARALLELISM 4

int pf_crypto_init(pf_crypto_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->unlocked = false;
    return PF_OK;
}

static int derive_key(const char *password, const uint8_t *salt, uint8_t *key) {
    int rc = argon2id_hash_raw(ARGON2_T_COST, ARGON2_M_COST, ARGON2_PARALLELISM,
                               password, strlen(password),
                               salt, PF_SALT_LEN,
                               key, PF_KEY_LEN);
    if (rc != ARGON2_OK) {
        fprintf(stderr, "[crypto] argon2id failed: %s\n", argon2_error_message(rc));
        return PF_ERR_CRYPTO;
    }
    return PF_OK;
}

int pf_crypto_set_master(pf_crypto_t *ctx, const char *password, const uint8_t *salt) {
    if (salt) {
        memcpy(ctx->salt, salt, PF_SALT_LEN);
    } else {
        if (RAND_bytes(ctx->salt, PF_SALT_LEN) != 1) return PF_ERR_CRYPTO;
    }
    int rc = derive_key(password, ctx->salt, ctx->key);
    if (rc == PF_OK) ctx->unlocked = true;
    return rc;
}

int pf_crypto_unlock(pf_crypto_t *ctx, const char *password, const uint8_t *salt) {
    memcpy(ctx->salt, salt, PF_SALT_LEN);
    int rc = derive_key(password, ctx->salt, ctx->key);
    if (rc == PF_OK) ctx->unlocked = true;
    return rc;
}

void pf_crypto_lock(pf_crypto_t *ctx) {
    explicit_bzero(ctx->key, PF_KEY_LEN);
    ctx->unlocked = false;
}

int pf_crypto_random_salt(uint8_t *salt, size_t len) {
    return RAND_bytes(salt, len) == 1 ? PF_OK : PF_ERR_CRYPTO;
}

int pf_crypto_encrypt(pf_crypto_t *ctx, const uint8_t *in, size_t in_len,
                      uint8_t *out, size_t *out_len) {
    if (!ctx->unlocked) return PF_ERR_LOCKED;

    uint8_t iv[PF_IV_LEN];
    if (RAND_bytes(iv, PF_IV_LEN) != 1) return PF_ERR_CRYPTO;

    EVP_CIPHER_CTX *evp = EVP_CIPHER_CTX_new();
    if (!evp) return PF_ERR_CRYPTO;

    /* out = IV || ciphertext || tag */
    memcpy(out, iv, PF_IV_LEN);
    int offset = PF_IV_LEN;

    int len = 0;
    EVP_EncryptInit_ex(evp, EVP_aes_256_gcm(), NULL, ctx->key, iv);
    EVP_EncryptUpdate(evp, out + offset, &len, in, (int)in_len);
    offset += len;
    EVP_EncryptFinal_ex(evp, out + offset, &len);
    offset += len;
    EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_GET_TAG, PF_TAG_LEN, out + offset);
    offset += PF_TAG_LEN;

    *out_len = offset;
    EVP_CIPHER_CTX_free(evp);
    return PF_OK;
}

int pf_crypto_decrypt(pf_crypto_t *ctx, const uint8_t *in, size_t in_len,
                      uint8_t *out, size_t *out_len) {
    if (!ctx->unlocked) return PF_ERR_LOCKED;
    if (in_len < PF_IV_LEN + PF_TAG_LEN) return PF_ERR_CRYPTO;

    const uint8_t *iv = in;
    const uint8_t *ciphertext = in + PF_IV_LEN;
    size_t ct_len = in_len - PF_IV_LEN - PF_TAG_LEN;
    const uint8_t *tag = in + PF_IV_LEN + ct_len;

    EVP_CIPHER_CTX *evp = EVP_CIPHER_CTX_new();
    if (!evp) return PF_ERR_CRYPTO;

    int len = 0;
    EVP_DecryptInit_ex(evp, EVP_aes_256_gcm(), NULL, ctx->key, iv);
    EVP_DecryptUpdate(evp, out, &len, ciphertext, (int)ct_len);
    *out_len = len;
    EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_TAG, PF_TAG_LEN, (void *)tag);

    int rc = EVP_DecryptFinal_ex(evp, out + len, &len);
    EVP_CIPHER_CTX_free(evp);

    if (rc <= 0) return PF_ERR_AUTH; /* tag verification failed */
    *out_len += len;
    return PF_OK;
}

int pf_crypto_export_encrypt(const char *password, const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t *out_len) {
    pf_crypto_t tmp;
    pf_crypto_init(&tmp);
    uint8_t salt[PF_SALT_LEN];
    pf_crypto_random_salt(salt, PF_SALT_LEN);
    pf_crypto_set_master(&tmp, password, salt);

    /* out = salt || encrypted_data */
    memcpy(out, salt, PF_SALT_LEN);
    size_t enc_len;
    int rc = pf_crypto_encrypt(&tmp, in, in_len, out + PF_SALT_LEN, &enc_len);
    *out_len = PF_SALT_LEN + enc_len;
    pf_crypto_lock(&tmp);
    return rc;
}

int pf_crypto_export_decrypt(const char *password, const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t *out_len) {
    if (in_len < PF_SALT_LEN) return PF_ERR_CRYPTO;
    pf_crypto_t tmp;
    pf_crypto_init(&tmp);
    pf_crypto_unlock(&tmp, password, in); /* first 16 bytes = salt */
    int rc = pf_crypto_decrypt(&tmp, in + PF_SALT_LEN, in_len - PF_SALT_LEN, out, out_len);
    pf_crypto_lock(&tmp);
    return rc;
}
```

- [ ] **Step 3: Test crypto module**

Add test target to CMakeLists.txt and create `daemon/tests/test_crypto.c`:
```c
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "crypto.h"

int main(void) {
    pf_crypto_t ctx;
    pf_crypto_init(&ctx);

    /* Test set master + encrypt/decrypt */
    assert(pf_crypto_set_master(&ctx, "testpass123", NULL) == PF_OK);
    assert(ctx.unlocked == true);

    const char *plaintext = "Hello ProxiFlare!";
    uint8_t encrypted[256], decrypted[256];
    size_t enc_len, dec_len;

    assert(pf_crypto_encrypt(&ctx, (const uint8_t *)plaintext, strlen(plaintext),
                             encrypted, &enc_len) == PF_OK);
    assert(enc_len == strlen(plaintext) + PF_IV_LEN + PF_TAG_LEN);

    assert(pf_crypto_decrypt(&ctx, encrypted, enc_len, decrypted, &dec_len) == PF_OK);
    assert(dec_len == strlen(plaintext));
    assert(memcmp(decrypted, plaintext, dec_len) == 0);
    printf("PASS: encrypt/decrypt roundtrip\n");

    /* Test lock */
    pf_crypto_lock(&ctx);
    assert(ctx.unlocked == false);
    assert(pf_crypto_encrypt(&ctx, (const uint8_t *)plaintext, strlen(plaintext),
                             encrypted, &enc_len) == PF_ERR_LOCKED);
    printf("PASS: lock prevents operations\n");

    /* Test unlock with same password + salt */
    uint8_t saved_salt[PF_SALT_LEN];
    pf_crypto_set_master(&ctx, "testpass123", NULL);
    memcpy(saved_salt, ctx.salt, PF_SALT_LEN);
    pf_crypto_encrypt(&ctx, (const uint8_t *)plaintext, strlen(plaintext), encrypted, &enc_len);
    pf_crypto_lock(&ctx);

    assert(pf_crypto_unlock(&ctx, "testpass123", saved_salt) == PF_OK);
    assert(pf_crypto_decrypt(&ctx, encrypted, enc_len, decrypted, &dec_len) == PF_OK);
    assert(memcmp(decrypted, plaintext, dec_len) == 0);
    printf("PASS: unlock with saved salt\n");

    /* Test export/import */
    uint8_t exported[512], imported[256];
    size_t exp_len, imp_len;
    assert(pf_crypto_export_encrypt("exportpass", (const uint8_t *)plaintext,
                                    strlen(plaintext), exported, &exp_len) == PF_OK);
    assert(pf_crypto_export_decrypt("exportpass", exported, exp_len,
                                    imported, &imp_len) == PF_OK);
    assert(imp_len == strlen(plaintext));
    assert(memcmp(imported, plaintext, imp_len) == 0);
    printf("PASS: export encrypt/decrypt\n");

    /* Wrong password fails */
    assert(pf_crypto_export_decrypt("wrongpass", exported, exp_len,
                                    imported, &imp_len) == PF_ERR_AUTH);
    printf("PASS: wrong password rejected\n");

    printf("ALL CRYPTO TESTS PASSED\n");
    return 0;
}
```

- [ ] **Step 4: Commit**

```bash
git add daemon/src/crypto.c daemon/src/crypto.h daemon/tests/test_crypto.c
git commit -m "feat: AES-256-GCM crypto module with Argon2id key derivation"
```

---

### Task 4: IPC Server (Unix Socket + JSON-NL)

**Files:**
- Create: `daemon/src/ipc.h`
- Create: `daemon/src/ipc.c`

- [ ] **Step 1: Create `daemon/src/ipc.h`**

```c
#ifndef PF_IPC_H
#define PF_IPC_H

#include "proxiflare.h"
#include <cJSON.h>

/* IPC client connection */
typedef struct {
    int fd;
    char buf[PF_BUF_SIZE];
    int buf_len;
    bool subscribed_log;   /* receives log.entry events */
    bool subscribed_stats; /* receives stats.update events */
} pf_ipc_client_t;

/* IPC server */
typedef struct {
    int listen_fd;
    pf_ipc_client_t clients[PF_MAX_CLIENTS];
    int client_count;
    /* Callback: process a request, return response JSON (caller frees) */
    cJSON *(*handler)(pf_ctx_t *ctx, const char *method, cJSON *params, pf_ipc_client_t *client);
    pf_ctx_t *ctx;
} pf_ipc_t;

/* Init/close */
int pf_ipc_init(pf_ipc_t *ipc, const char *socket_path, pf_ctx_t *ctx,
                cJSON *(*handler)(pf_ctx_t *, const char *, cJSON *, pf_ipc_client_t *));
void pf_ipc_close(pf_ipc_t *ipc);

/* Accept new connections */
int pf_ipc_accept(pf_ipc_t *ipc);

/* Read and process messages from a client. Returns -1 if client disconnected */
int pf_ipc_process(pf_ipc_t *ipc, int client_idx);

/* Send response to specific client */
int pf_ipc_send(pf_ipc_client_t *client, cJSON *msg);

/* Broadcast event to all subscribed clients */
int pf_ipc_broadcast_log(pf_ipc_t *ipc, cJSON *event);
int pf_ipc_broadcast_stats(pf_ipc_t *ipc, cJSON *event);

/* Get listen fd for epoll */
int pf_ipc_get_fd(pf_ipc_t *ipc);

#endif /* PF_IPC_H */
```

- [ ] **Step 2: Implement `daemon/src/ipc.c`**

Key implementation:
- Creates Unix socket at given path, `listen()` with backlog 5
- `pf_ipc_accept()`: accepts new client, adds to clients array
- `pf_ipc_process()`: reads from client fd, splits by `\n`, parses each line as JSON, extracts `id`, `method`, `params`, calls handler callback, sends response as `{"id": N, "result": ...}` or `{"id": N, "error": ...}`
- `pf_ipc_broadcast_log()`: iterates clients with `subscribed_log=true`, sends event
- Non-blocking sockets with `O_NONBLOCK`
- Client disconnect cleanup: close fd, compact array

- [ ] **Step 3: Commit**

```bash
git add daemon/src/ipc.c daemon/src/ipc.h
git commit -m "feat: IPC server with Unix socket and JSON-NL protocol"
```

---

### Task 5: Logger Module

**Files:**
- Create: `daemon/src/logger.h`
- Create: `daemon/src/logger.c`

- [ ] **Step 1: Create `daemon/src/logger.h`**

```c
#ifndef PF_LOGGER_H
#define PF_LOGGER_H

#include "proxiflare.h"
#include <cJSON.h>

typedef struct {
    bool disk_enabled;
    char log_path[PF_PATH_MAX];
    FILE *log_file;
    size_t max_size;      /* bytes, default 100MB */
    int max_files;        /* rotation count, default 5 */
    size_t current_size;
} pf_logger_t;

int pf_logger_init(pf_logger_t *log, const char *path);
void pf_logger_close(pf_logger_t *log);

/* Enable/disable disk logging */
int pf_logger_disk_enable(pf_logger_t *log);
int pf_logger_disk_disable(pf_logger_t *log);

/* Log an entry — returns cJSON event for IPC broadcast (caller frees) */
cJSON *pf_logger_log(pf_logger_t *log, const pf_log_entry_t *entry);

/* Rotate log file if needed */
int pf_logger_rotate(pf_logger_t *log);

/* Daemon internal logging */
void pf_log_info(const char *fmt, ...);
void pf_log_warn(const char *fmt, ...);
void pf_log_error(const char *fmt, ...);

#endif /* PF_LOGGER_H */
```

- [ ] **Step 2: Implement `daemon/src/logger.c`**

Key points:
- `pf_logger_log()`: formats entry as `[2026-04-11 14:32:01] [firefox:1234] sky.ch → CH (PROXY) 1024/14320 42ms`, writes to disk if enabled, creates cJSON event object for IPC broadcast
- Log rotation: when `current_size >= max_size`, rename `.log` → `.log.1`, `.log.1` → `.log.2`, etc., delete oldest beyond `max_files`
- `pf_log_info/warn/error`: stderr + syslog style, with `[proxiflare]` prefix and timestamp

- [ ] **Step 3: Commit**

```bash
git add daemon/src/logger.c daemon/src/logger.h
git commit -m "feat: dual logger with disk rotation and IPC event generation"
```

---

### Task 6: Rule Engine

**Files:**
- Create: `daemon/src/rules.h`
- Create: `daemon/src/rules.c`

- [ ] **Step 1: Create `daemon/src/rules.h`**

```c
#ifndef PF_RULES_H
#define PF_RULES_H

#include "proxiflare.h"

/* In-memory rule cache for fast matching */
typedef struct {
    pf_rule_t rules[PF_MAX_RULES];
    int count;
} pf_ruleset_t;

/* Load rules from config into memory */
int pf_rules_load(pf_ruleset_t *rs, pf_config_t *cfg);

/* Match a connection against rules. Returns the matching rule or NULL */
const pf_rule_t *pf_rules_match(const pf_ruleset_t *rs,
                                 const char *app_path,    /* nullable */
                                 const char *domain,      /* nullable */
                                 const char *dst_ip,      /* nullable */
                                 int dst_port);

/* Pattern matching helpers */
bool pf_match_domain(const char *pattern, const char *domain);
bool pf_match_app(const char *pattern, const char *app_path);
bool pf_match_ip(const char *pattern, const char *ip);
bool pf_match_port(const char *pattern, int port);

#endif /* PF_RULES_H */
```

- [ ] **Step 2: Implement `daemon/src/rules.c`**

Critical matching logic:

```c
#include "rules.h"
#include "config.h"
#include <string.h>
#include <fnmatch.h>
#include <arpa/inet.h>
#include <stdlib.h>

int pf_rules_load(pf_ruleset_t *rs, pf_config_t *cfg) {
    return pf_config_rule_list(cfg, rs->rules, PF_MAX_RULES, &rs->count);
}

bool pf_match_domain(const char *pattern, const char *domain) {
    if (!pattern || !pattern[0] || !domain || !domain[0]) return false;

    /* Exact match */
    if (strcasecmp(pattern, domain) == 0) return true;

    /* Wildcard *.example.com matches sub.example.com and example.com */
    if (pattern[0] == '*' && pattern[1] == '.') {
        const char *suffix = pattern + 1; /* .example.com */
        size_t slen = strlen(suffix);
        size_t dlen = strlen(domain);
        if (dlen >= slen && strcasecmp(domain + dlen - slen, suffix) == 0)
            return true;
        /* Also match the bare domain: *.example.com matches example.com */
        if (strcasecmp(suffix + 1, domain) == 0)
            return true;
    }

    /* Contains wildcard: *streaming* */
    if (pattern[0] == '*' && pattern[strlen(pattern) - 1] == '*') {
        char needle[PF_DOMAIN_MAX];
        strncpy(needle, pattern + 1, sizeof(needle) - 1);
        needle[strlen(needle) - 1] = '\0';
        return strcasestr(domain, needle) != NULL;
    }

    /* fnmatch fallback for complex patterns */
    return fnmatch(pattern, domain, FNM_CASEFOLD) == 0;
}

bool pf_match_app(const char *pattern, const char *app_path) {
    if (!pattern || !pattern[0] || !app_path || !app_path[0]) return false;

    /* Exact path match */
    if (strcmp(pattern, app_path) == 0) return true;

    /* Process name match (no /) */
    if (!strchr(pattern, '/')) {
        const char *basename = strrchr(app_path, '/');
        basename = basename ? basename + 1 : app_path;
        return strcmp(pattern, basename) == 0;
    }

    /* Wildcard path */
    return fnmatch(pattern, app_path, 0) == 0;
}

bool pf_match_ip(const char *pattern, const char *ip) {
    if (!pattern || !pattern[0] || !ip || !ip[0]) return false;

    /* CIDR match: 192.168.1.0/24 */
    char *slash = strchr(pattern, '/');
    if (slash) {
        char net[46];
        strncpy(net, pattern, slash - pattern);
        net[slash - pattern] = '\0';
        int prefix = atoi(slash + 1);

        struct in_addr addr, net_addr;
        if (inet_pton(AF_INET, ip, &addr) != 1) return false;
        if (inet_pton(AF_INET, net, &net_addr) != 1) return false;

        uint32_t mask = prefix == 0 ? 0 : htonl(~((1U << (32 - prefix)) - 1));
        return (addr.s_addr & mask) == (net_addr.s_addr & mask);
    }

    /* Range: 10.0.0.1-10.0.0.255 */
    char *dash = strchr(pattern, '-');
    if (dash) {
        char start[46], end[46];
        strncpy(start, pattern, dash - pattern);
        start[dash - pattern] = '\0';
        strncpy(end, dash + 1, sizeof(end) - 1);

        struct in_addr a, s, e;
        if (inet_pton(AF_INET, ip, &a) != 1) return false;
        if (inet_pton(AF_INET, start, &s) != 1) return false;
        if (inet_pton(AF_INET, end, &e) != 1) return false;

        uint32_t av = ntohl(a.s_addr), sv = ntohl(s.s_addr), ev = ntohl(e.s_addr);
        return av >= sv && av <= ev;
    }

    /* Exact */
    return strcmp(pattern, ip) == 0;
}

bool pf_match_port(const char *pattern, int port) {
    if (!pattern || !pattern[0]) return false;

    const char *p = pattern;
    if (*p == ':') p++;

    /* Range: 8000-9000 */
    char *dash = strchr(p, '-');
    if (dash) {
        int lo = atoi(p), hi = atoi(dash + 1);
        return port >= lo && port <= hi;
    }

    /* Exact */
    return port == atoi(p);
}

const pf_rule_t *pf_rules_match(const pf_ruleset_t *rs,
                                 const char *app_path,
                                 const char *domain,
                                 const char *dst_ip,
                                 int dst_port) {
    for (int i = 0; i < rs->count; i++) {
        const pf_rule_t *r = &rs->rules[i];
        if (!r->enabled) continue;

        bool app_ok = !r->match_app[0] || pf_match_app(r->match_app, app_path);
        bool dom_ok = !r->match_domain[0] || pf_match_domain(r->match_domain, domain);
        bool ip_ok = !r->match_ip[0] || pf_match_ip(r->match_ip, dst_ip);
        bool port_ok = !r->match_port[0] || pf_match_port(r->match_port, dst_port);

        /* All non-empty conditions must match */
        bool has_condition = r->match_app[0] || r->match_domain[0] ||
                             r->match_ip[0] || r->match_port[0];

        if (has_condition && app_ok && dom_ok && ip_ok && port_ok)
            return r;

        /* Default rule: no conditions set */
        if (!has_condition)
            return r;
    }
    return NULL; /* No match — implicit DIRECT */
}
```

- [ ] **Step 3: Write rule engine tests**

Create `daemon/tests/test_rules.c` with tests for:
- `pf_match_domain("*.sky.ch", "api.sky.ch")` → true
- `pf_match_domain("*.sky.ch", "sky.ch")` → true
- `pf_match_domain("*.ch", "sky.ch")` → true
- `pf_match_domain("sky.ch", "notsky.ch")` → false
- `pf_match_app("firefox", "/usr/bin/firefox")` → true
- `pf_match_app("/usr/bin/curl", "/usr/bin/curl")` → true
- `pf_match_ip("192.168.1.0/24", "192.168.1.42")` → true
- `pf_match_ip("192.168.1.0/24", "192.168.2.1")` → false
- `pf_match_port(":443", 443)` → true
- `pf_match_port(":8000-9000", 8500)` → true
- Full `pf_rules_match()` with priority ordering

- [ ] **Step 4: Commit**

```bash
git add daemon/src/rules.c daemon/src/rules.h daemon/tests/test_rules.c
git commit -m "feat: rule engine with domain/app/IP/port pattern matching"
```

---

## Phase 2: Proxy Connectors

### Task 7: SOCKS4/5 Connector

**Files:**
- Create: `daemon/src/proxy_socks.h`
- Create: `daemon/src/proxy_socks.c`

- [ ] **Step 1: Create `daemon/src/proxy_socks.h`**

```c
#ifndef PF_PROXY_SOCKS_H
#define PF_PROXY_SOCKS_H

#include "proxiflare.h"

/* Connect to destination through a SOCKS4/4a proxy.
   Returns connected socket fd or -1 on error */
int pf_socks4_connect(const char *proxy_host, int proxy_port,
                      const char *dst_host, int dst_port,
                      const char *userid);

/* Connect to destination through a SOCKS5 proxy.
   Returns connected socket fd or -1 on error */
int pf_socks5_connect(const char *proxy_host, int proxy_port,
                      const char *dst_host, int dst_port,
                      const char *username, const char *password);

/* Test proxy connectivity — returns latency in ms or -1 on failure */
int pf_socks_test(const pf_proxy_t *proxy);

#endif /* PF_PROXY_SOCKS_H */
```

- [ ] **Step 2: Implement `daemon/src/proxy_socks.c`**

SOCKS5 implementation:
1. TCP connect to proxy
2. Send greeting: `0x05 0x02 0x00 0x02` (no auth + user/pass)
3. Read response, if `0x02` → send user/pass auth
4. Send CONNECT: `0x05 0x01 0x00 0x03 [domain_len] [domain] [port]`
5. Read response, check `0x00` success
6. Return connected fd

SOCKS4a:
1. TCP connect, send `0x04 0x01 [port] [0.0.0.1] [userid\0] [domain\0]`
2. Read 8-byte response, check byte[1] == 0x5A

Test function: CONNECT to `httpbin.org:443`, measure time, close.

- [ ] **Step 3: Commit**

```bash
git add daemon/src/proxy_socks.c daemon/src/proxy_socks.h
git commit -m "feat: SOCKS4/4a and SOCKS5 proxy connectors"
```

---

### Task 8: HTTP CONNECT Proxy

**Files:**
- Create: `daemon/src/proxy_http.h`
- Create: `daemon/src/proxy_http.c`

- [ ] **Step 1: Implement HTTP CONNECT**

```c
/* HTTP CONNECT tunnel:
   1. TCP connect to proxy
   2. Send: "CONNECT dst_host:dst_port HTTP/1.1\r\nHost: dst_host:dst_port\r\n"
   3. If auth: add "Proxy-Authorization: Basic base64(user:pass)\r\n"
   4. Send: "\r\n"
   5. Read response, check "200"
   6. Return tunneled fd */
```

Interface mirrors proxy_socks: `pf_http_connect()` returns fd, `pf_http_test()` returns latency.

- [ ] **Step 2: Commit**

```bash
git add daemon/src/proxy_http.c daemon/src/proxy_http.h
git commit -m "feat: HTTP CONNECT proxy connector with Basic/Digest auth"
```

---

### Task 9: SSH Tunnel Manager

**Files:**
- Create: `daemon/src/proxy_ssh.h`
- Create: `daemon/src/proxy_ssh.c`

- [ ] **Step 1: Implement SSH tunnel via libssh2**

```c
/* SSH dynamic tunnel (-D style):
   1. libssh2_session_init + handshake
   2. Authenticate (password or key)
   3. libssh2_channel_direct_tcpip() for each connection
   4. Return channel fd wrapper
   
   Session pool: keep SSH sessions alive, reuse for multiple connections.
   Max 1 session per SSH proxy, multiplex channels on it. */
```

Key struct:
```c
typedef struct {
    LIBSSH2_SESSION *session;
    int sock_fd;
    int proxy_id;
    bool connected;
} pf_ssh_session_t;

/* Pool of active SSH sessions */
typedef struct {
    pf_ssh_session_t sessions[PF_MAX_PROXIES];
    int count;
} pf_ssh_pool_t;
```

- [ ] **Step 2: Commit**

```bash
git add daemon/src/proxy_ssh.c daemon/src/proxy_ssh.h
git commit -m "feat: SSH tunnel manager with session pooling via libssh2"
```

---

### Task 10: Proxy Chain Router

**Files:**
- Create: `daemon/src/chain.h`
- Create: `daemon/src/chain.c`

- [ ] **Step 1: Implement chaining**

```c
/* Chain connect:
   Given chain [proxy_A, proxy_B, proxy_C] and destination D:
   1. Connect to proxy_A directly (TCP)
   2. Via proxy_A, CONNECT to proxy_B (using A's protocol)
   3. Via proxy_B (through A), CONNECT to proxy_C
   4. Via proxy_C (through A→B), CONNECT to D
   
   Each hop uses the appropriate connector (socks4/5/http).
   SSH hops use direct-tcpip channel. */
   
int pf_chain_connect(const pf_chain_t *chain, const pf_proxy_t *proxies,
                     const char *dst_host, int dst_port);
int pf_chain_test(const pf_chain_t *chain, const pf_proxy_t *proxies);
```

- [ ] **Step 2: Commit**

```bash
git add daemon/src/chain.c daemon/src/chain.h
git commit -m "feat: multi-hop proxy chain router"
```

---

## Phase 3: Network Interception

### Task 11: DNS Interceptor (NFQUEUE)

**Files:**
- Create: `daemon/src/dns.h`
- Create: `daemon/src/dns.c`

- [ ] **Step 1: Create `daemon/src/dns.h`**

```c
#ifndef PF_DNS_H
#define PF_DNS_H

#include "proxiflare.h"

/* DNS query cache entry — maps domain → resolved IP + rule decision */
typedef struct {
    char domain[PF_DOMAIN_MAX];
    char resolved_ip[46];
    int rule_id;              /* matched rule, -1 if DIRECT */
    time_t expires;
} pf_dns_entry_t;

typedef struct {
    struct nfq_handle *nfq;
    struct nfq_q_handle *queue;
    int fd;
    pf_dns_entry_t cache[4096];
    int cache_count;
    pf_ruleset_t *ruleset;    /* pointer to active ruleset */
} pf_dns_t;

int pf_dns_init(pf_dns_t *dns, pf_ruleset_t *ruleset);
void pf_dns_close(pf_dns_t *dns);
int pf_dns_get_fd(pf_dns_t *dns);
int pf_dns_process(pf_dns_t *dns);  /* call when fd is readable */

/* Lookup cached domain → rule */
const pf_dns_entry_t *pf_dns_lookup(pf_dns_t *dns, const char *ip);

#endif /* PF_DNS_H */
```

- [ ] **Step 2: Implement `daemon/src/dns.c`**

NFQUEUE callback flow:
1. nftables redirects outgoing DNS (port 53 UDP) to NFQUEUE 0
2. Callback receives packet, parses DNS query section to extract queried domain
3. Looks up domain in ruleset via `pf_rules_match()`
4. Caches `resolved_ip → domain + rule_id` mapping (populated after DNS response)
5. Sets verdict ACCEPT (let DNS through, we route the subsequent TCP connection)

DNS packet parsing: standard format — 12-byte header, then QNAME (labels), QTYPE, QCLASS.

- [ ] **Step 3: Commit**

```bash
git add daemon/src/dns.c daemon/src/dns.h
git commit -m "feat: DNS interceptor via NFQUEUE with domain caching"
```

---

### Task 12: SNI Parser

**Files:**
- Create: `daemon/src/sni.h`
- Create: `daemon/src/sni.c`

- [ ] **Step 1: Implement TLS ClientHello SNI extraction**

```c
#ifndef PF_SNI_H
#define PF_SNI_H

/* Extract SNI hostname from TLS ClientHello packet.
   Returns length of hostname copied to out, or 0 if not found.
   Does NOT modify the packet data — read-only inspection. */
int pf_sni_extract(const uint8_t *data, size_t len, char *out, size_t out_max);

#endif

/* Implementation: 
   1. Check byte 0 = 0x16 (handshake), bytes 1-2 = TLS version
   2. Skip 5-byte record header
   3. Check handshake type = 0x01 (ClientHello)
   4. Skip to session ID, skip session ID
   5. Skip cipher suites, compression methods
   6. Parse extensions: find type 0x0000 (SNI)
   7. Extract hostname from SNI extension */
```

Pure parser, no dependencies. ~80 lines of careful bounds-checked byte parsing.

- [ ] **Step 2: Write SNI parser test**

Test with a captured TLS ClientHello for `www.google.com`. Hardcode the bytes, verify extraction.

- [ ] **Step 3: Commit**

```bash
git add daemon/src/sni.c daemon/src/sni.h daemon/tests/test_sni.c
git commit -m "feat: TLS ClientHello SNI parser"
```

---

### Task 13: TPROXY Transparent Proxy Handler

**Files:**
- Create: `daemon/src/tproxy.h`
- Create: `daemon/src/tproxy.c`

- [ ] **Step 1: Implement TPROXY listener**

```c
/* TPROXY flow:
   1. Listen on a local port (default 12345) with IP_TRANSPARENT socket option
   2. nftables TPROXY rule redirects matching traffic to this port
   3. On accept: getsockopt(SO_ORIGINAL_DST) to get real destination
   4. Read first bytes: if TLS → extract SNI for domain confirmation
   5. Lookup DNS cache by original dst IP → get domain + rule
   6. Connect to destination via matched proxy/chain
   7. Splice/relay data between client and proxy connection */
```

Key: `setsockopt(fd, SOL_IP, IP_TRANSPARENT, ...)` and `getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, ...)`.

Uses epoll for concurrent connection handling. Each connection is a relay pair (client_fd ↔ proxy_fd).

- [ ] **Step 2: Commit**

```bash
git add daemon/src/tproxy.c daemon/src/tproxy.h
git commit -m "feat: TPROXY transparent proxy handler with connection relay"
```

---

### Task 14: cgroups v2 Manager

**Files:**
- Create: `daemon/src/cgroup.h`
- Create: `daemon/src/cgroup.c`

- [ ] **Step 1: Implement cgroup management**

```c
/* cgroups v2 manager:
   - Creates /sys/fs/cgroup/proxiflare/ hierarchy
   - Creates per-rule cgroups: /sys/fs/cgroup/proxiflare/rule_<id>/
   - Assigns PIDs to cgroups by writing to cgroup.procs
   - nftables matches cgroup path for packet marking
   
   Functions:
   - pf_cgroup_init(): create base hierarchy
   - pf_cgroup_create_rule(rule_id): create cgroup for rule
   - pf_cgroup_assign_pid(rule_id, pid): move process to cgroup
   - pf_cgroup_remove_pid(pid): remove from all proxiflare cgroups
   - pf_cgroup_cleanup(): remove hierarchy */
```

All operations are filesystem writes to `/sys/fs/cgroup/`.

- [ ] **Step 2: Commit**

```bash
git add daemon/src/cgroup.c daemon/src/cgroup.h
git commit -m "feat: cgroups v2 manager for per-app traffic classification"
```

---

### Task 15: nftables Rule Manager

**Files:**
- Create: `daemon/src/nft.h`
- Create: `daemon/src/nft.c`

- [ ] **Step 1: Implement nftables management**

```c
/* nftables rules needed:
   
   table inet proxiflare {
       chain output {
           type filter hook output priority 0;
           
           # Redirect DNS queries to NFQUEUE for interception
           udp dport 53 queue num 0
           
           # Match cgroup-classified traffic → mark for TPROXY
           socket cgroupv2 level 1 "proxiflare/rule_*" mark set 0x1
       }
       
       chain prerouting {
           type filter hook prerouting priority -150;
           
           # TPROXY marked traffic to local listener  
           meta mark 0x1 tproxy to :12345
       }
   }
   
   Functions:
   - pf_nft_init(): create table + chains
   - pf_nft_add_rule(rule_id, cgroup_mark): add per-rule nft entry
   - pf_nft_remove_rule(rule_id): remove rule
   - pf_nft_cleanup(): flush table
   
   Implementation: use popen("nft -f -", "w") to submit rules as batch.
   Safer and more portable than libnftables C API. */
```

- [ ] **Step 2: Commit**

```bash
git add daemon/src/nft.c daemon/src/nft.h
git commit -m "feat: nftables rule manager for DNS redirect and TPROXY"
```

---

### Task 16: Process Monitor

**Files:**
- Create: `daemon/src/monitor.h`
- Create: `daemon/src/monitor.c`

- [ ] **Step 1: Implement process monitor via netlink**

```c
/* Monitor process exec/exit events via proc_event netlink connector.
   When a new process starts:
   1. Read /proc/<pid>/exe to get binary path
   2. Match against app-based rules
   3. If match → assign PID to appropriate cgroup
   
   When process exits:
   1. Remove from cgroup tracking
   
   Uses NETLINK_CONNECTOR with CN_IDX_PROC / CN_VAL_PROC.
   Requires CAP_NET_ADMIN (root). */
```

- [ ] **Step 2: Commit**

```bash
git add daemon/src/monitor.c daemon/src/monitor.h
git commit -m "feat: process monitor via netlink proc connector"
```

---

### Task 17: Stats Collector

**Files:**
- Create: `daemon/src/stats.h`
- Create: `daemon/src/stats.c`

- [ ] **Step 1: Implement stats tracking**

```c
/* Per-proxy, per-app, per-domain stats:
   - bytes_tx, bytes_rx
   - connection count
   - avg latency
   - Tracked in-memory, pushed to GUI via IPC periodically (1s interval)
   
   struct pf_stats_entry { int proxy_id; uint64_t bytes_tx/rx; int conns; int avg_latency_ms; }
   pf_stats_update(): called on each connection event
   pf_stats_get_json(): returns cJSON array for IPC response
   pf_stats_reset(): zero all counters */
```

- [ ] **Step 2: Commit**

```bash
git add daemon/src/stats.c daemon/src/stats.h
git commit -m "feat: stats collector for per-proxy/app/domain metrics"
```

---

### Task 18: Daemon Main Event Loop

**Files:**
- Modify: `daemon/src/main.c`

- [ ] **Step 1: Implement full main.c**

The daemon main ties everything together:

```c
/* Global daemon context */
struct pf_ctx {
    pf_config_t config;
    pf_crypto_t crypto;
    pf_ipc_t ipc;
    pf_dns_t dns;
    pf_tproxy_t tproxy;
    pf_logger_t logger;
    pf_ruleset_t ruleset;
    pf_ssh_pool_t ssh_pool;
    pf_stats_t stats;
    int epoll_fd;
    volatile bool running;
};

/* main() flow:
   1. Parse args (--foreground, --config-dir)
   2. Check root
   3. Write PID file
   4. Signal handlers (SIGTERM, SIGINT → set running=false; SIGHUP → reload config)
   5. pf_config_init() → open DB
   6. pf_crypto_init() → ready for unlock
   7. pf_rules_load() → load rules into memory
   8. pf_ipc_init() → start Unix socket
   9. pf_dns_init() → start NFQUEUE listener
   10. pf_nft_init() → install nftables rules
   11. pf_cgroup_init() → create cgroup hierarchy
   12. pf_monitor_init() → start process monitor
   13. pf_tproxy_init() → start TPROXY listener
   14. pf_logger_init() → open log
   15. epoll loop: watch all fds (IPC, DNS, TPROXY, monitor)
   16. On shutdown: cleanup all in reverse order
*/

/* IPC handler — dispatch method calls */
cJSON *pf_handle_request(pf_ctx_t *ctx, const char *method, cJSON *params, pf_ipc_client_t *client) {
    /* Route to appropriate handler based on method prefix:
       proxy.* → proxy CRUD + test
       rule.* → rule CRUD + reorder
       chain.* → chain CRUD + test
       log.* → subscribe/unsubscribe/clear/disk toggle
       stats.* → get/reset
       config.* → get/set
       credentials.* → unlock/lock/change/export/import
       system.* → status/version/shutdown */
}
```

- [ ] **Step 2: Build and test daemon starts**

```bash
cd ~/projects/proxiflare/daemon/build
cmake .. && make -j$(nproc)
sudo ./proxiflare-daemon --foreground
# Should print startup messages and wait for connections
# Ctrl+C to stop
```

- [ ] **Step 3: Commit**

```bash
git add daemon/src/main.c
git commit -m "feat: daemon main event loop with epoll and full subsystem init"
```

---

## Phase 4: GUI — Tauri Shell

### Task 19: Tauri Project Setup

**Files:**
- Create: `gui/package.json`
- Create: `gui/src-tauri/Cargo.toml`
- Create: `gui/src-tauri/tauri.conf.json`
- Create: `gui/src-tauri/src/main.rs`
- Create: `gui/vite.config.ts`
- Create: `gui/tsconfig.json`
- Create: `gui/index.html`

- [ ] **Step 1: Initialize Tauri project**

```bash
cd ~/projects/proxiflare/gui
npm create vite@latest . -- --template react-ts
npm install
npm install -D tailwindcss @tailwindcss/vite
npx tailwindcss init
npm install @tauri-apps/cli@latest @tauri-apps/api@latest
cargo install tauri-cli  # or use npx
npx tauri init
```

Configure `tauri.conf.json`:
```json
{
  "build": {
    "devPath": "http://localhost:5173",
    "distDir": "../dist"
  },
  "package": {
    "productName": "ProxiFlare",
    "version": "1.0.0"
  },
  "tauri": {
    "bundle": {
      "identifier": "com.proxiflare.app",
      "icon": ["../assets/icon-32.png", "../assets/icon-128.png", "../assets/icon-512.png"]
    },
    "windows": [{
      "title": "ProxiFlare",
      "width": 1100,
      "height": 700,
      "minWidth": 900,
      "minHeight": 600
    }]
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add gui/
git commit -m "feat: Tauri + React + Vite project scaffold"
```

---

### Task 20: Tauri IPC Bridge (Rust)

**Files:**
- Create: `gui/src-tauri/src/ipc.rs`
- Create: `gui/src-tauri/src/commands.rs`
- Modify: `gui/src-tauri/src/main.rs`

- [ ] **Step 1: Implement `ipc.rs` — Unix socket client**

```rust
// Connects to /run/proxiflare.sock
// Sends JSON-NL requests, receives responses
// Spawns background thread for event listening (log, stats, proxy.status)
// Exposes: send_request(method, params) -> Result<Value>
// Exposes: subscribe(event_type, callback)
```

- [ ] **Step 2: Implement `commands.rs` — Tauri commands**

```rust
// #[tauri::command] wrappers that call ipc::send_request()
// Each IPC method gets a Tauri command:
// proxy_list, proxy_add, proxy_edit, proxy_delete, proxy_test
// rule_list, rule_add, rule_edit, rule_delete, rule_reorder
// chain_list, chain_add, chain_edit, chain_delete, chain_test
// log_subscribe, log_unsubscribe
// config_get, config_set
// credentials_unlock, credentials_lock, credentials_export, credentials_import
// system_status, system_version
```

- [ ] **Step 3: Wire up main.rs**

```rust
fn main() {
    tauri::Builder::default()
        .setup(|app| {
            // Connect to daemon socket
            // Start event listener thread
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::proxy_list,
            commands::proxy_add,
            // ... all commands
        ])
        .run(tauri::generate_context!())
        .expect("error running ProxiFlare");
}
```

- [ ] **Step 4: Commit**

```bash
git add gui/src-tauri/
git commit -m "feat: Tauri IPC bridge and command wrappers"
```

---

## Phase 5: GUI — React Frontend

### Task 21: Types, API Layer, and Hooks

**Files:**
- Create: `gui/src/lib/types.ts`
- Create: `gui/src/lib/api.ts`
- Create: `gui/src/hooks/useDaemon.ts`
- Create: `gui/src/hooks/useLog.ts`

- [ ] **Step 1: Create `gui/src/lib/types.ts`**

```typescript
export type ProxyType = 'socks4' | 'socks5' | 'http' | 'ssh';
export type HealthStatus = 'unknown' | 'online' | 'offline' | 'slow' | 'error';
export type RuleAction = 'DIRECT' | 'PROXY' | 'CHAIN' | 'BLOCK' | 'REJECT';

export interface Proxy {
  id: number;
  name: string;
  type: ProxyType;
  host: string;
  port: number;
  username?: string;
  password?: string;
  enabled: boolean;
  health: HealthStatus;
  latency_ms: number | null;
  check_interval: number;
}

export interface Rule {
  id: number;
  name: string;
  enabled: boolean;
  priority: number;
  match_app?: string;
  match_domain?: string;
  match_ip?: string;
  match_port?: string;
  action: RuleAction;
  proxy_id?: number;
  chain_id?: number;
}

export interface Chain {
  id: number;
  name: string;
  enabled: boolean;
  hop_proxy_ids: number[];
}

export interface LogEntry {
  ts: number;
  app: string;
  pid: number;
  domain: string;
  dst_ip: string;
  dst_port: number;
  proxy: string;
  action: RuleAction;
  bytes_tx: number;
  bytes_rx: number;
  latency_ms: number;
}

export interface DaemonStatus {
  running: boolean;
  uptime: number;
  connections: number;
  proxies_online: number;
  rules_active: number;
}
```

- [ ] **Step 2: Create `gui/src/lib/api.ts`**

```typescript
import { invoke } from '@tauri-apps/api/core';
import type { Proxy, Rule, Chain, LogEntry, DaemonStatus } from './types';

export const api = {
  proxy: {
    list: () => invoke<Proxy[]>('proxy_list'),
    add: (proxy: Omit<Proxy, 'id' | 'health' | 'latency_ms'>) => invoke('proxy_add', { proxy }),
    edit: (proxy: Proxy) => invoke('proxy_edit', { proxy }),
    delete: (id: number) => invoke('proxy_delete', { id }),
    test: (id: number) => invoke<{ latency_ms: number; status: string }>('proxy_test', { id }),
  },
  rule: {
    list: () => invoke<Rule[]>('rule_list'),
    add: (rule: Omit<Rule, 'id'>) => invoke('rule_add', { rule }),
    edit: (rule: Rule) => invoke('rule_edit', { rule }),
    delete: (id: number) => invoke('rule_delete', { id }),
    reorder: (ids: number[]) => invoke('rule_reorder', { ids }),
  },
  chain: {
    list: () => invoke<Chain[]>('chain_list'),
    add: (chain: Omit<Chain, 'id'>) => invoke('chain_add', { chain }),
    edit: (chain: Chain) => invoke('chain_edit', { chain }),
    delete: (id: number) => invoke('chain_delete', { id }),
    test: (id: number) => invoke<{ latency_ms: number; status: string }>('chain_test', { id }),
  },
  log: {
    subscribe: () => invoke('log_subscribe'),
    unsubscribe: () => invoke('log_unsubscribe'),
  },
  config: {
    get: (key: string) => invoke<string>('config_get', { key }),
    set: (key: string, value: string) => invoke('config_set', { key, value }),
  },
  credentials: {
    unlock: (password: string) => invoke('credentials_unlock', { password }),
    lock: () => invoke('credentials_lock'),
    changeMaster: (oldPass: string, newPass: string) => invoke('credentials_change', { oldPass, newPass }),
    export: (path: string, password: string) => invoke('credentials_export', { path, password }),
    import: (path: string, password: string) => invoke('credentials_import', { path, password }),
  },
  system: {
    status: () => invoke<DaemonStatus>('system_status'),
    version: () => invoke<string>('system_version'),
  },
};
```

- [ ] **Step 3: Create `gui/src/hooks/useDaemon.ts`**

```typescript
import { useState, useEffect, useCallback } from 'react';
import { listen } from '@tauri-apps/api/event';
import { api } from '../lib/api';
import type { DaemonStatus } from '../lib/types';

export function useDaemon() {
  const [status, setStatus] = useState<DaemonStatus | null>(null);
  const [connected, setConnected] = useState(false);
  const [unlocked, setUnlocked] = useState(false);

  useEffect(() => {
    const poll = setInterval(async () => {
      try {
        const s = await api.system.status();
        setStatus(s);
        setConnected(true);
      } catch {
        setConnected(false);
      }
    }, 2000);
    return () => clearInterval(poll);
  }, []);

  const unlock = useCallback(async (password: string) => {
    await api.credentials.unlock(password);
    setUnlocked(true);
  }, []);

  return { status, connected, unlocked, unlock };
}
```

- [ ] **Step 4: Create `gui/src/hooks/useLog.ts`**

```typescript
import { useState, useEffect, useRef, useCallback } from 'react';
import { listen } from '@tauri-apps/api/event';
import type { LogEntry } from '../lib/types';

const MAX_ENTRIES = 10000;

export function useLog() {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [paused, setPaused] = useState(false);
  const bufferRef = useRef<LogEntry[]>([]);

  useEffect(() => {
    const unlisten = listen<LogEntry>('log-entry', (event) => {
      if (paused) {
        bufferRef.current.push(event.payload);
        return;
      }
      setEntries(prev => {
        const next = [...prev, event.payload];
        return next.length > MAX_ENTRIES ? next.slice(-MAX_ENTRIES) : next;
      });
    });
    return () => { unlisten.then(fn => fn()); };
  }, [paused]);

  const resume = useCallback(() => {
    setPaused(false);
    setEntries(prev => [...prev, ...bufferRef.current].slice(-MAX_ENTRIES));
    bufferRef.current = [];
  }, []);

  const clear = useCallback(() => setEntries([]), []);

  return { entries, paused, setPaused, resume, clear };
}
```

- [ ] **Step 5: Commit**

```bash
git add gui/src/lib/ gui/src/hooks/
git commit -m "feat: TypeScript types, API layer, and daemon/log hooks"
```

---

### Task 22: App Layout and Tab Navigation

**Files:**
- Create: `gui/src/App.tsx`
- Create: `gui/src/main.tsx`
- Create: `gui/src/styles/globals.css`
- Create: `gui/tailwind.config.js`
- Create: `gui/src/components/MasterPasswordDialog.tsx`

- [ ] **Step 1: Configure Tailwind with ProxiFlare theme**

`tailwind.config.js`:
```javascript
export default {
  content: ['./src/**/*.{ts,tsx}', './index.html'],
  theme: {
    extend: {
      colors: {
        pf: {
          bg: '#0f1117',
          panel: '#1a1d27',
          panel2: '#232733',
          accent: '#6366f1',
          'accent-hover': '#818cf8',
          success: '#22c55e',
          error: '#ef4444',
          warning: '#f59e0b',
          text: '#e2e8f0',
          muted: '#64748b',
          border: '#2d3348',
        }
      }
    }
  },
  plugins: [],
};
```

`globals.css`:
```css
@import "tailwindcss";

body {
  margin: 0;
  background: #0f1117;
  color: #e2e8f0;
  font-family: 'Inter', -apple-system, sans-serif;
  overflow: hidden;
}

/* Custom scrollbar */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #1a1d27; }
::-webkit-scrollbar-thumb { background: #3d4460; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #6366f1; }
```

- [ ] **Step 2: Create App.tsx with tab navigation**

```tsx
import { useState } from 'react';
import { useDaemon } from './hooks/useDaemon';
import { MasterPasswordDialog } from './components/MasterPasswordDialog';
import Proxies from './pages/Proxies';
import Rules from './pages/Rules';
import Chains from './pages/Chains';
import Log from './pages/Log';
import Settings from './pages/Settings';

const TABS = [
  { id: 'proxies', label: 'Proxies', icon: '⬡' },
  { id: 'rules', label: 'Rules', icon: '☰' },
  { id: 'chains', label: 'Chains', icon: '⛓' },
  { id: 'log', label: 'Log', icon: '▤' },
  { id: 'settings', label: 'Settings', icon: '⚙' },
] as const;

type TabId = typeof TABS[number]['id'];

export default function App() {
  const [activeTab, setActiveTab] = useState<TabId>('proxies');
  const { status, connected, unlocked, unlock } = useDaemon();

  if (!unlocked) return <MasterPasswordDialog onUnlock={unlock} />;

  return (
    <div className="h-screen flex flex-col bg-pf-bg">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 bg-pf-panel border-b border-pf-border">
        <div className="flex items-center gap-3">
          <img src="/logo.svg" className="w-7 h-7" alt="ProxiFlare" />
          <span className="text-lg font-semibold text-pf-text">ProxiFlare</span>
        </div>
        <div className="flex items-center gap-2 text-sm">
          <span className={`w-2 h-2 rounded-full ${connected ? 'bg-pf-success' : 'bg-pf-error'}`} />
          <span className="text-pf-muted">
            {connected ? `${status?.connections ?? 0} connections` : 'Disconnected'}
          </span>
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex bg-pf-panel border-b border-pf-border">
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-5 py-3 text-sm font-medium transition-colors relative
              ${activeTab === tab.id
                ? 'text-pf-accent'
                : 'text-pf-muted hover:text-pf-text'}`}
          >
            <span className="mr-2">{tab.icon}</span>
            {tab.label}
            {activeTab === tab.id && (
              <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-pf-accent" />
            )}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-hidden">
        {activeTab === 'proxies' && <Proxies />}
        {activeTab === 'rules' && <Rules />}
        {activeTab === 'chains' && <Chains />}
        {activeTab === 'log' && <Log />}
        {activeTab === 'settings' && <Settings />}
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Create MasterPasswordDialog**

Modal dialog shown on first launch or when credentials are locked. Input field for master password, "Set Password" (first time) or "Unlock" button.

- [ ] **Step 4: Commit**

```bash
git add gui/src/App.tsx gui/src/main.tsx gui/src/styles/ gui/tailwind.config.js gui/src/components/MasterPasswordDialog.tsx
git commit -m "feat: app layout with tab navigation and master password dialog"
```

---

### Task 23: Proxies Page

**Files:**
- Create: `gui/src/pages/Proxies.tsx`
- Create: `gui/src/components/ProxyCard.tsx`
- Create: `gui/src/components/ProxyFormModal.tsx`
- Create: `gui/src/components/StatusBadge.tsx`

- [ ] **Step 1: Implement ProxyCard component**

Card showing: proxy name, type badge (SOCKS5/HTTP/SSH), host:port, health status dot (green/red/yellow), latency in ms, enable/disable toggle. Actions: Edit, Test, Delete.

- [ ] **Step 2: Implement ProxyFormModal**

Modal for add/edit proxy: fields for name, type (select), host, port, username, password (with show/hide toggle), check interval. For SSH type: key file path or paste key.

- [ ] **Step 3: Implement Proxies page**

Grid layout of ProxyCards. Top bar: "Add Proxy" button, Import/Export buttons. Cards arranged in responsive grid (3 cols on wide, 2 on medium, 1 on narrow).

- [ ] **Step 4: Commit**

```bash
git add gui/src/pages/Proxies.tsx gui/src/components/ProxyCard.tsx gui/src/components/ProxyFormModal.tsx gui/src/components/StatusBadge.tsx
git commit -m "feat: Proxies page with card grid, add/edit/test/delete"
```

---

### Task 24: Rules Page

**Files:**
- Create: `gui/src/pages/Rules.tsx`
- Create: `gui/src/components/RuleRow.tsx`
- Create: `gui/src/components/RuleFormModal.tsx`

- [ ] **Step 1: Implement RuleRow**

Table row showing: priority number, name, match conditions (colored badges for app/domain/IP/port), action badge (color-coded), proxy/chain name, enabled toggle. Drag handle for reordering.

- [ ] **Step 2: Implement RuleFormModal**

Modal for add/edit rule: name, priority, match_app (with file picker), match_domain, match_ip, match_port, action (select), proxy (select from list), chain (select from list). Smart UI: proxy/chain select only shows when action is PROXY/CHAIN.

- [ ] **Step 3: Implement Rules page**

Sortable table with drag-to-reorder. Filter bar (by action type, search by name/domain). "Add Rule" button. Batch enable/disable.

- [ ] **Step 4: Commit**

```bash
git add gui/src/pages/Rules.tsx gui/src/components/RuleRow.tsx gui/src/components/RuleFormModal.tsx
git commit -m "feat: Rules page with sortable table, drag-to-reorder, CRUD"
```

---

### Task 25: Chains Page

**Files:**
- Create: `gui/src/pages/Chains.tsx`
- Create: `gui/src/components/ChainBuilder.tsx`

- [ ] **Step 1: Implement ChainBuilder**

Visual chain builder: sidebar shows available proxies, main area shows chain hops as connected boxes with arrows between them. Drag proxy from sidebar to add hop. Click X on hop to remove. Shows total estimated latency (sum of proxy latencies). Test chain button.

- [ ] **Step 2: Implement Chains page**

List of existing chains + "Create Chain" button. Each chain shows name, hop count, proxies in chain, test button.

- [ ] **Step 3: Commit**

```bash
git add gui/src/pages/Chains.tsx gui/src/components/ChainBuilder.tsx
git commit -m "feat: Chains page with visual chain builder"
```

---

### Task 26: Log Page

**Files:**
- Create: `gui/src/pages/Log.tsx`
- Create: `gui/src/components/LogEntry.tsx`

- [ ] **Step 1: Implement LogEntry component**

Single log row: timestamp, app name + pid, domain, destination IP:port, proxy name, action badge (color-coded), bytes tx/rx, latency. Compact single-line format like Proxifier.

Colors: DIRECT=gray-500, PROXY=blue-400, CHAIN=purple-400, BLOCK=red-400, REJECT=orange-400.

- [ ] **Step 2: Implement Log page**

Full-height virtual-scrolling log viewer using `useLog()` hook. Top bar: filter inputs (app, domain, action dropdown), search box, Pause/Resume button, Clear button, "Log to disk" toggle. Auto-scrolls to bottom unless paused. Shows entry count.

Virtual scroll: only render visible rows (~50 at a time), critical for handling 100k+ entries without lag.

- [ ] **Step 3: Commit**

```bash
git add gui/src/pages/Log.tsx gui/src/components/LogEntry.tsx
git commit -m "feat: real-time log page with virtual scroll and filters"
```

---

### Task 27: Settings Page

**Files:**
- Create: `gui/src/pages/Settings.tsx`

- [ ] **Step 1: Implement Settings page**

Sections:
- **Daemon**: Start at boot toggle (calls `config.set("boot_enabled", ...)` which triggers systemd enable/disable), daemon status display
- **Security**: Change master password, Lock credentials button, Export config (file save dialog + password), Import config (file open dialog + password)  
- **Logging**: Toggle disk logging, log file path display, max log size input
- **Appearance**: Dark/Light theme toggle
- **About**: Version, logo, links

- [ ] **Step 2: Commit**

```bash
git add gui/src/pages/Settings.tsx
git commit -m "feat: Settings page with boot, security, logging, theme options"
```

---

## Phase 6: Installer and System Integration

### Task 28: Systemd Service and Polkit Policy

**Files:**
- Create: `scripts/proxiflare-daemon.service`
- Create: `scripts/com.proxiflare.policy`

- [ ] **Step 1: Create systemd service**

```ini
[Unit]
Description=ProxiFlare Proxy Router Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/proxiflare-daemon
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Create polkit policy**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
  "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
  "http://www.freedesktop.org/standards/PolicyKit/1.0/policyconfig.dtd">
<policyconfig>
  <action id="com.proxiflare.daemon.manage">
    <description>Manage ProxiFlare daemon</description>
    <message>Authentication is required to manage ProxiFlare</message>
    <defaults>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
  </action>
</policyconfig>
```

- [ ] **Step 3: Commit**

```bash
git add scripts/proxiflare-daemon.service scripts/com.proxiflare.policy
git commit -m "feat: systemd service unit and polkit policy"
```

---

### Task 29: Installer Script

**Files:**
- Create: `scripts/install.sh`
- Create: `scripts/uninstall.sh`

- [ ] **Step 1: Create `scripts/install.sh`**

```bash
#!/bin/bash
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/proxiflare"
DATA_DIR="/var/lib/proxiflare"
LOG_DIR="/var/log/proxiflare"

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; exit 1; }

# Check root
[[ $EUID -ne 0 ]] && error "Run as root: sudo $0"

# Check OS
[[ "$(uname)" != "Linux" ]] && error "Linux only"

info "Installing ProxiFlare v1.0.0..."

# Install build dependencies
info "Checking dependencies..."
apt-get update -qq
apt-get install -y -qq build-essential cmake pkg-config \
  libsqlite3-dev libnetfilter-queue-dev libnfnetlink-dev \
  libssh2-1-dev libssl-dev libargon2-dev \
  webkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev \
  nftables >/dev/null 2>&1

# Check Node.js
command -v node >/dev/null || error "Node.js >= 18 required. Install: https://nodejs.org"
# Check Rust  
command -v cargo >/dev/null || error "Rust required. Install: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"

# Build daemon
info "Building daemon..."
cd "$(dirname "$0")/../daemon"
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release >/dev/null
make -j$(nproc) >/dev/null
cd ../..

# Build GUI
info "Building GUI..."
cd gui
npm install --silent
npm run tauri build 2>/dev/null
cd ..

# Install binaries
info "Installing binaries..."
install -m 755 daemon/build/proxiflare-daemon "$INSTALL_DIR/"
install -m 755 gui/src-tauri/target/release/proxiflare "$INSTALL_DIR/" 2>/dev/null || \
  install -m 755 gui/src-tauri/target/release/proxi-flare "$INSTALL_DIR/proxiflare"

# Create directories
install -d -m 755 "$CONFIG_DIR"
install -d -m 700 "$DATA_DIR"
install -d -m 755 "$LOG_DIR"

# Install systemd service (disabled by default)
install -m 644 scripts/proxiflare-daemon.service /etc/systemd/system/
systemctl daemon-reload

# Install polkit policy
install -m 644 scripts/com.proxiflare.policy /usr/share/polkit-1/actions/

# Install desktop entry
cat > /usr/share/applications/proxiflare.desktop << 'DESKTOP'
[Desktop Entry]
Name=ProxiFlare
Comment=Professional Proxy Router
Exec=proxiflare
Icon=proxiflare
Type=Application
Categories=Network;Security;
StartupWMClass=proxiflare
DESKTOP

# Install icons
for size in 16 32 128 256 512; do
  dir="/usr/share/icons/hicolor/${size}x${size}/apps"
  install -d "$dir"
  if [ -f "assets/icon-${size}.png" ]; then
    install -m 644 "assets/icon-${size}.png" "$dir/proxiflare.png"
  fi
done
# SVG icon
install -d /usr/share/icons/hicolor/scalable/apps
install -m 644 assets/logo.svg /usr/share/icons/hicolor/scalable/apps/proxiflare.svg
gtk-update-icon-cache /usr/share/icons/hicolor/ 2>/dev/null || true

info "Installation complete!"
echo ""
echo "  Start daemon:   sudo systemctl start proxiflare-daemon"
echo "  Enable at boot: sudo systemctl enable proxiflare-daemon"
echo "  Launch GUI:     proxiflare"
echo ""
echo "  Or from the app: Settings → Start at Boot"
```

- [ ] **Step 2: Create `scripts/uninstall.sh`**

```bash
#!/bin/bash
set -e

[[ $EUID -ne 0 ]] && { echo "Run as root: sudo $0"; exit 1; }

echo "Uninstalling ProxiFlare..."

# Stop service
systemctl stop proxiflare-daemon 2>/dev/null || true
systemctl disable proxiflare-daemon 2>/dev/null || true

# Remove binaries
rm -f /usr/local/bin/proxiflare-daemon
rm -f /usr/local/bin/proxiflare

# Remove systemd + polkit
rm -f /etc/systemd/system/proxiflare-daemon.service
rm -f /usr/share/polkit-1/actions/com.proxiflare.policy
systemctl daemon-reload

# Remove desktop entry + icons
rm -f /usr/share/applications/proxiflare.desktop
find /usr/share/icons -name "proxiflare*" -delete 2>/dev/null
gtk-update-icon-cache /usr/share/icons/hicolor/ 2>/dev/null || true

# Ask about data
read -p "Remove config and database? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  rm -rf /etc/proxiflare
  rm -rf /var/lib/proxiflare
  rm -rf /var/log/proxiflare
  echo "Data removed."
else
  echo "Data kept at /etc/proxiflare, /var/lib/proxiflare, /var/log/proxiflare"
fi

echo "ProxiFlare uninstalled."
```

- [ ] **Step 3: Make scripts executable and commit**

```bash
chmod +x scripts/install.sh scripts/uninstall.sh
git add scripts/
git commit -m "feat: installer and uninstaller scripts with systemd integration"
```

---

### Task 30: Generate PNG Icons from SVG

**Files:**
- Create: `assets/icon-16.png`
- Create: `assets/icon-32.png`
- Create: `assets/icon-128.png`
- Create: `assets/icon-256.png`
- Create: `assets/icon-512.png`

- [ ] **Step 1: Generate icons**

```bash
cd ~/projects/proxiflare
for size in 16 32 128 256 512; do
  rsvg-convert -w $size -h $size assets/logo.svg -o assets/icon-${size}.png
done
```

- [ ] **Step 2: Commit**

```bash
git add assets/icon-*.png
git commit -m "feat: PNG icons generated from logo SVG"
```

---

## Summary

| Phase | Tasks | Description |
|-------|-------|-------------|
| 1: Foundation | 1-6 | Build system, types, config, crypto, IPC, logger, rules |
| 2: Connectors | 7-10 | SOCKS, HTTP, SSH, chain routing |
| 3: Interception | 11-17 | DNS, SNI, TPROXY, cgroups, nftables, monitor, stats |
| 4: Tauri Shell | 18-20 | Project setup, IPC bridge, commands |
| 5: React GUI | 21-27 | Types, API, hooks, all 5 pages |
| 6: Installer | 28-30 | Systemd, polkit, install/uninstall, icons |

**Total: 30 tasks, ~150 steps**

Execution order is sequential within phases, but Phase 4-5 (GUI) can start once Phase 1 IPC is done (using mock daemon responses for development).
