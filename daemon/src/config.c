#include "config.h"
#include <string.h>
#include <stdio.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal helpers
 * ───────────────────────────────────────────────────────────────────────────── */

static int exec_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQLite error: %s\n", err ? err : "unknown");
        sqlite3_free(err);
        return PF_ERR_DB;
    }
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Schema
 * ───────────────────────────────────────────────────────────────────────────── */

static const char *SCHEMA_DDL =
    /* proxies */
    "CREATE TABLE IF NOT EXISTS proxies ("
    "  id             INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  name           TEXT    NOT NULL UNIQUE,"
    "  type           TEXT    NOT NULL CHECK(type IN ('socks4','socks5','http','ssh')),"
    "  host           TEXT    NOT NULL,"
    "  port           INTEGER NOT NULL,"
    "  username       BLOB,"
    "  password       BLOB,"
    "  ssh_key        BLOB,"
    "  enabled        INTEGER NOT NULL DEFAULT 1,"
    "  health         INTEGER NOT NULL DEFAULT 0,"
    "  latency_ms     INTEGER NOT NULL DEFAULT 0,"
    "  check_interval INTEGER NOT NULL DEFAULT 60,"
    "  created_at     INTEGER NOT NULL,"
    "  updated_at     INTEGER NOT NULL"
    ");"

    /* chains */
    "CREATE TABLE IF NOT EXISTS chains ("
    "  id         INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  name       TEXT    NOT NULL UNIQUE,"
    "  enabled    INTEGER NOT NULL DEFAULT 1,"
    "  created_at INTEGER NOT NULL"
    ");"

    /* chain_hops */
    "CREATE TABLE IF NOT EXISTS chain_hops ("
    "  id        INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  chain_id  INTEGER NOT NULL REFERENCES chains(id) ON DELETE CASCADE,"
    "  proxy_id  INTEGER NOT NULL REFERENCES proxies(id),"
    "  hop_order INTEGER NOT NULL,"
    "  UNIQUE(chain_id, hop_order)"
    ");"

    /* rules */
    "CREATE TABLE IF NOT EXISTS rules ("
    "  id           INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  name         TEXT    NOT NULL,"
    "  enabled      INTEGER NOT NULL DEFAULT 1,"
    "  priority     INTEGER NOT NULL DEFAULT 0,"
    "  match_app    TEXT,"
    "  match_domain TEXT,"
    "  match_ip     TEXT,"
    "  match_port   INTEGER,"
    "  action       TEXT    NOT NULL,"
    "  proxy_id     INTEGER REFERENCES proxies(id),"
    "  chain_id     INTEGER REFERENCES chains(id),"
    "  created_at   INTEGER NOT NULL,"
    "  updated_at   INTEGER NOT NULL"
    ");"

    /* config key-value */
    "CREATE TABLE IF NOT EXISTS config ("
    "  key   TEXT PRIMARY KEY,"
    "  value TEXT NOT NULL"
    ");"

    /* indexes */
    "CREATE INDEX IF NOT EXISTS idx_rules_priority ON rules(priority);"
    "CREATE INDEX IF NOT EXISTS idx_rules_enabled  ON rules(priority) WHERE enabled = 1;"
    "CREATE INDEX IF NOT EXISTS idx_chain_hops_chain ON chain_hops(chain_id, hop_order);";

/* ─────────────────────────────────────────────────────────────────────────────
 * Init / Close
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_config_init(pf_config_t *cfg, const char *db_path)
{
    if (!cfg || !db_path) return PF_ERR_DB;

    snprintf(cfg->db_path, PF_PATH_MAX, "%s", db_path);

    int rc = sqlite3_open(db_path, &cfg->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open DB %s: %s\n", db_path, sqlite3_errmsg(cfg->db));
        sqlite3_close(cfg->db);
        cfg->db = NULL;
        return PF_ERR_DB;
    }

    /* Performance / correctness settings */
    if (exec_sql(cfg->db, "PRAGMA journal_mode=WAL;")    != PF_OK) goto fail;
    if (exec_sql(cfg->db, "PRAGMA foreign_keys=ON;")     != PF_OK) goto fail;
    if (exec_sql(cfg->db, "PRAGMA synchronous=NORMAL;")  != PF_OK) goto fail;

    if (exec_sql(cfg->db, SCHEMA_DDL) != PF_OK) goto fail;

    return PF_OK;

fail:
    sqlite3_close(cfg->db);
    cfg->db = NULL;
    return PF_ERR_DB;
}

void pf_config_close(pf_config_t *cfg)
{
    if (cfg && cfg->db) {
        sqlite3_close(cfg->db);
        cfg->db = NULL;
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal: fill pf_proxy_t from a prepared statement row
 * cols: id, name, type, host, port, username, password, ssh_key,
 *       enabled, health, latency_ms, check_interval, created_at, updated_at
 * ───────────────────────────────────────────────────────────────────────────── */

static void row_to_proxy(sqlite3_stmt *st, pf_proxy_t *p)
{
    memset(p, 0, sizeof(*p));
    p->id = (uint32_t)sqlite3_column_int(st, 0);
    snprintf(p->name,     sizeof(p->name),     "%s", (const char *)sqlite3_column_text(st, 1));
    p->type    = pf_proxy_type_from_str((const char *)sqlite3_column_text(st, 2));
    snprintf(p->host,     sizeof(p->host),     "%s", (const char *)sqlite3_column_text(st, 3));
    p->port    = (uint16_t)sqlite3_column_int(st, 4);

    const char *uname = (const char *)sqlite3_column_text(st, 5);
    if (uname) snprintf(p->username, sizeof(p->username), "%s", uname);

    const char *pwd = (const char *)sqlite3_column_text(st, 6);
    if (pwd) snprintf(p->password, sizeof(p->password), "%s", pwd);

    const char *sshk = (const char *)sqlite3_column_text(st, 7);
    if (sshk) snprintf(p->ssh_key_path, sizeof(p->ssh_key_path), "%s", sshk);

    p->enabled    = sqlite3_column_int(st, 8);
    p->health     = (pf_health_t)sqlite3_column_int(st, 9);
    p->latency_ms = (uint32_t)sqlite3_column_int(st, 10);
    /* check_interval col 11 — not in struct, skip */
    p->last_check = (time_t)sqlite3_column_int64(st, 12);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Proxies CRUD
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_config_proxy_list(pf_config_t *cfg, pf_proxy_t *out, int max, int *count)
{
    if (!cfg || !cfg->db || !out || max <= 0 || !count) return PF_ERR_DB;
    *count = 0;

    const char *sql =
        "SELECT id,name,type,host,port,username,password,ssh_key,"
        "       enabled,health,latency_ms,check_interval,created_at,updated_at"
        " FROM proxies ORDER BY name;";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cfg->db, sql, -1, &st, NULL) != SQLITE_OK) return PF_ERR_DB;

    int rc = PF_OK;
    while (sqlite3_step(st) == SQLITE_ROW && *count < max) {
        row_to_proxy(st, &out[*count]);
        (*count)++;
    }
    sqlite3_finalize(st);
    return rc;
}

int pf_config_proxy_get(pf_config_t *cfg, int id, pf_proxy_t *out)
{
    if (!cfg || !cfg->db || !out) return PF_ERR_DB;

    const char *sql =
        "SELECT id,name,type,host,port,username,password,ssh_key,"
        "       enabled,health,latency_ms,check_interval,created_at,updated_at"
        " FROM proxies WHERE id=?;";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cfg->db, sql, -1, &st, NULL) != SQLITE_OK) return PF_ERR_DB;
    sqlite3_bind_int(st, 1, id);

    int rc = PF_ERR_DB;
    if (sqlite3_step(st) == SQLITE_ROW) {
        row_to_proxy(st, out);
        rc = PF_OK;
    }
    sqlite3_finalize(st);
    return rc;
}

int pf_config_proxy_add(pf_config_t *cfg, const pf_proxy_t *proxy)
{
    if (!cfg || !cfg->db || !proxy) return PF_ERR_DB;

    const char *sql =
        "INSERT INTO proxies"
        " (name,type,host,port,username,password,ssh_key,enabled,health,latency_ms,check_interval,created_at,updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,60,strftime('%s','now'),strftime('%s','now'));";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cfg->db, sql, -1, &st, NULL) != SQLITE_OK) return PF_ERR_DB;

    sqlite3_bind_text(st, 1, proxy->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, pf_proxy_type_str(proxy->type), -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, proxy->host, -1, SQLITE_STATIC);
    sqlite3_bind_int (st, 4, proxy->port);

    if (proxy->username[0])
        sqlite3_bind_text(st, 5, proxy->username, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 5);

    if (proxy->password[0])
        sqlite3_bind_text(st, 6, proxy->password, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 6);

    if (proxy->ssh_key_path[0])
        sqlite3_bind_text(st, 7, proxy->ssh_key_path, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 7);

    sqlite3_bind_int(st, 8, proxy->enabled);
    sqlite3_bind_int(st, 9, (int)proxy->health);
    sqlite3_bind_int(st, 10, (int)proxy->latency_ms);

    int rc = (sqlite3_step(st) == SQLITE_DONE) ? PF_OK : PF_ERR_DB;
    sqlite3_finalize(st);
    return rc;
}

int pf_config_proxy_update(pf_config_t *cfg, const pf_proxy_t *proxy)
{
    if (!cfg || !cfg->db || !proxy) return PF_ERR_DB;

    const char *sql =
        "UPDATE proxies SET"
        " name=?, type=?, host=?, port=?, username=?, password=?, ssh_key=?,"
        " enabled=?, health=?, latency_ms=?, updated_at=strftime('%s','now')"
        " WHERE id=?;";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cfg->db, sql, -1, &st, NULL) != SQLITE_OK) return PF_ERR_DB;

    sqlite3_bind_text(st, 1,  proxy->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2,  pf_proxy_type_str(proxy->type), -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 3,  proxy->host, -1, SQLITE_STATIC);
    sqlite3_bind_int (st, 4,  proxy->port);

    if (proxy->username[0])
        sqlite3_bind_text(st, 5, proxy->username, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 5);

    if (proxy->password[0])
        sqlite3_bind_text(st, 6, proxy->password, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 6);

    if (proxy->ssh_key_path[0])
        sqlite3_bind_text(st, 7, proxy->ssh_key_path, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 7);

    sqlite3_bind_int(st, 8,  proxy->enabled);
    sqlite3_bind_int(st, 9,  (int)proxy->health);
    sqlite3_bind_int(st, 10, (int)proxy->latency_ms);
    sqlite3_bind_int(st, 11, (int)proxy->id);

    int rc = (sqlite3_step(st) == SQLITE_DONE) ? PF_OK : PF_ERR_DB;
    sqlite3_finalize(st);
    return rc;
}

int pf_config_proxy_delete(pf_config_t *cfg, int id)
{
    if (!cfg || !cfg->db) return PF_ERR_DB;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cfg->db, "DELETE FROM proxies WHERE id=?;", -1, &st, NULL) != SQLITE_OK)
        return PF_ERR_DB;
    sqlite3_bind_int(st, 1, id);

    int rc = (sqlite3_step(st) == SQLITE_DONE) ? PF_OK : PF_ERR_DB;
    sqlite3_finalize(st);
    return rc;
}

int pf_config_proxy_update_health(pf_config_t *cfg, int id, pf_health_t health, int latency_ms)
{
    if (!cfg || !cfg->db) return PF_ERR_DB;

    const char *sql =
        "UPDATE proxies SET health=?, latency_ms=?, updated_at=strftime('%s','now') WHERE id=?;";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cfg->db, sql, -1, &st, NULL) != SQLITE_OK) return PF_ERR_DB;

    sqlite3_bind_int(st, 1, (int)health);
    sqlite3_bind_int(st, 2, latency_ms);
    sqlite3_bind_int(st, 3, id);

    int rc = (sqlite3_step(st) == SQLITE_DONE) ? PF_OK : PF_ERR_DB;
    sqlite3_finalize(st);
    return rc;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal: fill pf_rule_t from a prepared statement row
 * cols: id, name, enabled, priority, match_app, match_domain, match_ip,
 *       match_port, action, proxy_id, chain_id, created_at, updated_at
 * ───────────────────────────────────────────────────────────────────────────── */

static void row_to_rule(sqlite3_stmt *st, pf_rule_t *r)
{
    memset(r, 0, sizeof(*r));
    r->id       = (uint32_t)sqlite3_column_int(st, 0);
    snprintf(r->name, sizeof(r->name), "%s", (const char *)sqlite3_column_text(st, 1));
    r->enabled  = sqlite3_column_int(st, 2);
    r->priority = sqlite3_column_int(st, 3);

    const char *app = (const char *)sqlite3_column_text(st, 4);
    if (app) snprintf(r->app_path, sizeof(r->app_path), "%s", app);

    const char *dom = (const char *)sqlite3_column_text(st, 5);
    if (dom) snprintf(r->domain, sizeof(r->domain), "%s", dom);

    const char *ip = (const char *)sqlite3_column_text(st, 6);
    if (ip) snprintf(r->ip_cidr, sizeof(r->ip_cidr), "%s", ip);

    r->dst_port = (uint16_t)sqlite3_column_int(st, 7);
    r->action   = pf_action_from_str((const char *)sqlite3_column_text(st, 8));

    /* proxy_id / chain_id: NULL → 0 */
    if (sqlite3_column_type(st, 9) != SQLITE_NULL)
        r->proxy_id = (uint32_t)sqlite3_column_int(st, 9);
    if (sqlite3_column_type(st, 10) != SQLITE_NULL)
        r->chain_id = (uint32_t)sqlite3_column_int(st, 10);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Rules CRUD
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_config_rule_list(pf_config_t *cfg, pf_rule_t *out, int max, int *count)
{
    if (!cfg || !cfg->db || !out || max <= 0 || !count) return PF_ERR_DB;
    *count = 0;

    const char *sql =
        "SELECT id,name,enabled,priority,match_app,match_domain,match_ip,"
        "       match_port,action,proxy_id,chain_id,created_at,updated_at"
        " FROM rules ORDER BY priority ASC;";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cfg->db, sql, -1, &st, NULL) != SQLITE_OK) return PF_ERR_DB;

    while (sqlite3_step(st) == SQLITE_ROW && *count < max) {
        row_to_rule(st, &out[*count]);
        (*count)++;
    }
    sqlite3_finalize(st);
    return PF_OK;
}

int pf_config_rule_get(pf_config_t *cfg, int id, pf_rule_t *out)
{
    if (!cfg || !cfg->db || !out) return PF_ERR_DB;

    const char *sql =
        "SELECT id,name,enabled,priority,match_app,match_domain,match_ip,"
        "       match_port,action,proxy_id,chain_id,created_at,updated_at"
        " FROM rules WHERE id=?;";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cfg->db, sql, -1, &st, NULL) != SQLITE_OK) return PF_ERR_DB;
    sqlite3_bind_int(st, 1, id);

    int rc = PF_ERR_DB;
    if (sqlite3_step(st) == SQLITE_ROW) {
        row_to_rule(st, out);
        rc = PF_OK;
    }
    sqlite3_finalize(st);
    return rc;
}

int pf_config_rule_add(pf_config_t *cfg, const pf_rule_t *rule)
{
    if (!cfg || !cfg->db || !rule) return PF_ERR_DB;

    const char *sql =
        "INSERT INTO rules"
        " (name,enabled,priority,match_app,match_domain,match_ip,match_port,"
        "  action,proxy_id,chain_id,created_at,updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,strftime('%s','now'),strftime('%s','now'));";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cfg->db, sql, -1, &st, NULL) != SQLITE_OK) return PF_ERR_DB;

    sqlite3_bind_text(st, 1, rule->name,    -1, SQLITE_STATIC);
    sqlite3_bind_int (st, 2, rule->enabled);
    sqlite3_bind_int (st, 3, rule->priority);

    if (rule->app_path[0])
        sqlite3_bind_text(st, 4, rule->app_path, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 4);

    if (rule->domain[0])
        sqlite3_bind_text(st, 5, rule->domain, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 5);

    if (rule->ip_cidr[0])
        sqlite3_bind_text(st, 6, rule->ip_cidr, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 6);

    if (rule->dst_port)
        sqlite3_bind_int(st, 7, rule->dst_port);
    else
        sqlite3_bind_null(st, 7);

    sqlite3_bind_text(st, 8, pf_action_str(rule->action), -1, SQLITE_STATIC);

    if (rule->proxy_id)
        sqlite3_bind_int(st, 9, (int)rule->proxy_id);
    else
        sqlite3_bind_null(st, 9);

    if (rule->chain_id)
        sqlite3_bind_int(st, 10, (int)rule->chain_id);
    else
        sqlite3_bind_null(st, 10);

    int rc = (sqlite3_step(st) == SQLITE_DONE) ? PF_OK : PF_ERR_DB;
    sqlite3_finalize(st);
    return rc;
}

int pf_config_rule_update(pf_config_t *cfg, const pf_rule_t *rule)
{
    if (!cfg || !cfg->db || !rule) return PF_ERR_DB;

    const char *sql =
        "UPDATE rules SET"
        " name=?, enabled=?, priority=?, match_app=?, match_domain=?,"
        " match_ip=?, match_port=?, action=?, proxy_id=?, chain_id=?,"
        " updated_at=strftime('%s','now')"
        " WHERE id=?;";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cfg->db, sql, -1, &st, NULL) != SQLITE_OK) return PF_ERR_DB;

    sqlite3_bind_text(st, 1, rule->name, -1, SQLITE_STATIC);
    sqlite3_bind_int (st, 2, rule->enabled);
    sqlite3_bind_int (st, 3, rule->priority);

    if (rule->app_path[0])
        sqlite3_bind_text(st, 4, rule->app_path, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 4);

    if (rule->domain[0])
        sqlite3_bind_text(st, 5, rule->domain, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 5);

    if (rule->ip_cidr[0])
        sqlite3_bind_text(st, 6, rule->ip_cidr, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 6);

    if (rule->dst_port)
        sqlite3_bind_int(st, 7, rule->dst_port);
    else
        sqlite3_bind_null(st, 7);

    sqlite3_bind_text(st, 8, pf_action_str(rule->action), -1, SQLITE_STATIC);

    if (rule->proxy_id)
        sqlite3_bind_int(st, 9, (int)rule->proxy_id);
    else
        sqlite3_bind_null(st, 9);

    if (rule->chain_id)
        sqlite3_bind_int(st, 10, (int)rule->chain_id);
    else
        sqlite3_bind_null(st, 10);

    sqlite3_bind_int(st, 11, (int)rule->id);

    int rc = (sqlite3_step(st) == SQLITE_DONE) ? PF_OK : PF_ERR_DB;
    sqlite3_finalize(st);
    return rc;
}

int pf_config_rule_delete(pf_config_t *cfg, int id)
{
    if (!cfg || !cfg->db) return PF_ERR_DB;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cfg->db, "DELETE FROM rules WHERE id=?;", -1, &st, NULL) != SQLITE_OK)
        return PF_ERR_DB;
    sqlite3_bind_int(st, 1, id);

    int rc = (sqlite3_step(st) == SQLITE_DONE) ? PF_OK : PF_ERR_DB;
    sqlite3_finalize(st);
    return rc;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal: load hops for a chain into pf_chain_t
 * ───────────────────────────────────────────────────────────────────────────── */

static int load_chain_hops(pf_config_t *cfg, pf_chain_t *chain)
{
    const char *sql =
        "SELECT proxy_id FROM chain_hops WHERE chain_id=? ORDER BY hop_order ASC;";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cfg->db, sql, -1, &st, NULL) != SQLITE_OK) return PF_ERR_DB;
    sqlite3_bind_int(st, 1, (int)chain->id);

    chain->hop_count = 0;
    while (sqlite3_step(st) == SQLITE_ROW && chain->hop_count < PF_MAX_HOPS) {
        chain->hops[chain->hop_count++] = (uint32_t)sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Chains CRUD
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_config_chain_list(pf_config_t *cfg, pf_chain_t *out, int max, int *count)
{
    if (!cfg || !cfg->db || !out || max <= 0 || !count) return PF_ERR_DB;
    *count = 0;

    const char *sql = "SELECT id,name,enabled FROM chains ORDER BY name;";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cfg->db, sql, -1, &st, NULL) != SQLITE_OK) return PF_ERR_DB;

    while (sqlite3_step(st) == SQLITE_ROW && *count < max) {
        pf_chain_t *c = &out[*count];
        memset(c, 0, sizeof(*c));
        c->id      = (uint32_t)sqlite3_column_int(st, 0);
        snprintf(c->name, sizeof(c->name), "%s", (const char *)sqlite3_column_text(st, 1));
        c->enabled = sqlite3_column_int(st, 2);
        (*count)++;
    }
    sqlite3_finalize(st);

    /* load hops for each chain */
    for (int i = 0; i < *count; i++) {
        if (load_chain_hops(cfg, &out[i]) != PF_OK) return PF_ERR_DB;
    }
    return PF_OK;
}

int pf_config_chain_get(pf_config_t *cfg, int id, pf_chain_t *out)
{
    if (!cfg || !cfg->db || !out) return PF_ERR_DB;

    const char *sql = "SELECT id,name,enabled FROM chains WHERE id=?;";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cfg->db, sql, -1, &st, NULL) != SQLITE_OK) return PF_ERR_DB;
    sqlite3_bind_int(st, 1, id);

    int rc = PF_ERR_DB;
    if (sqlite3_step(st) == SQLITE_ROW) {
        memset(out, 0, sizeof(*out));
        out->id      = (uint32_t)sqlite3_column_int(st, 0);
        snprintf(out->name, sizeof(out->name), "%s", (const char *)sqlite3_column_text(st, 1));
        out->enabled = sqlite3_column_int(st, 2);
        rc = PF_OK;
    }
    sqlite3_finalize(st);

    if (rc == PF_OK) rc = load_chain_hops(cfg, out);
    return rc;
}

int pf_config_chain_add(pf_config_t *cfg, const pf_chain_t *chain)
{
    if (!cfg || !cfg->db || !chain) return PF_ERR_DB;

    /* Insert chain row */
    const char *ins_chain =
        "INSERT INTO chains (name,enabled,created_at) VALUES (?,?,strftime('%s','now'));";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cfg->db, ins_chain, -1, &st, NULL) != SQLITE_OK) return PF_ERR_DB;
    sqlite3_bind_text(st, 1, chain->name, -1, SQLITE_STATIC);
    sqlite3_bind_int (st, 2, chain->enabled);

    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return PF_ERR_DB;
    }
    sqlite3_finalize(st);

    sqlite3_int64 chain_id = sqlite3_last_insert_rowid(cfg->db);

    /* Insert hops */
    const char *ins_hop =
        "INSERT INTO chain_hops (chain_id,proxy_id,hop_order) VALUES (?,?,?);";

    for (int i = 0; i < chain->hop_count && i < PF_MAX_HOPS; i++) {
        if (sqlite3_prepare_v2(cfg->db, ins_hop, -1, &st, NULL) != SQLITE_OK) return PF_ERR_DB;
        sqlite3_bind_int64(st, 1, chain_id);
        sqlite3_bind_int  (st, 2, (int)chain->hops[i]);
        sqlite3_bind_int  (st, 3, i);
        int step_rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (step_rc != SQLITE_DONE) return PF_ERR_DB;
    }
    return PF_OK;
}

int pf_config_chain_update(pf_config_t *cfg, const pf_chain_t *chain)
{
    if (!cfg || !cfg->db || !chain) return PF_ERR_DB;

    /* Update chain row */
    const char *upd =
        "UPDATE chains SET name=?, enabled=? WHERE id=?;";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cfg->db, upd, -1, &st, NULL) != SQLITE_OK) return PF_ERR_DB;
    sqlite3_bind_text(st, 1, chain->name, -1, SQLITE_STATIC);
    sqlite3_bind_int (st, 2, chain->enabled);
    sqlite3_bind_int (st, 3, (int)chain->id);

    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return PF_ERR_DB;
    }
    sqlite3_finalize(st);

    /* Rebuild hops: delete + reinsert */
    if (sqlite3_prepare_v2(cfg->db, "DELETE FROM chain_hops WHERE chain_id=?;", -1, &st, NULL) != SQLITE_OK)
        return PF_ERR_DB;
    sqlite3_bind_int(st, 1, (int)chain->id);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return PF_ERR_DB;
    }
    sqlite3_finalize(st);

    const char *ins_hop =
        "INSERT INTO chain_hops (chain_id,proxy_id,hop_order) VALUES (?,?,?);";

    for (int i = 0; i < chain->hop_count && i < PF_MAX_HOPS; i++) {
        if (sqlite3_prepare_v2(cfg->db, ins_hop, -1, &st, NULL) != SQLITE_OK) return PF_ERR_DB;
        sqlite3_bind_int(st, 1, (int)chain->id);
        sqlite3_bind_int(st, 2, (int)chain->hops[i]);
        sqlite3_bind_int(st, 3, i);
        int step_rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (step_rc != SQLITE_DONE) return PF_ERR_DB;
    }
    return PF_OK;
}

int pf_config_chain_delete(pf_config_t *cfg, int id)
{
    if (!cfg || !cfg->db) return PF_ERR_DB;

    /* chain_hops cascade-delete via FK */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cfg->db, "DELETE FROM chains WHERE id=?;", -1, &st, NULL) != SQLITE_OK)
        return PF_ERR_DB;
    sqlite3_bind_int(st, 1, id);

    int rc = (sqlite3_step(st) == SQLITE_DONE) ? PF_OK : PF_ERR_DB;
    sqlite3_finalize(st);
    return rc;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Key-value config
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_config_get(pf_config_t *cfg, const char *key, char *value, int max_len)
{
    if (!cfg || !cfg->db || !key || !value || max_len <= 0) return PF_ERR_DB;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cfg->db, "SELECT value FROM config WHERE key=?;", -1, &st, NULL) != SQLITE_OK)
        return PF_ERR_DB;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_STATIC);

    int rc = PF_ERR_DB;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *v = (const char *)sqlite3_column_text(st, 0);
        if (v) {
            snprintf(value, max_len, "%s", v);
            rc = PF_OK;
        }
    }
    sqlite3_finalize(st);
    return rc;
}

int pf_config_set(pf_config_t *cfg, const char *key, const char *value)
{
    if (!cfg || !cfg->db || !key || !value) return PF_ERR_DB;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cfg->db,
            "INSERT OR REPLACE INTO config (key,value) VALUES (?,?);",
            -1, &st, NULL) != SQLITE_OK)
        return PF_ERR_DB;

    sqlite3_bind_text(st, 1, key,   -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, value, -1, SQLITE_STATIC);

    int rc = (sqlite3_step(st) == SQLITE_DONE) ? PF_OK : PF_ERR_DB;
    sqlite3_finalize(st);
    return rc;
}
