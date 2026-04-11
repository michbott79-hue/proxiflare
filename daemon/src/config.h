#ifndef PF_CONFIG_H
#define PF_CONFIG_H

#include "proxiflare.h"
#include <sqlite3.h>

typedef struct {
    sqlite3 *db;
    char db_path[PF_PATH_MAX];
} pf_config_t;

/* Init/close */
int  pf_config_init(pf_config_t *cfg, const char *db_path);
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

/* Last inserted row ID (wraps sqlite3_last_insert_rowid) */
int pf_config_last_id(pf_config_t *cfg);

/* Reference counting — returns count of references, or -1 on error */
int pf_config_proxy_ref_count(pf_config_t *cfg, int proxy_id);
int pf_config_chain_ref_count(pf_config_t *cfg, int chain_id);

#endif /* PF_CONFIG_H */
