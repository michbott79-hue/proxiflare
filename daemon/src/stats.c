#include "stats.h"
#include "logger.h"

#include <string.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_stats_init
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_stats_init(pf_stats_t *stats)
{
    if (!stats) return PF_ERR;

    memset(stats, 0, sizeof(*stats));
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal: find or create entry for proxy_id
 * ───────────────────────────────────────────────────────────────────────────── */

static pf_stats_entry_t *find_or_create(pf_stats_t *stats, int proxy_id)
{
    /* Search existing */
    for (int i = 0; i < stats->count; i++) {
        if (stats->entries[i].proxy_id == proxy_id)
            return &stats->entries[i];
    }

    /* Create new if there is space */
    if (stats->count >= PF_MAX_PROXIES) {
        pf_log_warn("stats: entry table full, cannot track proxy_id=%d", proxy_id);
        return NULL;
    }

    pf_stats_entry_t *e = &stats->entries[stats->count++];
    memset(e, 0, sizeof(*e));
    e->proxy_id = proxy_id;
    return e;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_stats_update
 *
 * Increments byte counters, connection count, and accumulates latency.
 * latency_ms == 0 means no latency sample this call (bytes-only update).
 * ───────────────────────────────────────────────────────────────────────────── */

void pf_stats_update(pf_stats_t *stats, int proxy_id,
                     uint64_t bytes_tx, uint64_t bytes_rx, int latency_ms)
{
    if (!stats) return;

    pf_stats_entry_t *e = find_or_create(stats, proxy_id);
    if (!e) return;

    e->bytes_tx    += bytes_tx;
    e->bytes_rx    += bytes_rx;
    e->connections += 1;

    if (latency_ms > 0) {
        e->total_latency_ms += latency_ms;
        e->latency_count    += 1;
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_stats_get_json
 *
 * Returns a cJSON array of per-proxy stats objects.  The caller owns the
 * returned object and must call cJSON_Delete() when done.
 * ───────────────────────────────────────────────────────────────────────────── */

cJSON *pf_stats_get_json(pf_stats_t *stats)
{
    cJSON *arr = cJSON_CreateArray();
    if (!arr) return NULL;

    if (!stats) return arr;

    for (int i = 0; i < stats->count; i++) {
        pf_stats_entry_t *e = &stats->entries[i];

        cJSON *obj = cJSON_CreateObject();
        if (!obj) continue;

        cJSON_AddNumberToObject(obj, "proxy_id",    e->proxy_id);
        cJSON_AddNumberToObject(obj, "bytes_tx",    (double)e->bytes_tx);
        cJSON_AddNumberToObject(obj, "bytes_rx",    (double)e->bytes_rx);
        cJSON_AddNumberToObject(obj, "connections", e->connections);

        int avg_latency = 0;
        if (e->latency_count > 0)
            avg_latency = e->total_latency_ms / e->latency_count;
        cJSON_AddNumberToObject(obj, "avg_latency_ms", avg_latency);

        cJSON_AddItemToArray(arr, obj);
    }

    return arr;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_stats_reset
 *
 * Zeroes all counters while preserving the proxy_id slots.
 * ───────────────────────────────────────────────────────────────────────────── */

void pf_stats_reset(pf_stats_t *stats)
{
    if (!stats) return;

    for (int i = 0; i < stats->count; i++) {
        int proxy_id = stats->entries[i].proxy_id;
        memset(&stats->entries[i], 0, sizeof(stats->entries[i]));
        stats->entries[i].proxy_id = proxy_id;
    }
}
