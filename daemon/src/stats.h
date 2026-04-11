#ifndef PF_STATS_H
#define PF_STATS_H

#include "proxiflare.h"
#include <cJSON.h>

typedef struct {
    int      proxy_id;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    int      connections;
    int      total_latency_ms;
    int      latency_count;
} pf_stats_entry_t;

typedef struct {
    pf_stats_entry_t entries[PF_MAX_PROXIES];
    int              count;
} pf_stats_t;

int    pf_stats_init(pf_stats_t *stats);
void   pf_stats_update(pf_stats_t *stats, int proxy_id,
                       uint64_t bytes_tx, uint64_t bytes_rx, int latency_ms);
cJSON *pf_stats_get_json(pf_stats_t *stats);
void   pf_stats_reset(pf_stats_t *stats);

#endif /* PF_STATS_H */
