#ifndef PF_DNS_H
#define PF_DNS_H

#include "proxiflare.h"
#include "rules.h"
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdbool.h>
#include <time.h>

#define PF_DNS_CACHE_SIZE 4096
#define PF_DNS_TTL        300   /* 5 minutes */

/* Cached DNS entry — maps resolved IP to domain + matched rule */
typedef struct {
    char        domain[PF_DOMAIN_MAX];
    char        resolved_ip[46];  /* IPv4 or IPv6 string */
    int         rule_id;          /* matched rule id, -1 if DIRECT */
    pf_action_t action;
    int         proxy_id;
    int         chain_id;
    time_t      expires;
    bool        used;
} pf_dns_entry_t;

typedef struct {
    struct nfq_handle   *nfq;
    struct nfq_q_handle *queue;
    int                  fd;
    pf_dns_entry_t       cache[PF_DNS_CACHE_SIZE];
    pf_ruleset_t        *ruleset;
} pf_dns_t;

int  pf_dns_init(pf_dns_t *dns, pf_ruleset_t *ruleset);
void pf_dns_close(pf_dns_t *dns);
int  pf_dns_get_fd(pf_dns_t *dns);
int  pf_dns_process(pf_dns_t *dns);

/* Lookup: given a destination IP, find the cached domain + routing info */
const pf_dns_entry_t *pf_dns_lookup(pf_dns_t *dns, const char *ip);

/* Manual cache add (for testing or direct IP rules) */
void pf_dns_cache_add(pf_dns_t *dns, const char *domain, const char *ip,
                      int rule_id, pf_action_t action, int proxy_id, int chain_id);

#endif /* PF_DNS_H */
