#include "dns.h"
#include "logger.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/netfilter.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal helpers
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * Parse the QNAME at `ptr` (inside the DNS payload bounded by `end`).
 * Writes a dot-separated domain string to `out` (max `outsz` bytes).
 * Returns a pointer past the terminating 0x00 label, or NULL on error.
 */
static const uint8_t *dns_parse_qname(const uint8_t *ptr, const uint8_t *end,
                                      char *out, size_t outsz)
{
    size_t written = 0;
    out[0] = '\0';

    while (ptr < end) {
        uint8_t len = *ptr++;

        /* Compression pointer (top two bits set) — not expected in queries,
         * but guard against malformed packets. */
        if ((len & 0xC0) == 0xC0) {
            if (ptr >= end) return NULL;
            ptr++;              /* skip second byte of pointer */
            break;
        }

        if (len == 0)           /* root label: QNAME finished */
            break;

        if (ptr + len > end)    /* label runs past packet end */
            return NULL;

        /* Append dot separator between labels */
        if (written > 0) {
            if (written + 1 >= outsz) return NULL;
            out[written++] = '.';
        }

        if (written + len >= outsz) return NULL;
        memcpy(out + written, ptr, len);
        written += len;
        ptr     += len;
    }

    out[written] = '\0';
    return ptr;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Cache helpers
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * Find a cache slot for `domain`:
 *   1. An existing entry for this domain (to update resolved_ip or refresh).
 *   2. An empty / expired slot.
 * Returns index or -1 if the cache is completely full of unexpired entries.
 */
static int cache_find_slot(pf_dns_t *dns, const char *domain)
{
    time_t now     = time(NULL);
    int    reuse   = -1;   /* first free/expired slot */

    for (int i = 0; i < PF_DNS_CACHE_SIZE; i++) {
        pf_dns_entry_t *e = &dns->cache[i];

        if (!e->used || e->expires <= now) {
            if (reuse < 0) reuse = i;
            continue;
        }

        /* Existing live entry for the same domain */
        if (strcasecmp(e->domain, domain) == 0)
            return i;
    }

    return reuse;   /* -1 only if every slot is live */
}

/* ─────────────────────────────────────────────────────────────────────────────
 * NFQUEUE callback
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * Invoked by nfq_handle_packet() for every queued DNS packet.
 * We inspect both queries (QR=0) and responses (QR=1).
 *
 * On QUERY  → record which domain is being looked up so we can rule-match it.
 * On RESPONSE → update the cached entry with the resolved A record IP(s).
 *
 * All packets receive NF_ACCEPT so DNS is never blocked.
 */
static int dns_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                        struct nfq_data *nfa, void *data)
{
    (void)nfmsg;    /* unused */

    pf_dns_t *dns = (pf_dns_t *)data;

    /* ── Packet id ─────────────────────────────────────────────────────────── */
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t pkt_id = ph ? ntohl(ph->packet_id) : 0;

    /* ── Raw packet bytes ──────────────────────────────────────────────────── */
    unsigned char *payload  = NULL;
    int            pkt_len  = nfq_get_payload(nfa, &payload);

    if (pkt_len < 0 || !payload)
        goto accept;

    /* ── IP header ──────────────────────────────────────────────────────────── */
    if (pkt_len < (int)sizeof(struct iphdr))
        goto accept;

    struct iphdr *iph = (struct iphdr *)payload;
    int ip_hlen       = iph->ihl * 4;

    if (ip_hlen < (int)sizeof(struct iphdr) || pkt_len < ip_hlen)
        goto accept;

    /* We only handle UDP */
    if (iph->protocol != IPPROTO_UDP)
        goto accept;

    /* ── UDP header ─────────────────────────────────────────────────────────── */
    if (pkt_len < ip_hlen + (int)sizeof(struct udphdr))
        goto accept;

    /* DNS data starts 8 bytes into UDP (past src/dst port + len + checksum) */
    const uint8_t *dns_data = payload + ip_hlen + 8;
    int            dns_len  = pkt_len - ip_hlen - 8;

    if (dns_len < 12)           /* DNS header is 12 bytes minimum */
        goto accept;

    /* ── DNS header fields ──────────────────────────────────────────────────── */
    /*
     * Byte 2 of DNS header (flags high byte):
     *   bit 7 → QR (0=query, 1=response)
     */
    uint8_t  flags_hi = dns_data[2];
    bool     is_response = (flags_hi & 0x80) != 0;

    uint16_t tx_id   = (uint16_t)((dns_data[0] << 8) | dns_data[1]);
    uint16_t qdcount = (uint16_t)((dns_data[4] << 8) | dns_data[5]);
    uint16_t ancount = (uint16_t)((dns_data[6] << 8) | dns_data[7]);

    (void)tx_id;    /* used implicitly — same packet carries QNAME in responses */

    const uint8_t *ptr = dns_data + 12;   /* skip fixed 12-byte header */
    const uint8_t *end = dns_data + dns_len;

    /* ── Parse QNAME (present in both queries and responses) ────────────────── */
    char domain[PF_DOMAIN_MAX] = {0};

    if (qdcount > 0) {
        const uint8_t *after = dns_parse_qname(ptr, end, domain, sizeof(domain));
        if (after)
            ptr = after + 4;    /* skip QTYPE + QCLASS */
    }

    if (domain[0] == '\0')
        goto accept;

    /* ── QUERY path: cache the domain (no IP yet) and rule-match ────────────── */
    if (!is_response) {
        const pf_rule_t *rule = pf_rules_match(dns->ruleset, NULL, domain, NULL, 0);

        int         rule_id  = rule ? (int)rule->id    : -1;
        pf_action_t action   = rule ? rule->action     : PF_ACTION_DIRECT;
        int         proxy_id = rule ? (int)rule->proxy_id : -1;
        int         chain_id = rule ? (int)rule->chain_id : -1;

        /* Store the domain in the cache (IP field empty for now) */
        pf_dns_cache_add(dns, domain, "", rule_id, action, proxy_id, chain_id);
        goto accept;
    }

    /* ── RESPONSE path: extract A records and update cache entries ──────────── */
    if (ancount == 0)
        goto accept;

    for (uint16_t i = 0; i < ancount && ptr < end; i++) {
        /* Skip owner name (may be compressed). Bound every pointer move so
         * a crafted response can't walk past `end`. */
        bool broken = false;
        while (ptr < end) {
            uint8_t b = *ptr;
            if ((b & 0xC0) == 0xC0) {
                if (ptr + 2 > end) { broken = true; break; }
                ptr += 2;
                break;
            }
            if (b == 0) {
                ptr++;
                break;
            }
            if (ptr + 1 + b > end) { broken = true; break; }
            ptr += b + 1;
        }
        if (broken) break;

        /* Need TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes */
        if (ptr + 10 > end)
            break;

        uint16_t rtype    = (uint16_t)((ptr[0] << 8) | ptr[1]);
        uint32_t rttl     = ((uint32_t)ptr[4] << 24) | ((uint32_t)ptr[5] << 16) |
                            ((uint32_t)ptr[6] << 8)  |  (uint32_t)ptr[7];
        uint16_t rdlength = (uint16_t)((ptr[8] << 8) | ptr[9]);
        ptr += 10;

        if (ptr + rdlength > end)
            break;

        /* A record: type 1, 4 bytes */
        if (rtype == 1 && rdlength == 4) {
            char ip_str[INET_ADDRSTRLEN];
            struct in_addr addr;
            memcpy(&addr.s_addr, ptr, 4);
            if (inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str))) {
                /*
                 * Find the cache entry for this domain and fill in the IP.
                 * If not found (edge case: response without prior query seen),
                 * do a fresh match and insert a full entry.
                 */
                int slot = cache_find_slot(dns, domain);
                if (slot >= 0) {
                    pf_dns_entry_t *e = &dns->cache[slot];
                    if (e->used && strcasecmp(e->domain, domain) == 0) {
                        /* Update IP on existing entry. Honor the TTL the
                         * authoritative server returned (capped at PF_DNS_TTL
                         * so we never cache longer than intended). */
                        strncpy(e->resolved_ip, ip_str, sizeof(e->resolved_ip) - 1);
                        uint32_t ttl = rttl < (uint32_t)PF_DNS_TTL ? rttl : (uint32_t)PF_DNS_TTL;
                        if (ttl < 30) ttl = 30;  /* floor: avoid thundering herd on TTL=0 */
                        e->expires = time(NULL) + (time_t)ttl;
                    } else {
                        /* Insert fresh entry with rule match */
                        const pf_rule_t *rule = pf_rules_match(
                            dns->ruleset, NULL, domain, NULL, 0);
                        pf_dns_cache_add(dns, domain, ip_str,
                                         rule ? (int)rule->id         : -1,
                                         rule ? rule->action          : PF_ACTION_DIRECT,
                                         rule ? (int)rule->proxy_id   : -1,
                                         rule ? (int)rule->chain_id   : -1);
                    }
                }
            }
        }
        /* AAAA record: type 28, 16 bytes */
        else if (rtype == 28 && rdlength == 16) {
            char ip_str[INET6_ADDRSTRLEN];
            struct in6_addr addr6;
            memcpy(&addr6, ptr, 16);
            if (inet_ntop(AF_INET6, &addr6, ip_str, sizeof(ip_str))) {
                int slot = cache_find_slot(dns, domain);
                if (slot >= 0) {
                    pf_dns_entry_t *e = &dns->cache[slot];
                    if (e->used && strcasecmp(e->domain, domain) == 0) {
                        strncpy(e->resolved_ip, ip_str, sizeof(e->resolved_ip) - 1);
                        e->expires = time(NULL) + PF_DNS_TTL;
                    } else {
                        const pf_rule_t *rule = pf_rules_match(
                            dns->ruleset, NULL, domain, NULL, 0);
                        pf_dns_cache_add(dns, domain, ip_str,
                                         rule ? (int)rule->id         : -1,
                                         rule ? rule->action          : PF_ACTION_DIRECT,
                                         rule ? (int)rule->proxy_id   : -1,
                                         rule ? (int)rule->chain_id   : -1);
                    }
                }
            }
        }

        ptr += rdlength;
    }

accept:
    nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, NULL);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_dns_init
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_dns_init(pf_dns_t *dns, pf_ruleset_t *ruleset)
{
    memset(dns, 0, sizeof(*dns));
    dns->ruleset = ruleset;
    dns->fd      = -1;

    /* Open netfilter queue handle */
    dns->nfq = nfq_open();
    if (!dns->nfq) {
        pf_log_error("dns: nfq_open() failed");
        return PF_ERR_NET;
    }

    /* Unbind any existing handler for AF_INET (ignore error — may not be set) */
    nfq_unbind_pf(dns->nfq, AF_INET);

    /* Bind AF_INET */
    if (nfq_bind_pf(dns->nfq, AF_INET) < 0) {
        pf_log_error("dns: nfq_bind_pf(AF_INET) failed");
        nfq_close(dns->nfq);
        dns->nfq = NULL;
        return PF_ERR_NET;
    }

    /* Create queue 0 with our callback */
    dns->queue = nfq_create_queue(dns->nfq, 0, &dns_callback, dns);
    if (!dns->queue) {
        pf_log_error("dns: nfq_create_queue() failed");
        nfq_close(dns->nfq);
        dns->nfq = NULL;
        return PF_ERR_NET;
    }

    /* Copy full packet into userspace (up to 0xffff bytes) */
    if (nfq_set_mode(dns->queue, NFQNL_COPY_PACKET, 0xffff) < 0) {
        pf_log_error("dns: nfq_set_mode() failed");
        nfq_destroy_queue(dns->queue);
        nfq_close(dns->nfq);
        dns->queue = NULL;
        dns->nfq   = NULL;
        return PF_ERR_NET;
    }

    dns->fd = nfq_fd(dns->nfq);
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_dns_close
 * ───────────────────────────────────────────────────────────────────────────── */

void pf_dns_close(pf_dns_t *dns)
{
    if (!dns) return;

    if (dns->queue) {
        nfq_destroy_queue(dns->queue);
        dns->queue = NULL;
    }
    if (dns->nfq) {
        nfq_close(dns->nfq);
        dns->nfq = NULL;
    }
    dns->fd = -1;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_dns_get_fd
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_dns_get_fd(pf_dns_t *dns)
{
    return dns ? dns->fd : -1;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_dns_process
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_dns_process(pf_dns_t *dns)
{
    char buf[4096] __attribute__((aligned(4)));
    ssize_t len = recv(dns->fd, buf, sizeof(buf), 0);

    if (len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return PF_OK;
        pf_log_error("dns: recv() failed: %s", strerror(errno));
        return PF_ERR_NET;
    }

    if (nfq_handle_packet(dns->nfq, buf, (int)len) < 0) {
        pf_log_error("dns: nfq_handle_packet() failed");
        return PF_ERR_NET;
    }

    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_dns_lookup
 * ───────────────────────────────────────────────────────────────────────────── */

const pf_dns_entry_t *pf_dns_lookup(pf_dns_t *dns, const char *ip)
{
    if (!dns || !ip) return NULL;

    time_t now = time(NULL);

    for (int i = 0; i < PF_DNS_CACHE_SIZE; i++) {
        pf_dns_entry_t *e = &dns->cache[i];
        if (!e->used || e->expires <= now)
            continue;
        if (e->resolved_ip[0] != '\0' && strcmp(e->resolved_ip, ip) == 0)
            return e;
    }

    return NULL;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_dns_cache_add
 * ───────────────────────────────────────────────────────────────────────────── */

void pf_dns_cache_add(pf_dns_t *dns, const char *domain, const char *ip,
                      int rule_id, pf_action_t action, int proxy_id, int chain_id)
{
    if (!dns || !domain) return;

    int slot = cache_find_slot(dns, domain);
    if (slot < 0) {
        pf_log_warn("dns: cache full, dropping entry for %s", domain);
        return;
    }

    pf_dns_entry_t *e = &dns->cache[slot];
    memset(e, 0, sizeof(*e));

    strncpy(e->domain,      domain, sizeof(e->domain)      - 1);
    strncpy(e->resolved_ip, ip ? ip : "", sizeof(e->resolved_ip) - 1);
    e->rule_id  = rule_id;
    e->action   = action;
    e->proxy_id = proxy_id;
    e->chain_id = chain_id;
    e->expires  = time(NULL) + PF_DNS_TTL;
    e->used     = true;
}
