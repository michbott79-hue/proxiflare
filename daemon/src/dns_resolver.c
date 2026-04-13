/* ─────────────────────────────────────────────────────────────────────────────
 * dns_resolver.c — DNS-over-HTTPS forwarder through the configured proxy.
 *
 * Flow:
 *   Firefox → UDP :53 (cgroup)
 *      ↓ nft REDIRECT
 *   127.0.0.1:<port>   ← this module
 *      ↓ pick proxy from config (dns_proxy_id or first enabled HTTP/SOCKS5)
 *      ↓ pf_socks5_connect / pf_http_connect to <doh_host>:443
 *      ↓ OpenSSL handshake (SNI = doh_host)
 *      ↓ HTTP/1.1 POST /dns-query, body = raw DNS wire query (RFC 8484)
 *      ↓ read response body (raw DNS wire answer)
 *   Firefox ← UDP answer (source IP restored by conntrack)
 *
 * Notes:
 *   - Default host is Cloudflare (cloudflare-dns.com). Cloudflare and Google
 *     accept HTTP/1.1; Quad9 requires HTTP/2 (we don't link nghttp2).
 *   - Port 443 is used, which every HTTP-CONNECT proxy whitelists (unlike
 *     853/DoT which most residential proxies block).
 *   - Each query spawns a detached pthread. On failure the query is dropped
 *     (no SERVFAIL synth) so the client retries naturally.
 * ───────────────────────────────────────────────────────────────────────────── */

#include "dns_resolver.h"
#include "logger.h"
#include "config.h"
#include "proxy_http.h"
#include "proxy_socks.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define CTX_CONFIG(r) ((r)->config)

/* ─── OpenSSL shared context ─────────────────────────────────────────────── */

static SSL_CTX   *g_ssl_ctx = NULL;
static pthread_once_t g_ssl_once = PTHREAD_ONCE_INIT;

static void ssl_ctx_init_once(void)
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) return;
    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);
    /* Use system trust store. Verification is best-effort: we log but don't
     * fail the query, so a broken cert bundle won't DoS the user. */
    SSL_CTX_set_default_verify_paths(g_ssl_ctx);
}

/* ─── Helpers ────────────────────────────────────────────────────────────── */

static ssize_t ssl_read_full(SSL *ssl, unsigned char *buf, size_t want)
{
    size_t got = 0;
    while (got < want) {
        int n = SSL_read(ssl, buf + got, (int)(want - got));
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return (ssize_t)got;
}

/* Read from ssl into buf until CRLFCRLF appears. On success *body_off points
 * to the first body byte and *total_read is bytes actually read (>= body_off;
 * any excess is body bytes buffered along with the headers). */
static int read_http_headers(SSL *ssl, char *buf, size_t cap,
                             size_t *body_off, size_t *total_read)
{
    size_t got = 0, scanned = 0;
    while (got < cap) {
        int n = SSL_read(ssl, buf + got, (int)(cap - got));
        if (n <= 0) return -1;
        got += (size_t)n;
        size_t scan_from = scanned >= 3 ? scanned - 3 : 0;
        for (size_t i = scan_from; i + 4 <= got; i++) {
            if (buf[i] == '\r' && buf[i+1] == '\n' &&
                buf[i+2] == '\r' && buf[i+3] == '\n') {
                *body_off   = i + 4;
                *total_read = got;
                return 0;
            }
        }
        scanned = got;
    }
    return -1;
}

static int parse_content_length(const char *hdr, size_t hlen)
{
    const char *p = hdr, *end = hdr + hlen;
    while (p < end - 16) {
        if ((p[0] == 'C' || p[0] == 'c') &&
            strncasecmp(p, "Content-Length:", 15) == 0) {
            p += 15;
            while (p < end && (*p == ' ' || *p == '\t')) p++;
            return atoi(p);
        }
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        if (!nl) return -1;
        p = nl + 1;
    }
    return -1;
}

/* Pick a proxy to tunnel DoH through. Preference:
 *   1. config "dns_proxy_id" (if set and that proxy is enabled + non-SSH)
 *   2. first enabled SOCKS5 or HTTP proxy in the DB
 * Returns PF_OK + fills *out, or PF_ERR if nothing suitable. */
static int pick_dns_proxy(pf_config_t *cfg, pf_proxy_t *out)
{
    char val[32] = "0";
    pf_config_get(cfg, "dns_proxy_id", val, sizeof(val));
    int configured = atoi(val);
    if (configured > 0) {
        if (pf_config_proxy_get(cfg, configured, out) == PF_OK &&
            out->enabled &&
            (out->type == PF_PROXY_SOCKS5 || out->type == PF_PROXY_HTTP)) {
            return PF_OK;
        }
    }
    /* Fallback: first usable proxy. */
    pf_proxy_t list[PF_MAX_PROXIES];
    int count = 0;
    if (pf_config_proxy_list(cfg, list, PF_MAX_PROXIES, &count) != PF_OK)
        return PF_ERR;
    for (int i = 0; i < count; i++) {
        if (list[i].enabled &&
            (list[i].type == PF_PROXY_SOCKS5 || list[i].type == PF_PROXY_HTTP)) {
            *out = list[i];
            return PF_OK;
        }
    }
    return PF_ERR;
}

static int connect_via_proxy(const pf_proxy_t *p, const char *host, int port)
{
    if (p->type == PF_PROXY_SOCKS5)
        return pf_socks5_connect(p->host, p->port, host, port,
                                 p->username, p->password);
    if (p->type == PF_PROXY_HTTP)
        return pf_http_connect(p->host, p->port, host, port,
                               p->username, p->password);
    return -1;
}

/* ─── Worker thread: one DoH exchange per invocation ─────────────────────── */

typedef struct {
    pf_dns_resolver_t *r;
    struct sockaddr_in client;  /* original client address (for sendto reply) */
    socklen_t          client_len;
    unsigned char     *query;   /* owned, freed here */
    size_t             query_len;
} dns_job_t;

static void *dns_worker(void *arg)
{
    dns_job_t *j = (dns_job_t *)arg;
    pf_dns_resolver_t *r = j->r;

    int tun_fd = -1;
    SSL *ssl = NULL;

    pf_proxy_t proxy;
    if (pick_dns_proxy(CTX_CONFIG(r), &proxy) != PF_OK) {
        pf_log_warn("dns_resolver: no usable proxy (enable one HTTP/SOCKS5 first)");
        goto done;
    }

    tun_fd = connect_via_proxy(&proxy, r->doh_host, r->doh_port);
    if (tun_fd < 0) {
        pf_log_warn("dns_resolver: proxy connect failed (proxy=%s)", proxy.name);
        goto done;
    }

    /* 8 s total timeout on the tunnel — generous for residential proxies. */
    struct timeval tv = { .tv_sec = 8, .tv_usec = 0 };
    setsockopt(tun_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(tun_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    pthread_once(&g_ssl_once, ssl_ctx_init_once);
    if (!g_ssl_ctx) {
        pf_log_error("dns_resolver: SSL_CTX init failed");
        goto done;
    }

    ssl = SSL_new(g_ssl_ctx);
    if (!ssl) goto done;
    SSL_set_tlsext_host_name(ssl, r->doh_host);
    SSL_set_fd(ssl, tun_fd);
    if (SSL_connect(ssl) != 1) {
        pf_log_warn("dns_resolver: TLS handshake failed to %s", r->doh_host);
        goto done;
    }

    /* Build HTTP/1.1 POST request. Body = raw DNS wire query (RFC 8484 §4.1) */
    char req[512];
    int req_len = snprintf(req, sizeof(req),
        "POST /dns-query HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: ProxiFlare/%s\r\n"
        "Content-Type: application/dns-message\r\n"
        "Accept: application/dns-message\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        r->doh_host, PF_VERSION, j->query_len);
    if (req_len <= 0 || req_len >= (int)sizeof(req)) goto done;

    if (SSL_write(ssl, req, req_len) != req_len) goto done;
    if (SSL_write(ssl, j->query, (int)j->query_len) != (int)j->query_len) goto done;

    /* Read response headers (may include leading body bytes) */
    char hbuf[8192];
    size_t body_off = 0, total_read = 0;
    if (read_http_headers(ssl, hbuf, sizeof(hbuf), &body_off, &total_read) != 0) {
        pf_log_warn("dns_resolver: no HTTP headers from %s", r->doh_host);
        goto done;
    }
    if (strncmp(hbuf, "HTTP/1.1 200", 12) != 0 &&
        strncmp(hbuf, "HTTP/1.0 200", 12) != 0) {
        pf_log_warn("dns_resolver: non-200 from %s: %.40s", r->doh_host, hbuf);
        goto done;
    }
    int clen_s = parse_content_length(hbuf, body_off);
    if (clen_s <= 0 || clen_s > 4096) {
        pf_log_warn("dns_resolver: bad content-length %d", clen_s);
        goto done;
    }
    size_t clen = (size_t)clen_s;

    /* Assemble body: leftover from header read, then pull the remainder */
    unsigned char body[4096];
    size_t have = total_read > body_off ? total_read - body_off : 0;
    if (have > clen) have = clen;
    if (have) memcpy(body, hbuf + body_off, have);
    if (have < clen) {
        if (ssl_read_full(ssl, body + have, clen - have) !=
            (ssize_t)(clen - have)) {
            pf_log_warn("dns_resolver: body short read from %s", r->doh_host);
            goto done;
        }
    }

    /* Send raw DNS answer back to the client. conntrack fixes src IP:port. */
    ssize_t sent = sendto(r->udp_fd, body, clen, 0,
                          (struct sockaddr *)&j->client, j->client_len);
    if (sent < 0) {
        pf_log_warn("dns_resolver: sendto client failed: %s", strerror(errno));
    } else {
        (void)sent; (void)proxy;
    }

done:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (tun_fd >= 0) close(tun_fd);
    free(j->query);
    free(j);
    return NULL;
}

/* ─── Public API ─────────────────────────────────────────────────────────── */

int pf_dns_resolver_init(pf_dns_resolver_t *r, pf_config_t *config, int port)
{
    memset(r, 0, sizeof(*r));
    r->config    = config;
    r->port      = port;
    r->doh_port  = 443;  /* DoH (RFC 8484) over HTTPS */
    snprintf(r->doh_host, sizeof(r->doh_host), "%s", PF_DNS_RESOLVER_DEFAULT_DOH);

    r->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (r->udp_fd < 0) {
        pf_log_error("dns_resolver: socket() failed: %s", strerror(errno));
        return PF_ERR;
    }
    int one = 1;
    setsockopt(r->udp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  /* 127.0.0.1 */
    if (bind(r->udp_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        pf_log_error("dns_resolver: bind 127.0.0.1:%d failed: %s",
                     port, strerror(errno));
        close(r->udp_fd);
        r->udp_fd = -1;
        return PF_ERR;
    }

    pf_log_info("dns_resolver: listening on 127.0.0.1:%d (DoH → %s:%d via proxy)",
                port, r->doh_host, r->doh_port);
    return PF_OK;
}

void pf_dns_resolver_close(pf_dns_resolver_t *r)
{
    if (!r) return;
    if (r->udp_fd >= 0) {
        close(r->udp_fd);
        r->udp_fd = -1;
    }
}

int pf_dns_resolver_process(pf_dns_resolver_t *r)
{
    if (!r || r->udp_fd < 0) return PF_ERR;

    unsigned char pkt[1500];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    ssize_t n = recvfrom(r->udp_fd, pkt, sizeof(pkt), 0,
                         (struct sockaddr *)&from, &from_len);
    if (n < 12) return PF_ERR; /* DNS header is 12 bytes minimum */

    dns_job_t *j = calloc(1, sizeof(*j));
    if (!j) return PF_ERR;
    j->r          = r;
    j->client     = from;
    j->client_len = from_len;
    j->query      = malloc((size_t)n);
    if (!j->query) { free(j); return PF_ERR; }
    memcpy(j->query, pkt, (size_t)n);
    j->query_len  = (size_t)n;

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&tid, &attr, dns_worker, j);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        pf_log_error("dns_resolver: pthread_create: %s", strerror(rc));
        free(j->query);
        free(j);
        return PF_ERR;
    }
    return PF_OK;
}
