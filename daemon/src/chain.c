#include "chain.h"
#include "logger.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/* ──────────────────────────────────────────────────────────────────────────
 * Constants
 * ────────────────────────────────────────────────────────────────────────── */

#define SOCK_TIMEOUT_SEC    10
#define TEST_HOST           "httpbin.org"
#define TEST_PORT           443
#define RESP_BUF_SIZE       4096

/* ──────────────────────────────────────────────────────────────────────────
 * Internal helpers
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * tcp_connect — resolve host and establish a TCP connection.
 * Returns the connected socket fd, or -1 on error.
 */
static int tcp_connect(const char *host, int port)
{
    struct addrinfo hints, *res, *rp;
    char portstr[16];
    int  fd = -1;
    int  ret;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(portstr, sizeof(portstr), "%d", port);

    ret = getaddrinfo(host, portstr, &hints, &res);
    if (ret != 0) {
        pf_log_error("chain: tcp_connect: getaddrinfo(%s:%d): %s",
                     host, port, gai_strerror(ret));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;

        struct timeval tv = { .tv_sec = SOCK_TIMEOUT_SEC, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    if (fd < 0)
        pf_log_error("chain: tcp_connect: could not connect to %s:%d: %s",
                     host, port, strerror(errno));

    return fd;
}

/*
 * send_all — write all bytes to fd, returns 0 on success or -1 on error.
 */
static int send_all(int fd, const uint8_t *buf, size_t len)
{
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) {
            pf_log_error("chain: send_all: send() failed: %s", strerror(errno));
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

/*
 * recv_all — read exactly len bytes from fd, returns 0 on success or -1 on error.
 */
static int recv_all(int fd, uint8_t *buf, size_t len)
{
    size_t got = 0;

    while (got < len) {
        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n <= 0) {
            if (n == 0)
                pf_log_error("chain: recv_all: connection closed by peer");
            else
                pf_log_error("chain: recv_all: recv() failed: %s", strerror(errno));
            return -1;
        }
        got += (size_t)n;
    }
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * find_proxy — look up a proxy by id in the flat proxies array
 * ────────────────────────────────────────────────────────────────────────── */

static const pf_proxy_t *find_proxy(const pf_proxy_t *proxies, int count, int id)
{
    for (int i = 0; i < count; i++)
        if ((int)proxies[i].id == id) return &proxies[i];
    return NULL;
}

/* ──────────────────────────────────────────────────────────────────────────
 * On-fd negotiation helpers
 *
 * These perform the proxy handshake on an ALREADY-connected fd (i.e. the
 * connection to hop[i] is established; we now ask it to forward to hop[i+1]
 * or the final destination).  This is the core of multi-hop chaining:
 * proxy protocol bytes are just layered TCP streams.
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * socks5_negotiate_on_fd — run full SOCKS5 greeting+auth+CONNECT on an
 * existing fd that is already connected to the SOCKS5 proxy.
 *
 * Returns 0 on success, -1 on failure (fd is not closed — caller handles it).
 */
static int socks5_negotiate_on_fd(int fd,
                                  const char *dst_host, int dst_port,
                                  const char *username, const char *password)
{
    uint8_t buf[PF_BUF_SIZE];
    uint8_t resp[4];
    size_t  off;
    int     has_auth;
    uint8_t method;
    size_t  ulen, plen, dlen;

    if (!dst_host || dst_port < 1 || dst_port > 65535) {
        pf_log_error("chain: socks5_negotiate: invalid destination");
        return -1;
    }

    has_auth = (username && username[0] != '\0');
    ulen     = has_auth ? strlen(username) : 0;
    plen     = (has_auth && password) ? strlen(password) : 0;
    dlen     = strlen(dst_host);

    if (dlen > 255) {
        pf_log_error("chain: socks5_negotiate: dst hostname too long (%zu)", dlen);
        return -1;
    }
    if (ulen > 255 || plen > 255) {
        pf_log_error("chain: socks5_negotiate: username or password too long");
        return -1;
    }

    /* ── Step 1: greeting / method negotiation ──────────────────────────── */
    off = 0;
    buf[off++] = 0x05;
    if (has_auth) {
        buf[off++] = 0x02;
        buf[off++] = 0x00;   /* no-auth */
        buf[off++] = 0x02;   /* username/password */
    } else {
        buf[off++] = 0x01;
        buf[off++] = 0x00;   /* no-auth */
    }

    if (send_all(fd, buf, off) < 0)
        return -1;

    if (recv_all(fd, buf, 2) < 0)
        return -1;

    if (buf[0] != 0x05) {
        pf_log_error("chain: socks5_negotiate: unexpected version 0x%02X", buf[0]);
        return -1;
    }

    method = buf[1];

    if (method == 0xFF) {
        pf_log_error("chain: socks5_negotiate: no acceptable auth methods");
        return -1;
    }

    /* ── Step 2: username/password auth (RFC 1929) ──────────────────────── */
    if (method == 0x02) {
        if (!has_auth) {
            pf_log_error("chain: socks5_negotiate: proxy requires auth but none provided");
            return -1;
        }

        off = 0;
        buf[off++] = 0x01;
        buf[off++] = (uint8_t)ulen;
        memcpy(buf + off, username, ulen);
        off += ulen;
        buf[off++] = (uint8_t)plen;
        if (plen > 0)
            memcpy(buf + off, password, plen);
        off += plen;

        if (send_all(fd, buf, off) < 0)
            return -1;

        if (recv_all(fd, buf, 2) < 0)
            return -1;

        if (buf[1] != 0x00) {
            pf_log_error("chain: socks5_negotiate: authentication failed (status 0x%02X)",
                         buf[1]);
            return -1;
        }
    }

    /* ── Step 3: CONNECT request ────────────────────────────────────────── */
    off = 0;
    buf[off++] = 0x05;
    buf[off++] = 0x01;   /* CMD: CONNECT */
    buf[off++] = 0x00;   /* RSV */
    buf[off++] = 0x03;   /* ATYP: domain name */
    buf[off++] = (uint8_t)dlen;
    memcpy(buf + off, dst_host, dlen);
    off += dlen;
    buf[off++] = (uint8_t)((dst_port >> 8) & 0xFF);
    buf[off++] = (uint8_t)(dst_port & 0xFF);

    if (send_all(fd, buf, off) < 0)
        return -1;

    /* ── Step 4: read CONNECT response header (VER|REP|RSV|ATYP) ────────── */
    if (recv_all(fd, resp, 4) < 0)
        return -1;

    if (resp[1] != 0x00) {
        pf_log_error("chain: socks5_negotiate: CONNECT rejected (code 0x%02X)", resp[1]);
        return -1;
    }

    /* ── Step 5: drain bound address ────────────────────────────────────── */
    {
        uint8_t atyp = resp[3];
        uint8_t drain[258]; /* max: 1 len byte + 255 domain + 2 port */
        size_t  addr_len;

        switch (atyp) {
            case 0x01: addr_len = 4;  break;  /* IPv4 */
            case 0x04: addr_len = 16; break;  /* IPv6 */
            case 0x03: {
                uint8_t domain_len;
                if (recv_all(fd, &domain_len, 1) < 0)
                    return -1;
                addr_len = domain_len;
                break;
            }
            default:
                pf_log_error("chain: socks5_negotiate: unknown ATYP 0x%02X", atyp);
                return -1;
        }

        if (recv_all(fd, drain, addr_len + 2) < 0)
            return -1;
    }

    return 0;
}

/*
 * socks4_negotiate_on_fd — run SOCKS4a CONNECT on an existing fd.
 *
 * Returns 0 on success, -1 on failure.
 */
static int socks4_negotiate_on_fd(int fd,
                                  const char *dst_host, int dst_port,
                                  const char *userid)
{
    uint8_t req[PF_BUF_SIZE];
    uint8_t resp[8];
    size_t  uid_len, dom_len;
    size_t  off = 0;

    if (!dst_host || dst_port < 1 || dst_port > 65535) {
        pf_log_error("chain: socks4_negotiate: invalid destination");
        return -1;
    }

    if (!userid)
        userid = "";

    uid_len = strlen(userid);
    dom_len = strlen(dst_host);

    if (8 + uid_len + 1 + dom_len + 1 > sizeof(req)) {
        pf_log_error("chain: socks4_negotiate: request too large");
        return -1;
    }

    req[off++] = 0x04;
    req[off++] = 0x01;   /* CONNECT */
    req[off++] = (uint8_t)((dst_port >> 8) & 0xFF);
    req[off++] = (uint8_t)(dst_port & 0xFF);
    /* DSTIP: 0.0.0.1 — SOCKS4a mode */
    req[off++] = 0x00;
    req[off++] = 0x00;
    req[off++] = 0x00;
    req[off++] = 0x01;
    memcpy(req + off, userid, uid_len);
    off += uid_len;
    req[off++] = 0x00;
    memcpy(req + off, dst_host, dom_len);
    off += dom_len;
    req[off++] = 0x00;

    if (send_all(fd, req, off) < 0)
        return -1;

    if (recv_all(fd, resp, 8) < 0)
        return -1;

    if (resp[1] != 0x5A) {
        pf_log_error("chain: socks4_negotiate: request rejected (code 0x%02X)", resp[1]);
        return -1;
    }

    return 0;
}

/*
 * http_negotiate_on_fd — send HTTP CONNECT on an existing fd and wait for
 * a 200 response.
 *
 * Returns 0 on success, -1 on failure.
 */
static int http_negotiate_on_fd(int fd,
                                const char *dst_host, int dst_port,
                                const char *username, const char *password)
{
    char req[PF_BUF_SIZE];
    int  req_len = 0;
    char resp[RESP_BUF_SIZE];
    int  resp_len = 0;
    int  has_auth;
    int  status_code;

    if (!dst_host || dst_port < 1 || dst_port > 65535) {
        pf_log_error("chain: http_negotiate: invalid destination");
        return -1;
    }

    has_auth = (username && username[0] != '\0');

    /* Build CONNECT request */
    req_len += snprintf(req + req_len, sizeof(req) - (size_t)req_len,
                        "CONNECT %s:%d HTTP/1.1\r\n"
                        "Host: %s:%d\r\n",
                        dst_host, dst_port,
                        dst_host, dst_port);

    if (has_auth) {
        /*
         * Base64-encode "username:password" using a simple portable encoder.
         * We avoid dragging OpenSSL into chain.c — the encoded size is at most
         * ceil((ulen+1+plen)/3)*4 which fits easily in 512 bytes for our
         * field limits (128+1+128 = 257 bytes raw → 344 bytes base64).
         */
        static const char b64chars[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        char   creds[384];  /* 128 user + ':' + 128 pass + NUL, with room */
        char   b64[512];
        int    clen;
        int    b64_len = 0;

        clen = snprintf(creds, sizeof(creds), "%s:%s",
                        username,
                        (password && password[0]) ? password : "");

        if (clen <= 0 || (size_t)clen >= sizeof(creds)) {
            pf_log_error("chain: http_negotiate: credentials overflow");
            return -1;
        }

        /* Simple base64 encoding */
        for (int i = 0; i < clen; i += 3) {
            uint32_t val = (uint32_t)((unsigned char)creds[i]) << 16;
            if (i + 1 < clen) val |= (uint32_t)((unsigned char)creds[i+1]) << 8;
            if (i + 2 < clen) val |= (uint32_t)((unsigned char)creds[i+2]);

            b64[b64_len++] = b64chars[(val >> 18) & 0x3F];
            b64[b64_len++] = b64chars[(val >> 12) & 0x3F];
            b64[b64_len++] = (i + 1 < clen) ? b64chars[(val >>  6) & 0x3F] : '=';
            b64[b64_len++] = (i + 2 < clen) ? b64chars[ val        & 0x3F] : '=';
        }
        b64[b64_len] = '\0';

        req_len += snprintf(req + req_len, sizeof(req) - (size_t)req_len,
                            "Proxy-Authorization: Basic %s\r\n", b64);
    }

    req_len += snprintf(req + req_len, sizeof(req) - (size_t)req_len, "\r\n");

    if (req_len <= 0 || (size_t)req_len >= sizeof(req)) {
        pf_log_error("chain: http_negotiate: request buffer overflow");
        return -1;
    }

    if (send_all(fd, (const uint8_t *)req, (size_t)req_len) < 0)
        return -1;

    /* Read response until \r\n\r\n */
    {
        int found_end = 0;

        while (resp_len < RESP_BUF_SIZE - 1) {
            ssize_t n = recv(fd,
                             resp + resp_len,
                             (size_t)(RESP_BUF_SIZE - 1 - resp_len),
                             0);
            if (n <= 0) {
                if (n == 0)
                    pf_log_error("chain: http_negotiate: connection closed by proxy");
                else
                    pf_log_error("chain: http_negotiate: recv() failed: %s",
                                 strerror(errno));
                return -1;
            }
            resp_len += (int)n;
            resp[resp_len] = '\0';

            if (strstr(resp, "\r\n\r\n") != NULL) {
                found_end = 1;
                break;
            }
        }

        if (!found_end) {
            pf_log_error("chain: http_negotiate: response too large or incomplete");
            return -1;
        }
    }

    /* Parse status line */
    {
        const char *sp = strchr(resp, ' ');
        if (!sp) {
            pf_log_error("chain: http_negotiate: malformed response: %.64s", resp);
            return -1;
        }
        status_code = (int)strtol(sp + 1, NULL, 10);
    }

    if (status_code == 407) {
        pf_log_error("chain: http_negotiate: proxy requires authentication (407)");
        return -1;
    }

    if (status_code != 200) {
        pf_log_error("chain: http_negotiate: CONNECT rejected with status %d",
                     status_code);
        return -1;
    }

    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * negotiate_hop_on_fd — dispatch to the right protocol negotiator
 *
 * proxy  — the proxy we are talking to (already connected on fd)
 * next_host / next_port — the next destination to tunnel through to
 *
 * Returns 0 on success, -1 on failure.
 * ────────────────────────────────────────────────────────────────────────── */

static int negotiate_hop_on_fd(int fd, const pf_proxy_t *proxy,
                                const char *next_host, int next_port)
{
    switch (proxy->type) {
        case PF_PROXY_SOCKS5:
            return socks5_negotiate_on_fd(fd, next_host, next_port,
                                          proxy->username[0] ? proxy->username : NULL,
                                          proxy->password[0] ? proxy->password : NULL);

        case PF_PROXY_SOCKS4:
            return socks4_negotiate_on_fd(fd, next_host, next_port,
                                          proxy->username[0] ? proxy->username : NULL);

        case PF_PROXY_HTTP:
            return http_negotiate_on_fd(fd, next_host, next_port,
                                        proxy->username[0] ? proxy->username : NULL,
                                        proxy->password[0] ? proxy->password : NULL);

        case PF_PROXY_SSH:
            /*
             * SSH hops mid-chain are not supported in v1.
             * SSH tunneling uses libssh2 channels, not raw TCP bytes, so it
             * cannot be layered the same way SOCKS/HTTP can.  SSH is only
             * supported as the FIRST hop (see pf_chain_connect logic below).
             */
            pf_log_error("chain: SSH hop mid-chain is not supported (proxy id=%u); "
                         "SSH is only allowed as the first hop", proxy->id);
            return -1;

        default:
            pf_log_error("chain: unknown proxy type %d (proxy id=%u)",
                         proxy->type, proxy->id);
            return -1;
    }
}

/* ──────────────────────────────────────────────────────────────────────────
 * pf_chain_connect
 *
 * For a chain [A, B, C] → destination D:
 *   1. TCP connect to A
 *   2. Negotiate A's protocol to reach B
 *   3. Negotiate B's protocol to reach C     (over the same fd, tunneled via A)
 *   4. Negotiate C's protocol to reach D     (tunneled via A→B)
 *   5. Return the fd (a single socket, tunneled all the way to D)
 *
 * SSH-as-first-hop note: libssh2 opens a direct-tcpip channel over the SSH
 * session.  That channel does NOT expose a raw fd — it uses libssh2 read/write
 * calls on the session's underlying socket.  In v1 we do NOT support SSH-first
 * chains because integrating a libssh2 channel fd into subsequent hop
 * negotiations requires multiplexing that is out of scope here.  A future
 * version could wrap the channel in a socketpair.
 *
 * Returns connected fd or -1 on error.
 * ────────────────────────────────────────────────────────────────────────── */

int pf_chain_connect(const pf_chain_t *chain, const pf_proxy_t *proxies,
                     int proxy_count, const char *dst_host, int dst_port)
{
    int fd = -1;
    int i;

    if (!chain || !proxies || !dst_host) {
        pf_log_error("chain_connect: NULL argument");
        return -1;
    }

    if (chain->hop_count < 1 || chain->hop_count > PF_MAX_HOPS) {
        pf_log_error("chain_connect: chain id=%u has invalid hop_count=%d",
                     chain->id, chain->hop_count);
        return -1;
    }

    if (dst_port < 1 || dst_port > 65535) {
        pf_log_error("chain_connect: invalid destination port %d", dst_port);
        return -1;
    }

    /* Look up every hop proxy upfront to catch bad ids before opening sockets */
    const pf_proxy_t *hop_proxies[PF_MAX_HOPS];
    for (i = 0; i < chain->hop_count; i++) {
        hop_proxies[i] = find_proxy(proxies, proxy_count, (int)chain->hops[i]);
        if (!hop_proxies[i]) {
            pf_log_error("chain_connect: chain id=%u hop[%d] references unknown proxy id=%u",
                         chain->id, i, chain->hops[i]);
            return -1;
        }
    }

    /* ── Step 1: TCP connect to the first hop ─────────────────────────────── */
    const pf_proxy_t *first = hop_proxies[0];

    if (first->type == PF_PROXY_SSH) {
        /*
         * SSH-first chains: not supported in v1.
         * libssh2 direct-tcpip channels don't expose a raw fd that subsequent
         * hop negotiations can write to.  Future work: wrap in a socketpair.
         */
        pf_log_error("chain_connect: chain id=%u starts with SSH proxy id=%u — "
                     "SSH-first chains are not supported in v1", chain->id, first->id);
        return -1;
    }

    fd = tcp_connect(first->host, first->port);
    if (fd < 0) {
        pf_log_error("chain_connect: chain id=%u failed to TCP-connect to "
                     "first hop proxy id=%u (%s:%u)",
                     chain->id, first->id, first->host, first->port);
        return -1;
    }

    /* ── Steps 2..N: negotiate each hop to tunnel toward the next ─────────── */
    for (i = 0; i < chain->hop_count; i++) {
        const char *next_host;
        int         next_port;

        if (i + 1 < chain->hop_count) {
            /* Next hop is another proxy in the chain */
            const pf_proxy_t *next_proxy = hop_proxies[i + 1];
            next_host = next_proxy->host;
            next_port = next_proxy->port;
        } else {
            /* Last hop: tunnel all the way to the final destination */
            next_host = dst_host;
            next_port = dst_port;
        }

        if (negotiate_hop_on_fd(fd, hop_proxies[i], next_host, next_port) < 0) {
            pf_log_error("chain_connect: chain id=%u failed at hop[%d] "
                         "(proxy id=%u) while connecting to %s:%d",
                         chain->id, i, hop_proxies[i]->id, next_host, next_port);
            close(fd);
            return -1;
        }
    }

    return fd;
}

/* ──────────────────────────────────────────────────────────────────────────
 * pf_chain_test — end-to-end latency test for a chain
 *
 * Connects to TEST_HOST:TEST_PORT through the chain, measures elapsed time
 * with CLOCK_MONOTONIC, closes the fd, and returns latency in ms (or -1).
 * ────────────────────────────────────────────────────────────────────────── */

int pf_chain_test(const pf_chain_t *chain, const pf_proxy_t *proxies, int proxy_count)
{
    struct timespec t0, t1;
    int             fd;
    long long       elapsed_ms;

    if (!chain || !proxies) {
        pf_log_error("chain_test: NULL argument");
        return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &t0);

    fd = pf_chain_connect(chain, proxies, proxy_count, TEST_HOST, TEST_PORT);

    clock_gettime(CLOCK_MONOTONIC, &t1);

    if (fd < 0)
        return -1;

    close(fd);

    elapsed_ms = (long long)(t1.tv_sec  - t0.tv_sec)  * 1000LL
               + (long long)(t1.tv_nsec - t0.tv_nsec) / 1000000LL;

    return (int)elapsed_ms;
}
