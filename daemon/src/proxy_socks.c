#include "proxy_socks.h"
#include "logger.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>

/* ──────────────────────────────────────────────────────────────────────────
 * Constants
 * ────────────────────────────────────────────────────────────────────────── */

#define SOCK_TIMEOUT_SEC    5
#define TEST_HOST           "httpbin.org"
#define TEST_PORT           443

/* SOCKS5 reply code descriptions */
static const char *socks5_reply_str(uint8_t code)
{
    switch (code) {
        case 0x00: return "succeeded";
        case 0x01: return "general SOCKS server failure";
        case 0x02: return "connection not allowed by ruleset";
        case 0x03: return "network unreachable";
        case 0x04: return "host unreachable";
        case 0x05: return "connection refused";
        case 0x06: return "TTL expired";
        case 0x07: return "command not supported";
        case 0x08: return "address type not supported";
        default:   return "unknown error";
    }
}

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
    hints.ai_family   = AF_UNSPEC;     /* allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;

    snprintf(portstr, sizeof(portstr), "%d", port);

    ret = getaddrinfo(host, portstr, &hints, &res);
    if (ret != 0) {
        pf_log_error("tcp_connect: getaddrinfo(%s:%d): %s",
                     host, port, gai_strerror(ret));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;

        /* Set send/recv timeouts before connecting */
        struct timeval tv = { .tv_sec = SOCK_TIMEOUT_SEC, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;  /* success */

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    if (fd < 0)
        pf_log_error("tcp_connect: could not connect to %s:%d: %s",
                     host, port, strerror(errno));

    return fd;
}

/*
 * send_all — keep writing until all bytes are sent or an error occurs.
 */
static int send_all(int fd, const uint8_t *buf, size_t len)
{
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) {
            pf_log_error("send_all: send() failed: %s", strerror(errno));
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

/*
 * recv_all — keep reading until all expected bytes arrive or an error occurs.
 */
static int recv_all(int fd, uint8_t *buf, size_t len)
{
    size_t got = 0;

    while (got < len) {
        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n <= 0) {
            if (n == 0)
                pf_log_error("recv_all: connection closed by peer");
            else
                pf_log_error("recv_all: recv() failed: %s", strerror(errno));
            return -1;
        }
        got += (size_t)n;
    }
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * SOCKS4 / 4a
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * pf_socks4_connect — connect through a SOCKS4a proxy.
 *
 * Sends the SOCKS4a variant (fake DSTIP 0.0.0.1 + domain after userid) so
 * the proxy performs the DNS resolution, keeping the client anonymous.
 *
 * Returns connected fd on success, -1 on failure.
 */
int pf_socks4_connect(const char *proxy_host, int proxy_port,
                      const char *dst_host, int dst_port,
                      const char *userid)
{
    int      fd;
    uint8_t  req[PF_BUF_SIZE];
    uint8_t  resp[8];
    size_t   uid_len, dom_len, req_len;
    size_t   off = 0;

    if (!proxy_host || !dst_host) {
        pf_log_error("socks4_connect: NULL argument");
        return -1;
    }

    if (dst_port < 1 || dst_port > 65535) {
        pf_log_error("socks4_connect: invalid destination port %d", dst_port);
        return -1;
    }

    /* userid may be NULL — treat as empty string */
    if (!userid)
        userid = "";

    uid_len = strlen(userid);
    dom_len = strlen(dst_host);

    /* Validate buffer room: header(8) + userid + NUL + domain + NUL */
    if (8 + uid_len + 1 + dom_len + 1 > sizeof(req)) {
        pf_log_error("socks4_connect: request too large");
        return -1;
    }

    fd = tcp_connect(proxy_host, proxy_port);
    if (fd < 0)
        return -1;

    /* ── Build SOCKS4a request ──────────────────────────────────────────── */
    req[off++] = 0x04;                          /* VN: SOCKS version 4     */
    req[off++] = 0x01;                          /* CD: CONNECT command     */
    req[off++] = (uint8_t)((dst_port >> 8) & 0xFF); /* DSTPORT high byte  */
    req[off++] = (uint8_t)(dst_port & 0xFF);    /* DSTPORT low byte        */
    /* DSTIP: 0.0.0.1 — invalid, signals 4a mode (resolve on proxy side)   */
    req[off++] = 0x00;
    req[off++] = 0x00;
    req[off++] = 0x00;
    req[off++] = 0x01;
    /* USERID (may be empty) + NUL terminator */
    memcpy(req + off, userid, uid_len);
    off += uid_len;
    req[off++] = 0x00;
    /* DOMAIN + NUL terminator (SOCKS4a extension) */
    memcpy(req + off, dst_host, dom_len);
    off += dom_len;
    req[off++] = 0x00;

    req_len = off;

    if (send_all(fd, req, req_len) < 0) {
        pf_log_error("socks4_connect: failed to send request to %s:%d",
                     proxy_host, proxy_port);
        close(fd);
        return -1;
    }

    /* ── Read 8-byte response ───────────────────────────────────────────── */
    if (recv_all(fd, resp, 8) < 0) {
        pf_log_error("socks4_connect: failed to read response from %s:%d",
                     proxy_host, proxy_port);
        close(fd);
        return -1;
    }

    /* resp[0] = VN (should be 0x00), resp[1] = CD (0x5A = granted) */
    if (resp[1] != 0x5A) {
        pf_log_error("socks4_connect: request rejected by %s:%d (code 0x%02X)",
                     proxy_host, proxy_port, resp[1]);
        close(fd);
        return -1;
    }

    return fd;
}

/* ──────────────────────────────────────────────────────────────────────────
 * SOCKS5
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * pf_socks5_connect — connect through a SOCKS5 proxy (RFC 1928 + RFC 1929).
 *
 * Supports:
 *   - No-auth (0x00)
 *   - Username/password auth (0x02) per RFC 1929
 *
 * The destination is always sent as a domain name (ATYP 0x03) so the proxy
 * performs DNS resolution — consistent with the SOCKS4a approach.
 *
 * Returns connected fd on success, -1 on failure.
 */
int pf_socks5_connect(const char *proxy_host, int proxy_port,
                      const char *dst_host, int dst_port,
                      const char *username, const char *password)
{
    int     fd;
    uint8_t buf[PF_BUF_SIZE];
    uint8_t resp[4];
    size_t  off;
    int     has_auth;
    uint8_t method;
    size_t  ulen, plen, dlen;

    if (!proxy_host || !dst_host) {
        pf_log_error("socks5_connect: NULL argument");
        return -1;
    }

    if (dst_port < 1 || dst_port > 65535) {
        pf_log_error("socks5_connect: invalid destination port %d", dst_port);
        return -1;
    }

    has_auth = (username && username[0] != '\0');
    ulen     = has_auth ? strlen(username) : 0;
    plen     = (has_auth && password) ? strlen(password) : 0;
    dlen     = strlen(dst_host);

    if (dlen > 255) {
        pf_log_error("socks5_connect: destination hostname too long (%zu)", dlen);
        return -1;
    }
    if (ulen > 255 || plen > 255) {
        pf_log_error("socks5_connect: username or password too long");
        return -1;
    }

    fd = tcp_connect(proxy_host, proxy_port);
    if (fd < 0)
        return -1;

    /* ── Step 1: greeting / method negotiation ──────────────────────────── */
    off = 0;
    buf[off++] = 0x05;                      /* VER: SOCKS5              */
    if (has_auth) {
        buf[off++] = 0x02;                  /* NMETHODS: 2              */
        buf[off++] = 0x00;                  /* METHOD: no authentication */
        buf[off++] = 0x02;                  /* METHOD: username/password */
    } else {
        buf[off++] = 0x01;                  /* NMETHODS: 1              */
        buf[off++] = 0x00;                  /* METHOD: no authentication */
    }

    if (send_all(fd, buf, off) < 0) {
        pf_log_error("socks5_connect: failed to send greeting to %s:%d",
                     proxy_host, proxy_port);
        close(fd);
        return -1;
    }

    /* Read server's chosen method (2 bytes: VER, METHOD) */
    if (recv_all(fd, buf, 2) < 0) {
        pf_log_error("socks5_connect: failed to read method from %s:%d",
                     proxy_host, proxy_port);
        close(fd);
        return -1;
    }

    if (buf[0] != 0x05) {
        pf_log_error("socks5_connect: unexpected version byte 0x%02X from %s:%d",
                     buf[0], proxy_host, proxy_port);
        close(fd);
        return -1;
    }

    method = buf[1];

    if (method == 0xFF) {
        pf_log_error("socks5_connect: no acceptable auth methods for %s:%d",
                     proxy_host, proxy_port);
        close(fd);
        return -1;
    }

    /* ── Step 2: username/password authentication (RFC 1929) ────────────── */
    if (method == 0x02) {
        if (!has_auth) {
            pf_log_error("socks5_connect: proxy %s:%d requires auth but none provided",
                         proxy_host, proxy_port);
            close(fd);
            return -1;
        }

        off = 0;
        buf[off++] = 0x01;                      /* auth sub-negotiation VER */
        buf[off++] = (uint8_t)ulen;
        memcpy(buf + off, username, ulen);
        off += ulen;
        buf[off++] = (uint8_t)plen;
        if (plen > 0)
            memcpy(buf + off, password, plen);
        off += plen;

        if (send_all(fd, buf, off) < 0) {
            pf_log_error("socks5_connect: failed to send credentials to %s:%d",
                         proxy_host, proxy_port);
            close(fd);
            return -1;
        }

        /* Read auth response (2 bytes: VER, STATUS) */
        if (recv_all(fd, buf, 2) < 0) {
            pf_log_error("socks5_connect: failed to read auth response from %s:%d",
                         proxy_host, proxy_port);
            close(fd);
            return -1;
        }

        if (buf[1] != 0x00) {
            pf_log_error("socks5_connect: authentication failed on %s:%d (status 0x%02X)",
                         proxy_host, proxy_port, buf[1]);
            close(fd);
            return -1;
        }
    }

    /* ── Step 3: CONNECT request ─────────────────────────────────────────── */
    off = 0;
    buf[off++] = 0x05;                          /* VER                     */
    buf[off++] = 0x01;                          /* CMD: CONNECT            */
    buf[off++] = 0x00;                          /* RSV: reserved           */
    buf[off++] = 0x03;                          /* ATYP: domain name       */
    buf[off++] = (uint8_t)dlen;                 /* domain length           */
    memcpy(buf + off, dst_host, dlen);
    off += dlen;
    buf[off++] = (uint8_t)((dst_port >> 8) & 0xFF); /* port high byte     */
    buf[off++] = (uint8_t)(dst_port & 0xFF);    /* port low byte           */

    if (send_all(fd, buf, off) < 0) {
        pf_log_error("socks5_connect: failed to send CONNECT request to %s:%d",
                     proxy_host, proxy_port);
        close(fd);
        return -1;
    }

    /* ── Step 4: read CONNECT response header (4 bytes) ─────────────────── */
    /* VER | REP | RSV | ATYP */
    if (recv_all(fd, resp, 4) < 0) {
        pf_log_error("socks5_connect: failed to read CONNECT response from %s:%d",
                     proxy_host, proxy_port);
        close(fd);
        return -1;
    }

    if (resp[1] != 0x00) {
        pf_log_error("socks5_connect: CONNECT rejected by %s:%d: %s (0x%02X)",
                     proxy_host, proxy_port,
                     socks5_reply_str(resp[1]), resp[1]);
        close(fd);
        return -1;
    }

    /* ── Step 5: drain bound address (ATYP-dependent) + 2 port bytes ────── */
    /* We must consume the BND.ADDR + BND.PORT fields before returning */
    {
        uint8_t atyp = resp[3];
        uint8_t drain[256 + 2]; /* max domain (255) + 1 len byte + 2 port */
        size_t  addr_len;

        switch (atyp) {
            case 0x01:  /* IPv4 — 4 bytes */
                addr_len = 4;
                break;
            case 0x04:  /* IPv6 — 16 bytes */
                addr_len = 16;
                break;
            case 0x03:  /* domain — 1 length byte + N bytes */
            {
                uint8_t domain_len;
                if (recv_all(fd, &domain_len, 1) < 0) {
                    pf_log_error("socks5_connect: failed to read domain length from %s:%d",
                                 proxy_host, proxy_port);
                    close(fd);
                    return -1;
                }
                addr_len = domain_len;
                break;
            }
            default:
                pf_log_error("socks5_connect: unknown ATYP 0x%02X from %s:%d",
                             atyp, proxy_host, proxy_port);
                close(fd);
                return -1;
        }

        /* Read BND.ADDR + BND.PORT (2 bytes) */
        if (recv_all(fd, drain, addr_len + 2) < 0) {
            pf_log_error("socks5_connect: failed to drain BND address from %s:%d",
                         proxy_host, proxy_port);
            close(fd);
            return -1;
        }
    }

    return fd;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Proxy test
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * pf_socks_test — connect to TEST_HOST:TEST_PORT through the proxy and
 * measure round-trip latency in milliseconds.
 *
 * Returns latency in ms, or -1 on failure.
 */
int pf_socks_test(const pf_proxy_t *proxy)
{
    struct timespec t0, t1;
    int             fd;
    long long       elapsed_ms;

    if (!proxy) {
        pf_log_error("socks_test: NULL proxy");
        return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &t0);

    switch (proxy->type) {
        case PF_PROXY_SOCKS4:
            fd = pf_socks4_connect(proxy->host, proxy->port,
                                   TEST_HOST, TEST_PORT,
                                   proxy->username[0] ? proxy->username : NULL);
            break;

        case PF_PROXY_SOCKS5:
            fd = pf_socks5_connect(proxy->host, proxy->port,
                                   TEST_HOST, TEST_PORT,
                                   proxy->username[0] ? proxy->username : NULL,
                                   proxy->password[0] ? proxy->password : NULL);
            break;

        default:
            pf_log_error("socks_test: proxy %u has non-SOCKS type %d",
                         proxy->id, proxy->type);
            return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);

    if (fd < 0)
        return -1;

    close(fd);

    elapsed_ms = (long long)(t1.tv_sec  - t0.tv_sec)  * 1000LL
               + (long long)(t1.tv_nsec - t0.tv_nsec) / 1000000LL;

    return (int)elapsed_ms;
}
