#include "proxy_http.h"
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
#include <stdio.h>

#include <openssl/evp.h>

/* ──────────────────────────────────────────────────────────────────────────
 * Constants
 * ────────────────────────────────────────────────────────────────────────── */

#define SOCK_TIMEOUT_SEC    5
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
 * base64_encode — encode src_len bytes from src into dst using OpenSSL's
 * EVP_EncodeBlock.  dst must be at least ((src_len + 2) / 3) * 4 + 1 bytes.
 * Returns the number of characters written (excluding NUL terminator).
 */
static int base64_encode(const unsigned char *src, int src_len,
                         char *dst, int dst_size)
{
    int out_len;

    /* EVP_EncodeBlock returns the number of bytes written (no NUL) */
    out_len = EVP_EncodeBlock((unsigned char *)dst,
                              src, src_len);

    if (out_len < 0 || out_len >= dst_size) {
        pf_log_error("base64_encode: output too large (%d, max %d)",
                     out_len, dst_size - 1);
        return -1;
    }

    dst[out_len] = '\0';
    return out_len;
}

/* ──────────────────────────────────────────────────────────────────────────
 * HTTP CONNECT
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * pf_http_connect — tunnel through an HTTP CONNECT proxy.
 *
 * Sends a CONNECT request and waits for a 200 response.  If username and
 * password are supplied, a "Proxy-Authorization: Basic <b64>" header is
 * added per RFC 7235.
 *
 * Returns a connected fd whose stream is the tunneled connection, or -1.
 */
int pf_http_connect(const char *proxy_host, int proxy_port,
                    const char *dst_host, int dst_port,
                    const char *username, const char *password)
{
    int    fd;
    char   req[PF_BUF_SIZE];
    int    req_len = 0;
    char   resp[RESP_BUF_SIZE];
    int    resp_len = 0;
    int    has_auth;
    int    status_code;

    if (!proxy_host || !dst_host) {
        pf_log_error("http_connect: NULL argument");
        return -1;
    }

    if (dst_port < 1 || dst_port > 65535) {
        pf_log_error("http_connect: invalid destination port %d", dst_port);
        return -1;
    }

    has_auth = (username && username[0] != '\0');

    fd = tcp_connect(proxy_host, proxy_port);
    if (fd < 0)
        return -1;

    /* ── Build CONNECT request ──────────────────────────────────────────── */
    req_len += snprintf(req + req_len, sizeof(req) - (size_t)req_len,
                        "CONNECT %s:%d HTTP/1.1\r\n"
                        "Host: %s:%d\r\n",
                        dst_host, dst_port,
                        dst_host, dst_port);

    if (has_auth) {
        /* Build "username:password" and base64-encode it */
        char   creds[256 + 1 + 128 + 1]; /* user(128)+':'+pass(128)+NUL */
        char   b64[512];
        int    creds_len;
        int    b64_len;

        creds_len = snprintf(creds, sizeof(creds), "%s:%s",
                             username,
                             (password && password[0]) ? password : "");

        if (creds_len <= 0 || (size_t)creds_len >= sizeof(creds)) {
            pf_log_error("http_connect: credentials string overflow");
            close(fd);
            return -1;
        }

        b64_len = base64_encode((unsigned char *)creds, creds_len,
                                b64, sizeof(b64));
        if (b64_len < 0) {
            close(fd);
            return -1;
        }

        req_len += snprintf(req + req_len, sizeof(req) - (size_t)req_len,
                            "Proxy-Authorization: Basic %s\r\n", b64);
    }

    /* Terminate headers */
    req_len += snprintf(req + req_len, sizeof(req) - (size_t)req_len,
                        "\r\n");

    if (req_len <= 0 || (size_t)req_len >= sizeof(req)) {
        pf_log_error("http_connect: request buffer overflow");
        close(fd);
        return -1;
    }

    /* ── Send request ───────────────────────────────────────────────────── */
    {
        size_t  sent = 0;
        size_t  total = (size_t)req_len;

        while (sent < total) {
            ssize_t n = send(fd, req + sent, total - sent, 0);
            if (n <= 0) {
                pf_log_error("http_connect: send() to %s:%d failed: %s",
                             proxy_host, proxy_port, strerror(errno));
                close(fd);
                return -1;
            }
            sent += (size_t)n;
        }
    }

    /* ── Read response until \r\n\r\n ───────────────────────────────────── */
    /*
     * HTTP responses may arrive in chunks.  We read byte-by-byte into the
     * buffer until we see the header terminator or run out of space.
     * 4096 bytes is more than enough for the proxy status line + headers.
     */
    {
        int    found_end = 0;

        while (resp_len < RESP_BUF_SIZE - 1) {
            ssize_t n = recv(fd,
                             resp + resp_len,
                             (size_t)(RESP_BUF_SIZE - 1 - resp_len),
                             0);
            if (n <= 0) {
                if (n == 0)
                    pf_log_error("http_connect: connection closed by %s:%d",
                                 proxy_host, proxy_port);
                else
                    pf_log_error("http_connect: recv() from %s:%d failed: %s",
                                 proxy_host, proxy_port, strerror(errno));
                close(fd);
                return -1;
            }
            resp_len += (int)n;
            resp[resp_len] = '\0';

            /* Check for end-of-headers marker */
            if (strstr(resp, "\r\n\r\n") != NULL) {
                found_end = 1;
                break;
            }
        }

        if (!found_end) {
            pf_log_error("http_connect: response from %s:%d too large or incomplete",
                         proxy_host, proxy_port);
            close(fd);
            return -1;
        }
    }

    /* ── Parse status line ──────────────────────────────────────────────── */
    /*
     * Expected format: "HTTP/1.x NNN <reason>\r\n..."
     * We scan for a space then read the 3-digit status code.
     */
    {
        const char *sp = strchr(resp, ' ');
        if (!sp) {
            pf_log_error("http_connect: malformed response from %s:%d: %.64s",
                         proxy_host, proxy_port, resp);
            close(fd);
            return -1;
        }

        status_code = (int)strtol(sp + 1, NULL, 10);
    }

    if (status_code == 407) {
        pf_log_error("http_connect: proxy %s:%d requires authentication (407)",
                     proxy_host, proxy_port);
        close(fd);
        return -1;
    }

    if (status_code != 200) {
        pf_log_error("http_connect: proxy %s:%d rejected CONNECT with status %d",
                     proxy_host, proxy_port, status_code);
        close(fd);
        return -1;
    }

    /* Tunnel established — fd is now a raw stream to dst_host:dst_port */
    return fd;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Proxy test
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * pf_http_test — connect to TEST_HOST:TEST_PORT through the proxy and
 * measure round-trip latency in milliseconds.
 *
 * Returns latency in ms, or -1 on failure.
 */
int pf_http_test(const pf_proxy_t *proxy)
{
    struct timespec t0, t1;
    int             fd;
    long long       elapsed_ms;

    if (!proxy) {
        pf_log_error("http_test: NULL proxy");
        return -1;
    }

    if (proxy->type != PF_PROXY_HTTP) {
        pf_log_error("http_test: proxy %u has non-HTTP type %d",
                     proxy->id, proxy->type);
        return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &t0);

    fd = pf_http_connect(proxy->host, proxy->port,
                         TEST_HOST, TEST_PORT,
                         proxy->username[0] ? proxy->username : NULL,
                         proxy->password[0] ? proxy->password : NULL);

    clock_gettime(CLOCK_MONOTONIC, &t1);

    if (fd < 0)
        return -1;

    close(fd);

    elapsed_ms = (long long)(t1.tv_sec  - t0.tv_sec)  * 1000LL
               + (long long)(t1.tv_nsec - t0.tv_nsec) / 1000000LL;

    return (int)elapsed_ms;
}
