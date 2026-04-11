#include "tproxy.h"
#include "sni.h"
#include "logger.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter_ipv4.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal helpers
 * ───────────────────────────────────────────────────────────────────────────── */

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int find_free_slot(pf_tproxy_t *tp)
{
    for (int i = 0; i < PF_MAX_CONNECTIONS; i++) {
        if (!tp->conns[i].active)
            return i;
    }
    return -1;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_tproxy_init
 *
 * Creates an IP_TRANSPARENT TCP listen socket bound to 0.0.0.0:port.
 * Also creates a private epoll fd for tracking relay connections.
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_tproxy_init(pf_tproxy_t *tp, int port)
{
    if (!tp) return PF_ERR;

    memset(tp, 0, sizeof(*tp));
    tp->listen_fd = -1;
    tp->epoll_fd  = -1;

    /* Initialise all conn slots as inactive */
    for (int i = 0; i < PF_MAX_CONNECTIONS; i++) {
        tp->conns[i].client_fd = -1;
        tp->conns[i].proxy_fd  = -1;
        tp->conns[i].active    = false;
    }

    /* ── Create listen socket ─────────────────────────────────────────────── */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        pf_log_error("tproxy: socket() failed: %s", strerror(errno));
        return PF_ERR_NET;
    }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    /* IP_TRANSPARENT — allow binding to non-local addresses */
    if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one)) < 0) {
        pf_log_error("tproxy: setsockopt(IP_TRANSPARENT) failed: %s (need CAP_NET_ADMIN)",
                     strerror(errno));
        close(fd);
        return PF_ERR_NET;
    }

    /* SO_ORIGINAL_DST requires IP_RECVORIGDSTADDR on newer kernels */
    setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &one, sizeof(one));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port        = htons((uint16_t)port),
    };

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        pf_log_error("tproxy: bind() on port %d failed: %s", port, strerror(errno));
        close(fd);
        return PF_ERR_NET;
    }

    if (listen(fd, 128) < 0) {
        pf_log_error("tproxy: listen() failed: %s", strerror(errno));
        close(fd);
        return PF_ERR_NET;
    }

    set_nonblocking(fd);

    /* ── Create epoll fd ──────────────────────────────────────────────────── */
    int efd = epoll_create1(EPOLL_CLOEXEC);
    if (efd < 0) {
        pf_log_error("tproxy: epoll_create1() failed: %s", strerror(errno));
        close(fd);
        return PF_ERR_NET;
    }

    tp->listen_fd  = fd;
    tp->epoll_fd   = efd;
    tp->conn_count = 0;

    pf_log_info("tproxy: listening on port %d (IP_TRANSPARENT)", port);
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_tproxy_close
 * ───────────────────────────────────────────────────────────────────────────── */

void pf_tproxy_close(pf_tproxy_t *tp)
{
    if (!tp) return;

    for (int i = 0; i < PF_MAX_CONNECTIONS; i++) {
        if (tp->conns[i].active)
            pf_tproxy_close_conn(tp, i);
    }

    if (tp->epoll_fd >= 0) {
        close(tp->epoll_fd);
        tp->epoll_fd = -1;
    }
    if (tp->listen_fd >= 0) {
        close(tp->listen_fd);
        tp->listen_fd = -1;
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_tproxy_get_fd
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_tproxy_get_fd(pf_tproxy_t *tp)
{
    return tp ? tp->listen_fd : -1;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_tproxy_accept
 *
 * Accepts a new redirected TCP connection.  Uses SO_ORIGINAL_DST to recover
 * the original destination IP:port that the kernel transparently redirected.
 * Peeks at the first bytes to detect TLS and extract the SNI hostname.
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_tproxy_accept(pf_tproxy_t *tp)
{
    if (!tp || tp->listen_fd < 0) return PF_ERR;

    struct sockaddr_in peer;
    socklen_t peerlen = sizeof(peer);

    int cfd = accept(tp->listen_fd, (struct sockaddr *)&peer, &peerlen);
    if (cfd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return PF_OK;
        pf_log_error("tproxy: accept() failed: %s", strerror(errno));
        return PF_ERR_NET;
    }

    /* ── Recover original destination ────────────────────────────────────── */
    struct sockaddr_in orig_dst;
    socklen_t orig_len = sizeof(orig_dst);

    if (getsockopt(cfd, SOL_IP, SO_ORIGINAL_DST, &orig_dst, &orig_len) < 0) {
        pf_log_error("tproxy: getsockopt(SO_ORIGINAL_DST) failed: %s", strerror(errno));
        close(cfd);
        return PF_ERR_NET;
    }

    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &orig_dst.sin_addr, dst_ip, sizeof(dst_ip));
    int dst_port = ntohs(orig_dst.sin_port);

    /* ── Find free connection slot ───────────────────────────────────────── */
    int slot = find_free_slot(tp);
    if (slot < 0) {
        pf_log_warn("tproxy: connection table full, dropping connection");
        close(cfd);
        return PF_ERR;
    }

    /* ── Peek first bytes for TLS/SNI detection ──────────────────────────── */
    uint8_t peek_buf[512];
    char    domain[PF_DOMAIN_MAX] = {0};

    ssize_t n = recv(cfd, peek_buf, sizeof(peek_buf), MSG_PEEK | MSG_DONTWAIT);
    if (n > 0 && peek_buf[0] == 0x16) {
        /* Looks like TLS — try to extract SNI */
        pf_sni_extract(peek_buf, (size_t)n, domain, sizeof(domain));
    }

    /* ── Connect through proxy via callback ─────────────────────────────── */
    int proxy_fd = -1;

    if (tp->connect_cb) {
        proxy_fd = tp->connect_cb(dst_ip, dst_port, domain, tp->connect_userdata);

        if (proxy_fd == -2) {
            /* BLOCK action — drop connection */
            pf_log_info("tproxy: BLOCKED connection to %s:%d%s%s",
                        dst_ip, dst_port,
                        domain[0] ? " domain=" : "",
                        domain[0] ? domain : "");
            close(cfd);
            return PF_OK;
        }

        if (proxy_fd < 0) {
            /* DIRECT — no proxy configured or no matching rule.
             * For now, close the connection since TPROXY can't do direct passthrough
             * (the packet was already redirected to us). We need to connect directly
             * to the original destination and relay. */
            proxy_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (proxy_fd < 0) {
                pf_log_error("tproxy: direct connect socket() failed: %s", strerror(errno));
                close(cfd);
                return PF_ERR;
            }
            struct sockaddr_in dst_addr = {
                .sin_family = AF_INET,
                .sin_port   = htons((uint16_t)dst_port),
            };
            inet_pton(AF_INET, dst_ip, &dst_addr.sin_addr);
            if (connect(proxy_fd, (struct sockaddr *)&dst_addr, sizeof(dst_addr)) < 0) {
                pf_log_error("tproxy: direct connect to %s:%d failed: %s",
                             dst_ip, dst_port, strerror(errno));
                close(proxy_fd);
                close(cfd);
                return PF_ERR;
            }
            pf_log_info("tproxy: DIRECT relay to %s:%d%s%s",
                        dst_ip, dst_port,
                        domain[0] ? " domain=" : "",
                        domain[0] ? domain : "");
        } else {
            pf_log_info("tproxy: PROXY relay to %s:%d%s%s (proxy_fd=%d)",
                        dst_ip, dst_port,
                        domain[0] ? " domain=" : "",
                        domain[0] ? domain : "",
                        proxy_fd);
        }
    } else {
        /* No callback set — can't route, close */
        pf_log_warn("tproxy: no connect callback set, dropping connection to %s:%d",
                     dst_ip, dst_port);
        close(cfd);
        return PF_ERR;
    }

    /* ── Populate slot ───────────────────────────────────────────────────── */
    pf_connection_t *conn = &tp->conns[slot];
    memset(conn, 0, sizeof(*conn));

    conn->client_fd = cfd;
    conn->proxy_fd  = proxy_fd;
    conn->dst_port  = dst_port;
    conn->proxy_id  = -1;
    conn->active    = true;

    strncpy(conn->dst_ip, dst_ip, sizeof(conn->dst_ip) - 1);
    strncpy(conn->domain, domain, sizeof(conn->domain) - 1);

    set_nonblocking(cfd);
    set_nonblocking(proxy_fd);
    tp->conn_count++;

    return slot;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_tproxy_relay
 *
 * Splices data between client_fd and proxy_fd.  Tracks bytes transferred.
 * Returns PF_OK on success, PF_ERR when one side closed/errored.
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_tproxy_relay(pf_tproxy_t *tp, int conn_idx)
{
    if (!tp || conn_idx < 0 || conn_idx >= PF_MAX_CONNECTIONS)
        return PF_ERR;

    pf_connection_t *conn = &tp->conns[conn_idx];
    if (!conn->active || conn->client_fd < 0 || conn->proxy_fd < 0)
        return PF_ERR;

    uint8_t buf[PF_BUF_SIZE];
    bool any_data = false;

    /* client → proxy */
    ssize_t n = read(conn->client_fd, buf, sizeof(buf));
    if (n > 0) {
        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(conn->proxy_fd, buf + written, (size_t)(n - written));
            if (w < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                pf_tproxy_close_conn(tp, conn_idx);
                return PF_ERR;
            }
            written += w;
        }
        conn->bytes_tx += (uint64_t)n;
        any_data = true;
    } else if (n == 0) {
        /* Client closed connection */
        pf_tproxy_close_conn(tp, conn_idx);
        return PF_ERR;
    } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        pf_tproxy_close_conn(tp, conn_idx);
        return PF_ERR;
    }

    /* proxy → client */
    n = read(conn->proxy_fd, buf, sizeof(buf));
    if (n > 0) {
        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(conn->client_fd, buf + written, (size_t)(n - written));
            if (w < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                pf_tproxy_close_conn(tp, conn_idx);
                return PF_ERR;
            }
            written += w;
        }
        conn->bytes_rx += (uint64_t)n;
        any_data = true;
    } else if (n == 0) {
        /* Proxy closed connection */
        pf_tproxy_close_conn(tp, conn_idx);
        return PF_ERR;
    } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        pf_tproxy_close_conn(tp, conn_idx);
        return PF_ERR;
    }

    (void)any_data;
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_tproxy_close_conn
 * ───────────────────────────────────────────────────────────────────────────── */

void pf_tproxy_close_conn(pf_tproxy_t *tp, int conn_idx)
{
    if (!tp || conn_idx < 0 || conn_idx >= PF_MAX_CONNECTIONS)
        return;

    pf_connection_t *conn = &tp->conns[conn_idx];
    if (!conn->active) return;

    if (conn->client_fd >= 0) {
        close(conn->client_fd);
        conn->client_fd = -1;
    }
    if (conn->proxy_fd >= 0) {
        close(conn->proxy_fd);
        conn->proxy_fd = -1;
    }

    conn->active = false;

    if (tp->conn_count > 0)
        tp->conn_count--;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_tproxy_set_connect_cb
 * ───────────────────────────────────────────────────────────────────────────── */

void pf_tproxy_set_connect_cb(pf_tproxy_t *tp, pf_tproxy_connect_cb cb, void *userdata)
{
    if (!tp) return;
    tp->connect_cb      = cb;
    tp->connect_userdata = userdata;
}
