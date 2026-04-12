#include "proxy_ssh.h"
#include "logger.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>

/* ──────────────────────────────────────────────────────────────────────────
 * Constants
 * ────────────────────────────────────────────────────────────────────────── */

#define SOCK_TIMEOUT_SEC    10
#define TEST_HOST           "httpbin.org"
#define TEST_PORT           443

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
 * session_invalidate — mark session as disconnected and free resources.
 * Does NOT remove from pool — caller handles slot reuse.
 */
static void session_invalidate(pf_ssh_session_t *sess)
{
    if (!sess)
        return;

    if (sess->session) {
        libssh2_session_disconnect(sess->session, "Closing session");
        libssh2_session_free(sess->session);
        sess->session = NULL;
    }

    if (sess->sock_fd >= 0) {
        close(sess->sock_fd);
        sess->sock_fd = -1;
    }

    sess->connected = false;
}

/*
 * log_ssh_error — emit a libssh2 error message to the daemon log.
 */
static void log_ssh_error(LIBSSH2_SESSION *session, const char *context)
{
    char   *errmsg = NULL;
    int     errlen = 0;
    int     rc;

    rc = libssh2_session_last_error(session, &errmsg, &errlen, 0);
    pf_log_error("%s: libssh2 error %d: %.*s", context, rc, errlen, errmsg);
}

/* ──────────────────────────────────────────────────────────────────────────
 * Pool init / close
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * pf_ssh_pool_init — zero all sessions and initialise libssh2.
 *
 * libssh2_init() must be called once per process before any other libssh2
 * function.  Flag 0 means "use default crypto init" (e.g. OpenSSL).
 *
 * Returns 0 on success, -1 on failure.
 */
int pf_ssh_pool_init(pf_ssh_pool_t *pool)
{
    int rc;

    if (!pool) {
        pf_log_error("ssh_pool_init: NULL pool");
        return -1;
    }

    memset(pool, 0, sizeof(*pool));

    if (pthread_mutex_init(&pool->pool_mutex, NULL) != 0) {
        pf_log_error("ssh_pool_init: pthread_mutex_init failed");
        return -1;
    }

    /* Initialise all sock_fd fields to -1 (unallocated) */
    for (int i = 0; i < PF_MAX_PROXIES; i++)
        pool->sessions[i].sock_fd = -1;

    rc = libssh2_init(0);
    if (rc != 0) {
        pf_log_error("ssh_pool_init: libssh2_init() failed: %d", rc);
        return -1;
    }

    pf_log_info("ssh_pool_init: libssh2 initialised");
    return 0;
}

/*
 * pf_ssh_pool_close — disconnect all active sessions and call libssh2_exit().
 */
void pf_ssh_pool_close(pf_ssh_pool_t *pool)
{
    if (!pool)
        return;

    pthread_mutex_lock(&pool->pool_mutex);
    for (int i = 0; i < pool->count; i++) {
        pf_ssh_session_t *sess = &pool->sessions[i];
        if (sess->connected)
            session_invalidate(sess);
    }

    pool->count = 0;
    pthread_mutex_unlock(&pool->pool_mutex);
    pthread_mutex_destroy(&pool->pool_mutex);
    libssh2_exit();
    pf_log_info("ssh_pool_close: pool closed");
}

/* ──────────────────────────────────────────────────────────────────────────
 * Session management
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * ssh_session_create — establish a new SSH session for the given proxy.
 *
 * Steps:
 *   1. TCP connect to proxy->host:proxy->port
 *   2. libssh2_session_init / handshake
 *   3. Authenticate (password or public-key from file)
 *   4. Set blocking mode
 *
 * Returns 0 on success and populates *sess, -1 on any failure.
 */
static int ssh_session_create(pf_ssh_session_t *sess, const pf_proxy_t *proxy)
{
    int              fd;
    LIBSSH2_SESSION *session;
    int              rc;
    const char      *user;

    user = proxy->username[0] ? proxy->username : "root";

    /* 1. TCP connect */
    fd = tcp_connect(proxy->host, proxy->port);
    if (fd < 0) {
        pf_log_error("ssh_session_create: TCP connect to %s:%u failed",
                     proxy->host, proxy->port);
        return -1;
    }

    /* 2a. Init session object */
    session = libssh2_session_init();
    if (!session) {
        pf_log_error("ssh_session_create: libssh2_session_init() failed");
        close(fd);
        return -1;
    }

    /* 2b. SSH handshake */
    rc = libssh2_session_handshake(session, fd);
    if (rc != 0) {
        log_ssh_error(session, "ssh_session_create: handshake");
        libssh2_session_free(session);
        close(fd);
        return -1;
    }

    /* 3. Authentication — password takes priority, then key file */
    if (proxy->password[0]) {
        rc = libssh2_userauth_password(session, user, proxy->password);
        if (rc != 0) {
            log_ssh_error(session, "ssh_session_create: password auth");
            libssh2_session_disconnect(session, "Auth failed");
            libssh2_session_free(session);
            close(fd);
            return -1;
        }
        pf_log_info("ssh_session_create: password auth OK for %s@%s:%u",
                    user, proxy->host, proxy->port);
    } else if (proxy->ssh_key_path[0]) {
        /* Public key path: libssh2 derives pubkey path from private key path
         * by appending ".pub".  Pass NULL for pubkey to use auto-derivation. */
        rc = libssh2_userauth_publickey_fromfile(session, user,
                                                 NULL,             /* pubkey */
                                                 proxy->ssh_key_path,
                                                 NULL);            /* passphrase */
        if (rc != 0) {
            log_ssh_error(session, "ssh_session_create: pubkey auth");
            libssh2_session_disconnect(session, "Auth failed");
            libssh2_session_free(session);
            close(fd);
            return -1;
        }
        pf_log_info("ssh_session_create: pubkey auth OK for %s@%s:%u",
                    user, proxy->host, proxy->port);
    } else {
        pf_log_error("ssh_session_create: proxy %u has no password or key path",
                     proxy->id);
        libssh2_session_disconnect(session, "No credentials");
        libssh2_session_free(session);
        close(fd);
        return -1;
    }

    /* 4. Set blocking mode — channels inherit this setting */
    libssh2_session_set_blocking(session, 1);

    sess->session   = session;
    sess->sock_fd   = fd;
    sess->proxy_id  = (int)proxy->id;
    sess->connected = true;

    pf_log_info("ssh_session_create: session established to %s:%u (proxy %u)",
                proxy->host, proxy->port, proxy->id);
    return 0;
}

/*
 * pf_ssh_get_session — return an existing connected session for the proxy,
 * or create a new one.
 *
 * If the pool is full (PF_MAX_PROXIES active sessions), returns NULL.
 * Returns a pointer into pool->sessions on success, NULL on failure.
 */
pf_ssh_session_t *pf_ssh_get_session(pf_ssh_pool_t *pool, const pf_proxy_t *proxy)
{
    int  i;
    int  free_slot = -1;

    if (!pool || !proxy) {
        pf_log_error("ssh_get_session: NULL argument");
        return NULL;
    }

    pthread_mutex_lock(&pool->pool_mutex);

    /* Search for an existing connected session for this proxy_id */
    for (i = 0; i < pool->count; i++) {
        pf_ssh_session_t *s = &pool->sessions[i];
        if (s->proxy_id == (int)proxy->id && s->connected) {
            pthread_mutex_unlock(&pool->pool_mutex);
            return s;
        }
        if (!s->connected && free_slot < 0)
            free_slot = i;
    }

    /* No existing session — allocate a new slot */
    if (pool->count < PF_MAX_PROXIES) {
        free_slot = pool->count;
    } else if (free_slot < 0) {
        pf_log_error("ssh_get_session: pool exhausted (%d sessions)", pool->count);
        pthread_mutex_unlock(&pool->pool_mutex);
        return NULL;
    }

    pf_ssh_session_t *sess = &pool->sessions[free_slot];

    /* Clear any leftover state in the slot */
    memset(sess, 0, sizeof(*sess));
    sess->sock_fd = -1;

    if (ssh_session_create(sess, proxy) < 0) {
        pthread_mutex_unlock(&pool->pool_mutex);
        return NULL;
    }

    /* Advance count only if using a brand-new slot at the end */
    if (free_slot == pool->count)
        pool->count++;

    pthread_mutex_unlock(&pool->pool_mutex);
    return sess;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Channel operations
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * pf_ssh_connect — open a direct-tcpip channel through the SSH session.
 *
 * If the session has been disconnected (detected via NULL return from
 * libssh2_channel_direct_tcpip), the session is removed from the pool and
 * a reconnect is attempted once.
 *
 * Returns a LIBSSH2_CHANNEL* ready for read/write, or NULL on error.
 * The caller is responsible for calling libssh2_channel_free() when done.
 */
LIBSSH2_CHANNEL *pf_ssh_connect(pf_ssh_pool_t *pool, const pf_proxy_t *proxy,
                                 const char *dst_host, int dst_port)
{
    pf_ssh_session_t *sess;
    LIBSSH2_CHANNEL  *channel;
    int               retry = 0;

    if (!pool || !proxy || !dst_host) {
        pf_log_error("ssh_connect: NULL argument");
        return NULL;
    }

    if (dst_port < 1 || dst_port > 65535) {
        pf_log_error("ssh_connect: invalid destination port %d", dst_port);
        return NULL;
    }

retry_connect:
    sess = pf_ssh_get_session(pool, proxy);
    if (!sess) {
        pf_log_error("ssh_connect: could not get session for proxy %u", proxy->id);
        return NULL;
    }

    channel = libssh2_channel_direct_tcpip(sess->session, dst_host, dst_port);
    if (!channel) {
        log_ssh_error(sess->session, "ssh_connect: direct_tcpip");

        /* Session likely dead — invalidate and retry once */
        if (!retry) {
            pf_log_info("ssh_connect: session dead for proxy %u, reconnecting",
                        proxy->id);
            session_invalidate(sess);
            retry = 1;
            goto retry_connect;
        }

        pf_log_error("ssh_connect: channel open failed for proxy %u -> %s:%d",
                     proxy->id, dst_host, dst_port);
        return NULL;
    }

    pf_log_info("ssh_connect: channel opened to %s:%d via proxy %u",
                dst_host, dst_port, proxy->id);
    return channel;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Accessors
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * pf_ssh_get_fd — return the underlying TCP socket fd for a session.
 * Useful for integrating with epoll/select event loops.
 */
int pf_ssh_get_fd(pf_ssh_session_t *sess)
{
    if (!sess)
        return -1;
    return sess->sock_fd;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Proxy test
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * pf_ssh_test — measure latency for establishing an SSH session and opening
 * a direct-tcpip channel to TEST_HOST:TEST_PORT.
 *
 * The session is kept in the pool for subsequent reuse.
 * Returns latency in ms, or -1 on failure.
 */
int pf_ssh_test(pf_ssh_pool_t *pool, const pf_proxy_t *proxy)
{
    struct timespec  t0, t1;
    LIBSSH2_CHANNEL *channel;
    long long        elapsed_ms;

    if (!pool || !proxy) {
        pf_log_error("ssh_test: NULL argument");
        return -1;
    }

    if (proxy->type != PF_PROXY_SSH) {
        pf_log_error("ssh_test: proxy %u has non-SSH type %d",
                     proxy->id, proxy->type);
        return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &t0);

    channel = pf_ssh_connect(pool, proxy, TEST_HOST, TEST_PORT);

    clock_gettime(CLOCK_MONOTONIC, &t1);

    if (!channel)
        return -1;

    /* Close the test channel — session stays in pool */
    libssh2_channel_free(channel);

    elapsed_ms = (long long)(t1.tv_sec  - t0.tv_sec)  * 1000LL
               + (long long)(t1.tv_nsec - t0.tv_nsec) / 1000000LL;

    pf_log_info("ssh_test: proxy %u latency %lld ms", proxy->id, elapsed_ms);
    return (int)elapsed_ms;
}
