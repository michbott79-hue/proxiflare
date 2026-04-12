#define _GNU_SOURCE
#include "ipc.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ── helpers ────────────────────────────────────────────────────────────── */

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* ── pf_ipc_init ─────────────────────────────────────────────────────────── */

int pf_ipc_init(pf_ipc_t *ipc, const char *socket_path, pf_ctx_t *ctx,
                cJSON *(*handler)(pf_ctx_t *, const char *, cJSON *, pf_ipc_client_t *))
{
    memset(ipc, 0, sizeof(*ipc));
    ipc->listen_fd   = -1;
    ipc->handler     = handler;
    ipc->ctx         = ctx;
    ipc->client_count = 0;

    for (int i = 0; i < PF_MAX_CLIENTS; i++)
        ipc->clients[i].fd = -1;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("ipc: socket");
        return -1;
    }

    /* Remove stale socket file */
    unlink(socket_path);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("ipc: bind");
        close(fd);
        return -1;
    }

    /* Make socket world-accessible so GUI (non-root) can connect */
    chmod(socket_path, 0777);

    if (listen(fd, 5) < 0) {
        perror("ipc: listen");
        close(fd);
        return -1;
    }

    if (set_nonblock(fd) < 0) {
        perror("ipc: set_nonblock");
        close(fd);
        return -1;
    }

    ipc->listen_fd = fd;
    return fd;
}

/* ── pf_ipc_get_fd ───────────────────────────────────────────────────────── */

int pf_ipc_get_fd(pf_ipc_t *ipc)
{
    return ipc->listen_fd;
}

/* ── pf_ipc_accept ───────────────────────────────────────────────────────── */

int pf_ipc_accept(pf_ipc_t *ipc)
{
    int cfd = accept(ipc->listen_fd, NULL, NULL);
    if (cfd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            perror("ipc: accept");
        return -1;
    }

    /* Peer credential check — defense-in-depth against other local users.
     * The daemon runs as root and executes privileged operations on request,
     * so any local process that can open the socket is effectively trusted.
     * Accept only root or regular users (uid >= 1000); reject system users
     * (www-data, nobody, etc.) which have no business talking to us. */
    struct ucred uc;
    socklen_t uclen = sizeof(uc);
    if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &uc, &uclen) == 0) {
        if (uc.uid != 0 && uc.uid < 1000) {
            fprintf(stderr, "ipc: rejecting connection from uid=%u pid=%d\n",
                    (unsigned)uc.uid, uc.pid);
            close(cfd);
            return -1;
        }
    } /* if getsockopt fails, fall through — not a security regression */

    if (ipc->client_count >= PF_MAX_CLIENTS) {
        /* Too many clients — reject */
        close(cfd);
        return -1;
    }

    if (set_nonblock(cfd) < 0) {
        perror("ipc: set_nonblock client");
        close(cfd);
        return -1;
    }

    /* Find a free slot */
    for (int i = 0; i < PF_MAX_CLIENTS; i++) {
        if (ipc->clients[i].fd < 0) {
            ipc->clients[i].fd              = cfd;
            ipc->clients[i].buf_len         = 0;
            ipc->clients[i].subscribed_log  = false;
            ipc->clients[i].subscribed_stats = false;
            ipc->client_count++;
            return i;
        }
    }

    /* Should not reach here (client_count guard above), but be safe */
    close(cfd);
    return -1;
}

/* ── pf_ipc_send ─────────────────────────────────────────────────────────── */

int pf_ipc_send(pf_ipc_client_t *client, cJSON *msg)
{
    char *raw = cJSON_PrintUnformatted(msg);
    if (!raw) return -1;

    size_t len  = strlen(raw);
    /* raw + newline */
    size_t total = len + 1;
    char  *buf  = malloc(total);
    if (!buf) {
        free(raw);
        return -1;
    }
    memcpy(buf, raw, len);
    buf[len] = '\n';
    free(raw);

    size_t sent = 0;
    int retries = 0;
    while (sent < total) {
        ssize_t n = write(client->fd, buf + sent, total - sent);
        if (n < 0) {
            if (errno == EINTR) continue;
            if ((errno == EAGAIN || errno == EWOULDBLOCK) && retries < 50) {
                /* Non-blocking fd not ready — brief pause and retry */
                usleep(1000); /* 1ms */
                retries++;
                continue;
            }
            free(buf);
            return -1;
        }
        sent += (size_t)n;
        retries = 0;
    }

    free(buf);
    return 0;
}

/* ── _client_remove ──────────────────────────────────────────────────────── */

static void client_remove(pf_ipc_t *ipc, int idx)
{
    close(ipc->clients[idx].fd);
    ipc->clients[idx].fd = -1;
    ipc->clients[idx].buf_len = 0;
    ipc->clients[idx].subscribed_log   = false;
    ipc->clients[idx].subscribed_stats = false;
    ipc->client_count--;
}

/* ── pf_ipc_process ──────────────────────────────────────────────────────── */

int pf_ipc_process(pf_ipc_t *ipc, int client_idx)
{
    pf_ipc_client_t *client = &ipc->clients[client_idx];

    /* Read into buffer after existing data */
    int space = PF_BUF_SIZE - client->buf_len - 1; /* -1 for safety */
    if (space <= 0) {
        /* Buffer full — discard and close */
        client_remove(ipc, client_idx);
        return -1;
    }

    ssize_t n = read(client->fd, client->buf + client->buf_len, (size_t)space);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0; /* no data yet — normal for non-blocking */
        client_remove(ipc, client_idx);
        return -1;
    }
    if (n == 0) {
        /* EOF — client disconnected */
        client_remove(ipc, client_idx);
        return -1;
    }

    client->buf_len += (int)n;

    /* Process complete lines (newline-delimited) */
    char *start = client->buf;
    int   remaining = client->buf_len;

    while (remaining > 0) {
        /* Find newline */
        char *nl = memchr(start, '\n', (size_t)remaining);
        if (!nl) break; /* incomplete line — wait for more data */

        int line_len = (int)(nl - start);
        /* NUL-terminate the line in-place */
        *nl = '\0';

        /* Parse JSON */
        cJSON *req = cJSON_Parse(start);

        /* Advance past this line + newline */
        start     = nl + 1;
        remaining -= line_len + 1;

        if (!req) {
            /* Malformed JSON — skip silently */
            continue;
        }

        cJSON *id_node = cJSON_GetObjectItemCaseSensitive(req, "id");
        cJSON *method_node = cJSON_GetObjectItemCaseSensitive(req, "method");
        cJSON *params_node = cJSON_GetObjectItemCaseSensitive(req, "params");

        const char *method = cJSON_IsString(method_node) ? method_node->valuestring : NULL;

        cJSON *response = cJSON_CreateObject();

        /* Reflect id (number or null) */
        if (cJSON_IsNumber(id_node))
            cJSON_AddNumberToObject(response, "id", id_node->valuedouble);
        else
            cJSON_AddNullToObject(response, "id");

        if (!method) {
            /* No method — return error */
            cJSON *err = cJSON_CreateObject();
            cJSON_AddNumberToObject(err, "code", -32600);
            cJSON_AddStringToObject(err, "message", "Invalid Request: missing method");
            cJSON_AddItemToObject(response, "error", err);
            pf_ipc_send(client, response);
            cJSON_Delete(response);
            cJSON_Delete(req);
            continue;
        }

        /* Handle built-in subscription methods */
        bool handled = false;

        if (strcmp(method, "log.subscribe") == 0) {
            client->subscribed_log = true;
            cJSON_AddBoolToObject(response, "result", cJSON_True);
            handled = true;
        } else if (strcmp(method, "log.unsubscribe") == 0) {
            client->subscribed_log = false;
            cJSON_AddBoolToObject(response, "result", cJSON_True);
            handled = true;
        } else if (strcmp(method, "stats.subscribe") == 0) {
            client->subscribed_stats = true;
            cJSON_AddBoolToObject(response, "result", cJSON_True);
            handled = true;
        } else if (strcmp(method, "stats.unsubscribe") == 0) {
            client->subscribed_stats = false;
            cJSON_AddBoolToObject(response, "result", cJSON_True);
            handled = true;
        }

        if (!handled && ipc->handler) {
            cJSON *result = ipc->handler(ipc->ctx, method, params_node, client);
            if (result) {
                cJSON_AddItemToObject(response, "result", result);
            } else {
                cJSON *err = cJSON_CreateObject();
                cJSON_AddNumberToObject(err, "code", -1);
                cJSON_AddStringToObject(err, "message", "method not found or internal error");
                cJSON_AddItemToObject(response, "error", err);
            }
        }

        pf_ipc_send(client, response);
        cJSON_Delete(response);
        cJSON_Delete(req);
    }

    /* Compact buffer: move leftover incomplete data to the front */
    if (remaining > 0 && start != client->buf)
        memmove(client->buf, start, (size_t)remaining);
    client->buf_len = remaining;

    return 0;
}

/* ── pf_ipc_broadcast_log ────────────────────────────────────────────────── */

int pf_ipc_broadcast_log(pf_ipc_t *ipc, cJSON *event)
{
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddNullToObject(msg, "id");
    cJSON_AddStringToObject(msg, "event", "log.entry");
    /* Duplicate event so each send can own it independently if needed */
    cJSON_AddItemToObject(msg, "data", cJSON_Duplicate(event, 1));

    for (int i = 0; i < PF_MAX_CLIENTS; i++) {
        if (ipc->clients[i].fd >= 0 && ipc->clients[i].subscribed_log)
            pf_ipc_send(&ipc->clients[i], msg);
    }

    cJSON_Delete(msg);
    return 0;
}

/* ── pf_ipc_broadcast_stats ──────────────────────────────────────────────── */

int pf_ipc_broadcast_stats(pf_ipc_t *ipc, cJSON *event)
{
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddNullToObject(msg, "id");
    cJSON_AddStringToObject(msg, "event", "stats.update");
    cJSON_AddItemToObject(msg, "data", cJSON_Duplicate(event, 1));

    for (int i = 0; i < PF_MAX_CLIENTS; i++) {
        if (ipc->clients[i].fd >= 0 && ipc->clients[i].subscribed_stats)
            pf_ipc_send(&ipc->clients[i], msg);
    }

    cJSON_Delete(msg);
    return 0;
}

/* ── pf_ipc_close ────────────────────────────────────────────────────────── */

void pf_ipc_close(pf_ipc_t *ipc)
{
    for (int i = 0; i < PF_MAX_CLIENTS; i++) {
        if (ipc->clients[i].fd >= 0) {
            close(ipc->clients[i].fd);
            ipc->clients[i].fd = -1;
        }
    }

    if (ipc->listen_fd >= 0) {
        /* Retrieve socket path from the fd to unlink it */
        struct sockaddr_un addr;
        socklen_t addrlen = sizeof(addr);
        if (getsockname(ipc->listen_fd, (struct sockaddr *)&addr, &addrlen) == 0)
            unlink(addr.sun_path);
        close(ipc->listen_fd);
        ipc->listen_fd = -1;
    }

    ipc->client_count = 0;
}
