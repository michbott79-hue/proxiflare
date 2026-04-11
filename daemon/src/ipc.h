#ifndef PF_IPC_H
#define PF_IPC_H

#include "proxiflare.h"
#include <cJSON.h>
#include <stdbool.h>

typedef struct {
    int fd;
    char buf[PF_BUF_SIZE];
    int buf_len;
    bool subscribed_log;
    bool subscribed_stats;
} pf_ipc_client_t;

typedef struct {
    int listen_fd;
    pf_ipc_client_t clients[PF_MAX_CLIENTS];
    int client_count;
    cJSON *(*handler)(pf_ctx_t *ctx, const char *method, cJSON *params, pf_ipc_client_t *client);
    pf_ctx_t *ctx;
} pf_ipc_t;

int  pf_ipc_init(pf_ipc_t *ipc, const char *socket_path, pf_ctx_t *ctx,
                 cJSON *(*handler)(pf_ctx_t *, const char *, cJSON *, pf_ipc_client_t *));
void pf_ipc_close(pf_ipc_t *ipc);
int  pf_ipc_accept(pf_ipc_t *ipc);
int  pf_ipc_process(pf_ipc_t *ipc, int client_idx);
int  pf_ipc_send(pf_ipc_client_t *client, cJSON *msg);
int  pf_ipc_broadcast_log(pf_ipc_t *ipc, cJSON *event);
int  pf_ipc_broadcast_stats(pf_ipc_t *ipc, cJSON *event);
int  pf_ipc_get_fd(pf_ipc_t *ipc);

#endif /* PF_IPC_H */
