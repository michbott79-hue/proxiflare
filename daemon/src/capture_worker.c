#include "capture_worker.h"
#include "logger.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

#define DRAIN_BATCH 64  /* messages pulled per wake */

static pthread_t            g_thread;
static _Atomic int          g_running = 0;
static pf_capture_queue_t  *g_queue   = NULL;
static pf_capture_process_fn g_cb     = NULL;
static void                *g_ud      = NULL;

static void *worker_main(void *arg)
{
    (void)arg;
    pf_capture_msg_t *batch[DRAIN_BATCH];
    uint64_t discard;

    while (atomic_load_explicit(&g_running, memory_order_acquire)) {
        /* Block until a producer writes — or until stop() bumps the eventfd
         * with the g_running=0 already visible. */
        ssize_t n = read(g_queue->eventfd, &discard, sizeof(discard));
        if (n < 0) {
            if (errno == EINTR) continue;
            pf_log_error("capture_worker: eventfd read failed: %s", strerror(errno));
            break;
        }
        if (!atomic_load_explicit(&g_running, memory_order_acquire)) break;

        /* Drain everything available. One read() can correspond to many
         * producer writes thanks to the eventfd counter collapse. */
        for (;;) {
            int got = pf_capture_queue_drain(g_queue, batch, DRAIN_BATCH);
            if (got <= 0) break;
            for (int i = 0; i < got; i++) {
                if (g_cb) g_cb(batch[i], g_ud);
                else      free(batch[i]);
            }
        }
    }
    pf_log_info("capture_worker: exited");
    return NULL;
}

int pf_capture_worker_start(pf_capture_queue_t *q,
                            pf_capture_process_fn cb, void *ud)
{
    if (!q) return -1;
    if (atomic_exchange(&g_running, 1)) return -1;  /* already running */
    g_queue = q;
    g_cb    = cb;
    g_ud    = ud;
    if (pthread_create(&g_thread, NULL, worker_main, NULL) != 0) {
        atomic_store(&g_running, 0);
        g_queue = NULL; g_cb = NULL; g_ud = NULL;
        return -1;
    }
    pf_log_info("capture_worker: thread started");
    return 0;
}

void pf_capture_worker_stop(void)
{
    if (!atomic_exchange(&g_running, 0)) return;
    /* Wake the thread so it notices g_running==0. */
    if (g_queue && g_queue->eventfd >= 0) {
        uint64_t one = 1;
        (void)write(g_queue->eventfd, &one, sizeof(one));
    }
    pthread_join(g_thread, NULL);
    g_queue = NULL; g_cb = NULL; g_ud = NULL;
}
