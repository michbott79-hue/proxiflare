#include "capture_queue.h"
#include "logger.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

int pf_capture_queue_init(pf_capture_queue_t *q)
{
    if (!q) return -1;
    memset(q, 0, sizeof(*q));
    if (pthread_mutex_init(&q->lock, NULL) != 0) return -1;
    /* Blocking eventfd: the consumer calls read() directly to wait. Each
     * producer write(1) bumps the counter; each consumer read() clears it
     * and returns the accumulated count. We don't use that count — we just
     * drain the queue until empty. No EFD_SEMAPHORE because we want to
     * coalesce many producer writes into a single consumer wake. */
    q->eventfd = eventfd(0, EFD_CLOEXEC);
    if (q->eventfd < 0) {
        pthread_mutex_destroy(&q->lock);
        return -1;
    }
    return 0;
}

void pf_capture_queue_close(pf_capture_queue_t *q)
{
    if (!q) return;
    pthread_mutex_lock(&q->lock);
    while (q->tail != q->head) {
        free(q->slots[q->tail & PF_CAPTURE_QUEUE_MASK]);
        q->slots[q->tail & PF_CAPTURE_QUEUE_MASK] = NULL;
        q->tail++;
    }
    pthread_mutex_unlock(&q->lock);
    if (q->eventfd >= 0) close(q->eventfd);
    pthread_mutex_destroy(&q->lock);
}

int pf_capture_queue_push(pf_capture_queue_t *q, pf_capture_msg_t *msg)
{
    if (!q || !msg) { free(msg); return -1; }

    pthread_mutex_lock(&q->lock);
    uint32_t used = q->head - q->tail;
    if (used >= PF_CAPTURE_QUEUE_SIZE) {
        /* Queue is full. Drop the OLDEST undequeued message — better to lose
         * stale data than to add latency to live browsing. */
        pf_capture_msg_t *drop = q->slots[q->tail & PF_CAPTURE_QUEUE_MASK];
        q->slots[q->tail & PF_CAPTURE_QUEUE_MASK] = NULL;
        q->tail++;
        atomic_fetch_add_explicit(&q->dropped, 1, memory_order_relaxed);
        free(drop);
    }
    q->slots[q->head & PF_CAPTURE_QUEUE_MASK] = msg;
    q->head++;
    atomic_fetch_add_explicit(&q->enqueued, 1, memory_order_relaxed);
    pthread_mutex_unlock(&q->lock);

    /* Wake the consumer. Ignore EAGAIN (counter saturated at UINT64_MAX-1 —
     * the consumer will still drain on its next wake). */
    uint64_t one = 1;
    ssize_t wr = write(q->eventfd, &one, sizeof(one));
    (void)wr;
    return 0;
}

int pf_capture_queue_drain(pf_capture_queue_t *q,
                           pf_capture_msg_t **out, int max)
{
    if (!q || !out || max <= 0) return 0;

    /* NOTE: we do NOT read the eventfd here. The eventfd is a pure wake
     * signal owned by the consumer's outer loop — the consumer reads it
     * once, then keeps calling drain() until we return 0. Reading the
     * eventfd inside drain would block the consumer when the queue is
     * empty, which in turn blocks producers waiting for the mutex
     * inside push(), collapsing the whole point of the decoupling. */

    int got = 0;
    pthread_mutex_lock(&q->lock);
    while (got < max && q->tail != q->head) {
        out[got++] = q->slots[q->tail & PF_CAPTURE_QUEUE_MASK];
        q->slots[q->tail & PF_CAPTURE_QUEUE_MASK] = NULL;
        q->tail++;
    }
    pthread_mutex_unlock(&q->lock);
    return got;
}
