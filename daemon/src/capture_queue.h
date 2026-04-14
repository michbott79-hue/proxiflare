/* ─────────────────────────────────────────────────────────────────────────────
 * capture_queue.h — MPSC queue between the TPROXY relay threads (producers)
 * and a single capture worker thread (consumer).
 *
 * The goal is to keep the relay hot path O(1) and lock-free-enough so that
 * enabling the MITM capture does not add user-visible latency to browsing.
 * Heavy work (HTTP parsing, gzip/brotli/zstd decompression, cJSON tree
 * building, ring-buffer insertion) is moved off the relay thread and onto
 * the capture worker.
 *
 * Implementation: a bounded ring of `pf_capture_msg_t *` protected by a
 * short-held mutex, with an `eventfd` for wake-up. The mutex is held for
 * ~100 ns per enqueue (bounds check + pointer store), which is negligible
 * compared to the ~μs cost of the `memcpy` that already has to happen on
 * the producer side to detach from the per-relay stack buffer.
 *
 * When the queue is full, enqueue drops the oldest undequeued message and
 * increments a dropped counter — capture fidelity is sacrificed to keep
 * the relay thread non-blocking. This only happens under extreme burst
 * load; under normal browsing the worker keeps up easily.
 * ─────────────────────────────────────────────────────────────────────────── */

#ifndef PF_CAPTURE_QUEUE_H
#define PF_CAPTURE_QUEUE_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>

/* Ring size — power of 2 so mask wrap is free. 4096 slots × 8 bytes
 * (pointer) = 32 KB overhead, with each referenced message averaging
 * ~1–4 KB of captured data. A few MB of in-flight queue is acceptable. */
#define PF_CAPTURE_QUEUE_BITS    12
#define PF_CAPTURE_QUEUE_SIZE    (1U << PF_CAPTURE_QUEUE_BITS)
#define PF_CAPTURE_QUEUE_MASK    (PF_CAPTURE_QUEUE_SIZE - 1)

/* One captured event. Owned by the queue between enqueue and free-in-worker.
 *
 * The byte payload is stored inline right after the struct — one allocation
 * per message, no separate body buffer. `data` points to `this + 1`.
 */
typedef struct pf_capture_msg {
    uint8_t     *data;             /* points to flex array after the struct */
    size_t       len;
    int          is_request;       /* 1 = client→server, 0 = response */
    int          is_tls;
    int          dst_port;
    uint64_t     conn_id;          /* per-connection id for stream grouping */
    uint64_t     ts_sec;
    char         domain[256];
    char         dst_ip[46];
} pf_capture_msg_t;

typedef struct pf_capture_queue {
    pthread_mutex_t    lock;
    uint32_t           head;        /* producer index; next slot to write */
    uint32_t           tail;        /* consumer index; next slot to read */
    pf_capture_msg_t  *slots[PF_CAPTURE_QUEUE_SIZE];
    int                eventfd;     /* consumer wakes on readable */
    _Atomic uint64_t   dropped;     /* running count of dropped messages */
    _Atomic uint64_t   enqueued;    /* running count of accepted messages */
} pf_capture_queue_t;

/* Initialise a zeroed queue. Returns 0 on success. */
int  pf_capture_queue_init (pf_capture_queue_t *q);

/* Release everything — any remaining messages are freed. */
void pf_capture_queue_close(pf_capture_queue_t *q);

/* Producer side. Steals ownership of `msg`; on drop the caller's message is
 * freed by the queue. Returns 0 on successful enqueue, -1 on drop.
 * Wakes the consumer via eventfd. Called from the TPROXY relay thread. */
int  pf_capture_queue_push (pf_capture_queue_t *q, pf_capture_msg_t *msg);

/* Consumer side. Blocks on eventfd until at least one message is ready,
 * then drains up to `max` messages into `out[]`. Returns the number
 * dequeued. Ownership of each message transfers to the caller (must free
 * via free()). */
int  pf_capture_queue_drain(pf_capture_queue_t *q,
                            pf_capture_msg_t **out, int max);

#endif /* PF_CAPTURE_QUEUE_H */
