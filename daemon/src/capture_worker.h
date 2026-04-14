/* ─────────────────────────────────────────────────────────────────────────────
 * capture_worker.h — single consumer thread that drains the capture queue
 * and invokes a user-provided processing callback off the relay hot path.
 *
 * Lifetime: start once at daemon init, stop cleanly at shutdown. The worker
 * owns no application state — the callback is responsible for HTTP parsing,
 * decompression, JSON construction, and ring-buffer insertion. This keeps
 * the queue/worker pair application-agnostic and cheap to test.
 * ─────────────────────────────────────────────────────────────────────────── */

#ifndef PF_CAPTURE_WORKER_H
#define PF_CAPTURE_WORKER_H

#include "capture_queue.h"

/* Called once per dequeued message. The callback takes ownership of the
 * message and MUST free() it before returning. `ud` is the arbitrary
 * user-data pointer registered at start time. */
typedef void (*pf_capture_process_fn)(pf_capture_msg_t *msg, void *ud);

/* Spawns the worker thread. Non-zero return on failure. */
int  pf_capture_worker_start(pf_capture_queue_t *q,
                             pf_capture_process_fn cb, void *ud);

/* Signals the worker to exit and joins the thread. Safe even if not started. */
void pf_capture_worker_stop(void);

#endif /* PF_CAPTURE_WORKER_H */
