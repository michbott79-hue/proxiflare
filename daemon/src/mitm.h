#ifndef PF_MITM_H
#define PF_MITM_H

#include "proxiflare.h"
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <pthread.h>

/* ──────────────────────────────────────────────────────────────────────────
 * Limits
 * ────────────────────────────────────────────────────────────────────────── */
#define PF_MITM_CERT_CACHE_SIZE  256
#define PF_MITM_CA_KEY_PATH      "/var/lib/proxiflare/ca.key"
#define PF_MITM_CA_CERT_PATH     "/var/lib/proxiflare/ca.crt"

/* ──────────────────────────────────────────────────────────────────────────
 * Cert cache entry
 * ────────────────────────────────────────────────────────────────────────── */
typedef struct {
    char         domain[PF_DOMAIN_MAX + 1];
    X509        *cert;
    EVP_PKEY    *key;
    time_t       created;
} pf_cert_cache_entry_t;

/* ──────────────────────────────────────────────────────────────────────────
 * MITM context
 * ────────────────────────────────────────────────────────────────────────── */
typedef struct {
    /* CA authority */
    EVP_PKEY    *ca_key;
    X509        *ca_cert;

    /* SSL contexts: one for server-side (presenting to client),
     * one for client-side (connecting to real server) */
    SSL_CTX     *server_ctx;   /* template — cert set per-connection via SNI callback */
    SSL_CTX     *client_ctx;   /* connects to real servers */

    /* Dynamic cert cache — protected by cache_lock (accessed from handshake threads) */
    pf_cert_cache_entry_t cache[PF_MITM_CERT_CACHE_SIZE];
    int          cache_count;
    pthread_mutex_t cache_lock;

    int          enabled;      /* global on/off toggle */
} pf_mitm_t;

/* ──────────────────────────────────────────────────────────────────────────
 * API
 * ────────────────────────────────────────────────────────────────────────── */

/* Generate a new CA key + self-signed cert. Saves to PF_MITM_CA_*_PATH.
 * Only needed once — if files already exist, returns PF_OK immediately. */
int pf_mitm_generate_ca(void);

/* Check if CA files exist */
int pf_mitm_ca_exists(void);

/* Initialize MITM subsystem — loads CA, creates SSL contexts */
int pf_mitm_init(pf_mitm_t *m);

/* Close MITM subsystem */
void pf_mitm_close(pf_mitm_t *m);

/* Get or create a cert+key pair for the given domain.
 * Returns OWNED references — caller MUST call X509_free / EVP_PKEY_free
 * (or transfer ownership to SSL via SSL_use_certificate / SSL_use_PrivateKey
 * which up-refs again; then still free these refs). */
int pf_mitm_get_cert(pf_mitm_t *m, const char *domain,
                     X509 **out_cert, EVP_PKEY **out_key);

/* Wrap an accepted client fd in TLS (server-side: daemon acts as server).
 * Uses a cert generated for 'domain'. Returns SSL* or NULL on error. */
SSL *pf_mitm_wrap_client(pf_mitm_t *m, int client_fd, const char *domain);

/* Wrap a proxy fd in TLS (client-side: daemon connects to real server).
 * Sets SNI to 'domain'. Returns SSL* or NULL on error. */
SSL *pf_mitm_wrap_server(pf_mitm_t *m, int proxy_fd, const char *domain);

#endif /* PF_MITM_H */
