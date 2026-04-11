#include "mitm.h"
#include "logger.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

/* ──────────────────────────────────────────────────────────────────────────
 * Internal helpers
 * ────────────────────────────────────────────────────────────────────────── */

static void log_ssl_errors(const char *ctx)
{
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        pf_log_error("mitm: %s: %s", ctx, buf);
    }
}

/* ──────────────────────────────────────────────────────────────────────────
 * pf_mitm_ca_exists
 * ────────────────────────────────────────────────────────────────────────── */

int pf_mitm_ca_exists(void)
{
    struct stat st;
    return (stat(PF_MITM_CA_KEY_PATH, &st) == 0 &&
            stat(PF_MITM_CA_CERT_PATH, &st) == 0) ? 1 : 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * pf_mitm_generate_ca — RSA 2048 CA key + self-signed cert (valid 10 years)
 * ────────────────────────────────────────────────────────────────────────── */

int pf_mitm_generate_ca(void)
{
    if (pf_mitm_ca_exists()) {
        pf_log_info("mitm: CA already exists at %s", PF_MITM_CA_CERT_PATH);
        return PF_OK;
    }

    EVP_PKEY *pkey = NULL;
    X509     *x509 = NULL;
    FILE     *fp   = NULL;
    int       rc   = PF_ERR;

    /* Generate RSA 2048 key */
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!kctx) goto fail;
    if (EVP_PKEY_keygen_init(kctx) <= 0) goto fail;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0) goto fail;
    if (EVP_PKEY_keygen(kctx, &pkey) <= 0) goto fail;
    EVP_PKEY_CTX_free(kctx);
    kctx = NULL;

    /* Create self-signed X509 cert */
    x509 = X509_new();
    if (!x509) goto fail;

    /* Version 3 (0-indexed) */
    X509_set_version(x509, 2);

    /* Random serial number */
    {
        uint8_t serial_bytes[16];
        RAND_bytes(serial_bytes, sizeof(serial_bytes));
        BIGNUM *bn = BN_bin2bn(serial_bytes, sizeof(serial_bytes), NULL);
        ASN1_INTEGER *asn1 = X509_get_serialNumber(x509);
        BN_to_ASN1_INTEGER(bn, asn1);
        BN_free(bn);
    }

    /* Validity: now → +10 years */
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 10L * 365 * 24 * 3600);

    /* Subject: CN=ProxiFlare CA */
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                (const unsigned char *)"ProxiFlare CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                (const unsigned char *)"ProxiFlare", -1, -1, 0);
    X509_set_issuer_name(x509, name); /* self-signed */

    /* Set public key */
    X509_set_pubkey(x509, pkey);

    /* Extensions: CA=TRUE, Key Usage */
    {
        X509V3_CTX v3ctx;
        X509V3_set_ctx_nodb(&v3ctx);
        X509V3_set_ctx(&v3ctx, x509, x509, NULL, NULL, 0);

        X509_EXTENSION *ext;
        ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_basic_constraints, "critical,CA:TRUE");
        if (ext) { X509_add_ext(x509, ext, -1); X509_EXTENSION_free(ext); }

        ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_key_usage,
                                   "critical,keyCertSign,cRLSign");
        if (ext) { X509_add_ext(x509, ext, -1); X509_EXTENSION_free(ext); }

        ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_subject_key_identifier, "hash");
        if (ext) { X509_add_ext(x509, ext, -1); X509_EXTENSION_free(ext); }
    }

    /* Sign with SHA-256 */
    if (!X509_sign(x509, pkey, EVP_sha256())) goto fail;

    /* Write key */
    fp = fopen(PF_MITM_CA_KEY_PATH, "w");
    if (!fp) {
        pf_log_error("mitm: cannot write CA key to %s", PF_MITM_CA_KEY_PATH);
        goto fail;
    }
    if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL)) goto fail;
    fclose(fp);
    chmod(PF_MITM_CA_KEY_PATH, 0600);

    /* Write cert */
    fp = fopen(PF_MITM_CA_CERT_PATH, "w");
    if (!fp) {
        pf_log_error("mitm: cannot write CA cert to %s", PF_MITM_CA_CERT_PATH);
        goto fail;
    }
    if (!PEM_write_X509(fp, x509)) goto fail;
    fclose(fp);
    fp = NULL;

    pf_log_info("mitm: CA generated — key: %s, cert: %s",
                PF_MITM_CA_KEY_PATH, PF_MITM_CA_CERT_PATH);
    rc = PF_OK;

fail:
    if (rc != PF_OK) log_ssl_errors("generate_ca");
    if (fp) fclose(fp);
    if (x509) X509_free(x509);
    if (pkey) EVP_PKEY_free(pkey);
    if (kctx) EVP_PKEY_CTX_free(kctx);
    return rc;
}

/* ──────────────────────────────────────────────────────────────────────────
 * generate_domain_cert — create a cert for a specific domain, signed by CA
 * ────────────────────────────────────────────────────────────────────────── */

static int generate_domain_cert(pf_mitm_t *m, const char *domain,
                                X509 **out_cert, EVP_PKEY **out_key)
{
    EVP_PKEY *pkey = NULL;
    X509     *cert = NULL;
    int       rc   = PF_ERR;

    /* Generate RSA 2048 key for this domain */
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!kctx) goto fail;
    if (EVP_PKEY_keygen_init(kctx) <= 0) goto fail;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0) goto fail;
    if (EVP_PKEY_keygen(kctx, &pkey) <= 0) goto fail;
    EVP_PKEY_CTX_free(kctx);
    kctx = NULL;

    cert = X509_new();
    if (!cert) goto fail;

    X509_set_version(cert, 2);

    /* Random serial */
    {
        uint8_t sb[16];
        RAND_bytes(sb, sizeof(sb));
        BIGNUM *bn = BN_bin2bn(sb, sizeof(sb), NULL);
        BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(cert));
        BN_free(bn);
    }

    /* Valid: now → +1 year */
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 365L * 24 * 3600);

    /* Subject: CN=domain */
    X509_NAME *subj = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
                                (const unsigned char *)domain, -1, -1, 0);

    /* Issuer: CA's subject name */
    X509_set_issuer_name(cert, X509_get_subject_name(m->ca_cert));

    /* Public key */
    X509_set_pubkey(cert, pkey);

    /* SAN extension: DNS:domain, DNS:*.domain */
    {
        X509V3_CTX v3ctx;
        X509V3_set_ctx_nodb(&v3ctx);
        X509V3_set_ctx(&v3ctx, m->ca_cert, cert, NULL, NULL, 0);

        char san[PF_DOMAIN_MAX * 2 + 32];
        snprintf(san, sizeof(san), "DNS:%s,DNS:*.%s", domain, domain);

        X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &v3ctx,
                                                    NID_subject_alt_name, san);
        if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
    }

    /* Sign with CA key */
    if (!X509_sign(cert, m->ca_key, EVP_sha256())) goto fail;

    *out_cert = cert;
    *out_key  = pkey;
    return PF_OK;

fail:
    log_ssl_errors("generate_domain_cert");
    if (cert) X509_free(cert);
    if (pkey) EVP_PKEY_free(pkey);
    if (kctx) EVP_PKEY_CTX_free(kctx);
    return rc;
}

/* ──────────────────────────────────────────────────────────────────────────
 * pf_mitm_init
 * ────────────────────────────────────────────────────────────────────────── */

int pf_mitm_init(pf_mitm_t *m)
{
    if (!m) return PF_ERR;
    memset(m, 0, sizeof(*m));

    if (!pf_mitm_ca_exists()) {
        pf_log_warn("mitm: CA not found — interception disabled. "
                     "Run 'proxiflare-daemon --generate-ca' to create one.");
        return PF_OK; /* not fatal — app works without MITM */
    }

    /* Load CA key */
    FILE *fp = fopen(PF_MITM_CA_KEY_PATH, "r");
    if (!fp) {
        pf_log_error("mitm: cannot open CA key %s", PF_MITM_CA_KEY_PATH);
        return PF_ERR;
    }
    m->ca_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!m->ca_key) {
        log_ssl_errors("load CA key");
        return PF_ERR;
    }

    /* Load CA cert */
    fp = fopen(PF_MITM_CA_CERT_PATH, "r");
    if (!fp) {
        pf_log_error("mitm: cannot open CA cert %s", PF_MITM_CA_CERT_PATH);
        return PF_ERR;
    }
    m->ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!m->ca_cert) {
        log_ssl_errors("load CA cert");
        return PF_ERR;
    }

    /* Server SSL context (for presenting certs to clients) */
    m->server_ctx = SSL_CTX_new(TLS_server_method());
    if (!m->server_ctx) {
        log_ssl_errors("SSL_CTX_new server");
        return PF_ERR;
    }
    SSL_CTX_set_min_proto_version(m->server_ctx, TLS1_2_VERSION);

    /* Client SSL context (for connecting to real servers) */
    m->client_ctx = SSL_CTX_new(TLS_client_method());
    if (!m->client_ctx) {
        log_ssl_errors("SSL_CTX_new client");
        return PF_ERR;
    }
    SSL_CTX_set_min_proto_version(m->client_ctx, TLS1_2_VERSION);
    /* Don't verify server cert — we're a proxy, we accept whatever the server sends */
    SSL_CTX_set_verify(m->client_ctx, SSL_VERIFY_NONE, NULL);

    m->enabled = 0; /* disabled by default until user enables */
    pf_log_info("mitm: engine initialized (CA loaded, disabled by default)");
    return PF_OK;
}

/* ──────────────────────────────────────────────────────────────────────────
 * pf_mitm_close
 * ────────────────────────────────────────────────────────────────────────── */

void pf_mitm_close(pf_mitm_t *m)
{
    if (!m) return;

    for (int i = 0; i < m->cache_count; i++) {
        if (m->cache[i].cert) X509_free(m->cache[i].cert);
        if (m->cache[i].key)  EVP_PKEY_free(m->cache[i].key);
    }

    if (m->server_ctx) SSL_CTX_free(m->server_ctx);
    if (m->client_ctx) SSL_CTX_free(m->client_ctx);
    if (m->ca_cert)    X509_free(m->ca_cert);
    if (m->ca_key)     EVP_PKEY_free(m->ca_key);

    memset(m, 0, sizeof(*m));
}

/* ──────────────────────────────────────────────────────────────────────────
 * pf_mitm_get_cert — cached cert lookup/generation
 * ────────────────────────────────────────────────────────────────────────── */

int pf_mitm_get_cert(pf_mitm_t *m, const char *domain,
                     X509 **out_cert, EVP_PKEY **out_key)
{
    if (!m || !domain || !m->ca_key) return PF_ERR;

    /* Search cache */
    for (int i = 0; i < m->cache_count; i++) {
        if (strcmp(m->cache[i].domain, domain) == 0) {
            *out_cert = m->cache[i].cert;
            *out_key  = m->cache[i].key;
            return PF_OK;
        }
    }

    /* Generate new cert */
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    if (generate_domain_cert(m, domain, &cert, &key) != PF_OK)
        return PF_ERR;

    /* Add to cache — evict oldest if full */
    int slot;
    if (m->cache_count < PF_MITM_CERT_CACHE_SIZE) {
        slot = m->cache_count++;
    } else {
        /* Evict oldest (slot 0), shift down */
        if (m->cache[0].cert) X509_free(m->cache[0].cert);
        if (m->cache[0].key)  EVP_PKEY_free(m->cache[0].key);
        memmove(&m->cache[0], &m->cache[1],
                sizeof(pf_cert_cache_entry_t) * (PF_MITM_CERT_CACHE_SIZE - 1));
        slot = PF_MITM_CERT_CACHE_SIZE - 1;
    }

    snprintf(m->cache[slot].domain, sizeof(m->cache[slot].domain), "%s", domain);
    m->cache[slot].cert    = cert;
    m->cache[slot].key     = key;
    m->cache[slot].created = time(NULL);

    *out_cert = cert;
    *out_key  = key;
    return PF_OK;
}

/* ──────────────────────────────────────────────────────────────────────────
 * pf_mitm_wrap_client — TLS server-side (daemon → client)
 * ────────────────────────────────────────────────────────────────────────── */

SSL *pf_mitm_wrap_client(pf_mitm_t *m, int client_fd, const char *domain)
{
    if (!m || !m->server_ctx || !m->ca_key || client_fd < 0) return NULL;

    /* Get/generate cert for this domain */
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    if (pf_mitm_get_cert(m, domain, &cert, &key) != PF_OK) {
        pf_log_error("mitm: failed to get cert for %s", domain);
        return NULL;
    }

    SSL *ssl = SSL_new(m->server_ctx);
    if (!ssl) {
        log_ssl_errors("SSL_new server");
        return NULL;
    }

    /* Set this connection's cert + key */
    if (SSL_use_certificate(ssl, cert) != 1 ||
        SSL_use_PrivateKey(ssl, key) != 1) {
        log_ssl_errors("SSL_use_certificate/key");
        SSL_free(ssl);
        return NULL;
    }

    SSL_set_fd(ssl, client_fd);

    /* Do the TLS handshake (server-side accept) */
    int ret = SSL_accept(ssl);
    if (ret != 1) {
        int err = SSL_get_error(ssl, ret);
        pf_log_error("mitm: SSL_accept failed for %s (err=%d)", domain, err);
        log_ssl_errors("SSL_accept");
        SSL_free(ssl);
        return NULL;
    }

    pf_log_info("mitm: TLS server handshake OK for %s", domain);
    return ssl;
}

/* ──────────────────────────────────────────────────────────────────────────
 * pf_mitm_wrap_server — TLS client-side (daemon → real server via proxy)
 * ────────────────────────────────────────────────────────────────────────── */

SSL *pf_mitm_wrap_server(pf_mitm_t *m, int proxy_fd, const char *domain)
{
    if (!m || !m->client_ctx || proxy_fd < 0) return NULL;

    SSL *ssl = SSL_new(m->client_ctx);
    if (!ssl) {
        log_ssl_errors("SSL_new client");
        return NULL;
    }

    SSL_set_fd(ssl, proxy_fd);

    /* Set SNI hostname */
    if (domain && domain[0])
        SSL_set_tlsext_host_name(ssl, domain);

    /* TLS handshake (client-side connect) */
    int ret = SSL_connect(ssl);
    if (ret != 1) {
        int err = SSL_get_error(ssl, ret);
        pf_log_error("mitm: SSL_connect failed for %s (err=%d)", domain, err);
        log_ssl_errors("SSL_connect");
        SSL_free(ssl);
        return NULL;
    }

    pf_log_info("mitm: TLS client handshake OK for %s", domain);
    return ssl;
}
