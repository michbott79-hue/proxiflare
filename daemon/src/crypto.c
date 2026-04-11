#include "crypto.h"
#include "proxiflare.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <argon2.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* Argon2id parameters */
#define ARGON2_T_COST    3
#define ARGON2_M_COST    (64 * 1024)  /* 64 MB */
#define ARGON2_PARALLELISM 4

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal: derive key from password + salt via Argon2id
 * ───────────────────────────────────────────────────────────────────────────── */
static int derive_key(uint8_t *key, const char *password, const uint8_t *salt)
{
    int rc = argon2id_hash_raw(
        ARGON2_T_COST,
        ARGON2_M_COST,
        ARGON2_PARALLELISM,
        password, strlen(password),
        salt, PF_SALT_LEN,
        key, PF_KEY_LEN
    );
    if (rc != ARGON2_OK)
        return PF_ERR_CRYPTO;
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_crypto_init
 * ───────────────────────────────────────────────────────────────────────────── */
int pf_crypto_init(pf_crypto_t *ctx)
{
    if (!ctx)
        return PF_ERR;
    memset(ctx, 0, sizeof(*ctx));
    ctx->unlocked = false;
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_crypto_random_salt
 * ───────────────────────────────────────────────────────────────────────────── */
int pf_crypto_random_salt(uint8_t *salt, size_t len)
{
    if (!salt || len == 0)
        return PF_ERR;
    if (RAND_bytes(salt, (int)len) != 1)
        return PF_ERR_CRYPTO;
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_crypto_set_master
 * If salt is NULL, generate a random one.
 * ───────────────────────────────────────────────────────────────────────────── */
int pf_crypto_set_master(pf_crypto_t *ctx, const char *password, const uint8_t *salt)
{
    if (!ctx || !password)
        return PF_ERR;

    if (salt == NULL) {
        if (pf_crypto_random_salt(ctx->salt, PF_SALT_LEN) != PF_OK)
            return PF_ERR_CRYPTO;
    } else {
        memcpy(ctx->salt, salt, PF_SALT_LEN);
    }

    int rc = derive_key(ctx->key, password, ctx->salt);
    if (rc != PF_OK)
        return rc;

    ctx->unlocked = true;
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_crypto_unlock
 * ───────────────────────────────────────────────────────────────────────────── */
int pf_crypto_unlock(pf_crypto_t *ctx, const char *password, const uint8_t *salt)
{
    if (!ctx || !password || !salt)
        return PF_ERR;

    memcpy(ctx->salt, salt, PF_SALT_LEN);

    int rc = derive_key(ctx->key, password, ctx->salt);
    if (rc != PF_OK)
        return rc;

    ctx->unlocked = true;
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_crypto_lock
 * ───────────────────────────────────────────────────────────────────────────── */
void pf_crypto_lock(pf_crypto_t *ctx)
{
    if (!ctx)
        return;
    explicit_bzero(ctx->key, PF_KEY_LEN);
    ctx->unlocked = false;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_crypto_encrypt
 * Output: [12-byte IV][ciphertext][16-byte tag]
 * ───────────────────────────────────────────────────────────────────────────── */
int pf_crypto_encrypt(pf_crypto_t *ctx, const uint8_t *in, size_t in_len,
                      uint8_t *out, size_t *out_len)
{
    if (!ctx || !in || !out || !out_len)
        return PF_ERR;
    if (!ctx->unlocked)
        return PF_ERR_LOCKED;

    /* Generate random IV */
    uint8_t iv[PF_IV_LEN];
    if (RAND_bytes(iv, PF_IV_LEN) != 1)
        return PF_ERR_CRYPTO;

    EVP_CIPHER_CTX *evp = EVP_CIPHER_CTX_new();
    if (!evp)
        return PF_ERR_CRYPTO;

    int rc = PF_OK;
    int len = 0;

    if (EVP_EncryptInit_ex(evp, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        { rc = PF_ERR_CRYPTO; goto cleanup; }

    if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, PF_IV_LEN, NULL) != 1)
        { rc = PF_ERR_CRYPTO; goto cleanup; }

    if (EVP_EncryptInit_ex(evp, NULL, NULL, ctx->key, iv) != 1)
        { rc = PF_ERR_CRYPTO; goto cleanup; }

    /* Write IV to output first */
    memcpy(out, iv, PF_IV_LEN);
    uint8_t *ciphertext = out + PF_IV_LEN;

    if (EVP_EncryptUpdate(evp, ciphertext, &len, in, (int)in_len) != 1)
        { rc = PF_ERR_CRYPTO; goto cleanup; }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(evp, ciphertext + len, &final_len) != 1)
        { rc = PF_ERR_CRYPTO; goto cleanup; }

    /* Append tag */
    uint8_t *tag = ciphertext + len + final_len;
    if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_GET_TAG, PF_TAG_LEN, tag) != 1)
        { rc = PF_ERR_CRYPTO; goto cleanup; }

    *out_len = PF_IV_LEN + (size_t)(len + final_len) + PF_TAG_LEN;

cleanup:
    EVP_CIPHER_CTX_free(evp);
    return rc;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_crypto_decrypt
 * Input: [12-byte IV][ciphertext][16-byte tag]
 * ───────────────────────────────────────────────────────────────────────────── */
int pf_crypto_decrypt(pf_crypto_t *ctx, const uint8_t *in, size_t in_len,
                      uint8_t *out, size_t *out_len)
{
    if (!ctx || !in || !out || !out_len)
        return PF_ERR;
    if (!ctx->unlocked)
        return PF_ERR_LOCKED;
    if (in_len < (size_t)(PF_IV_LEN + PF_TAG_LEN))
        return PF_ERR_CRYPTO;

    const uint8_t *iv         = in;
    const uint8_t *ciphertext = in + PF_IV_LEN;
    size_t         ct_len     = in_len - PF_IV_LEN - PF_TAG_LEN;
    const uint8_t *tag        = in + PF_IV_LEN + ct_len;

    EVP_CIPHER_CTX *evp = EVP_CIPHER_CTX_new();
    if (!evp)
        return PF_ERR_CRYPTO;

    int rc = PF_OK;
    int len = 0;

    if (EVP_DecryptInit_ex(evp, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        { rc = PF_ERR_CRYPTO; goto cleanup; }

    if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, PF_IV_LEN, NULL) != 1)
        { rc = PF_ERR_CRYPTO; goto cleanup; }

    if (EVP_DecryptInit_ex(evp, NULL, NULL, ctx->key, iv) != 1)
        { rc = PF_ERR_CRYPTO; goto cleanup; }

    if (EVP_DecryptUpdate(evp, out, &len, ciphertext, (int)ct_len) != 1)
        { rc = PF_ERR_CRYPTO; goto cleanup; }

    /* Set expected tag before Final */
    if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_TAG, PF_TAG_LEN, (void *)tag) != 1)
        { rc = PF_ERR_CRYPTO; goto cleanup; }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(evp, out + len, &final_len) <= 0) {
        rc = PF_ERR_AUTH;
        goto cleanup;
    }

    *out_len = (size_t)(len + final_len);

cleanup:
    EVP_CIPHER_CTX_free(evp);
    return rc;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_crypto_export_encrypt
 * Output: [16-byte salt][IV+ciphertext+tag]
 * ───────────────────────────────────────────────────────────────────────────── */
int pf_crypto_export_encrypt(const char *password, const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t *out_len)
{
    if (!password || !in || !out || !out_len)
        return PF_ERR;

    pf_crypto_t ctx;
    pf_crypto_init(&ctx);

    /* set_master generates random salt if NULL */
    int rc = pf_crypto_set_master(&ctx, password, NULL);
    if (rc != PF_OK)
        goto cleanup;

    /* Write salt first */
    memcpy(out, ctx.salt, PF_SALT_LEN);

    size_t enc_len = 0;
    rc = pf_crypto_encrypt(&ctx, in, in_len, out + PF_SALT_LEN, &enc_len);
    if (rc != PF_OK)
        goto cleanup;

    *out_len = PF_SALT_LEN + enc_len;

cleanup:
    pf_crypto_lock(&ctx);
    return rc;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_crypto_export_decrypt
 * Input: [16-byte salt][IV+ciphertext+tag]
 * ───────────────────────────────────────────────────────────────────────────── */
int pf_crypto_export_decrypt(const char *password, const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t *out_len)
{
    if (!password || !in || !out || !out_len)
        return PF_ERR;
    if (in_len < (size_t)(PF_SALT_LEN + PF_IV_LEN + PF_TAG_LEN))
        return PF_ERR_CRYPTO;

    const uint8_t *salt = in;
    const uint8_t *enc  = in + PF_SALT_LEN;
    size_t         enc_len = in_len - PF_SALT_LEN;

    pf_crypto_t ctx;
    pf_crypto_init(&ctx);

    int rc = pf_crypto_unlock(&ctx, password, salt);
    if (rc != PF_OK)
        goto cleanup;

    rc = pf_crypto_decrypt(&ctx, enc, enc_len, out, out_len);

cleanup:
    pf_crypto_lock(&ctx);
    return rc;
}
