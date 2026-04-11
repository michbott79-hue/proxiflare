#ifndef PF_CRYPTO_H
#define PF_CRYPTO_H

#include "proxiflare.h"
#include <stddef.h>
#include <stdbool.h>

#define PF_SALT_LEN 16
#define PF_IV_LEN   12
#define PF_TAG_LEN  16
#define PF_KEY_LEN  32  /* AES-256 */

typedef struct {
    uint8_t key[PF_KEY_LEN];
    uint8_t salt[PF_SALT_LEN];
    bool    unlocked;
} pf_crypto_t;

int  pf_crypto_init(pf_crypto_t *ctx);
int  pf_crypto_set_master(pf_crypto_t *ctx, const char *password, const uint8_t *salt);
int  pf_crypto_unlock(pf_crypto_t *ctx, const char *password, const uint8_t *salt);
void pf_crypto_lock(pf_crypto_t *ctx);
int  pf_crypto_encrypt(pf_crypto_t *ctx, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);
int  pf_crypto_decrypt(pf_crypto_t *ctx, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);
int  pf_crypto_random_salt(uint8_t *salt, size_t len);
int  pf_crypto_export_encrypt(const char *password, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);
int  pf_crypto_export_decrypt(const char *password, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);

#endif /* PF_CRYPTO_H */
