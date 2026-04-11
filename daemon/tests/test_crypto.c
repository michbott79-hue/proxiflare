#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "proxiflare.h"
#include "crypto.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * Test helpers
 * ───────────────────────────────────────────────────────────────────────────── */

static int g_pass = 0;
static int g_fail = 0;

#define ASSERT(label, expr) do { \
    if (expr) { \
        printf("  [PASS] %s\n", label); \
        g_pass++; \
    } else { \
        printf("  [FAIL] %s  (line %d)\n", label, __LINE__); \
        g_fail++; \
    } \
} while (0)

/* ─────────────────────────────────────────────────────────────────────────────
 * Test 1: set_master + encrypt/decrypt roundtrip
 * ───────────────────────────────────────────────────────────────────────────── */
static void test_roundtrip(void)
{
    printf("\n=== test_roundtrip ===\n");

    pf_crypto_t ctx;
    pf_crypto_init(&ctx);

    int rc = pf_crypto_set_master(&ctx, "correct-horse-battery-staple", NULL);
    ASSERT("set_master returns PF_OK", rc == PF_OK);
    ASSERT("ctx.unlocked after set_master", ctx.unlocked == true);

    const uint8_t plaintext[] = "Hello, ProxiFlare! This is secret data.";
    size_t pt_len = sizeof(plaintext) - 1; /* exclude NUL */

    uint8_t ciphertext[256];
    size_t ct_len = 0;
    rc = pf_crypto_encrypt(&ctx, plaintext, pt_len, ciphertext, &ct_len);
    ASSERT("encrypt returns PF_OK", rc == PF_OK);

    uint8_t decrypted[256];
    size_t dec_len = 0;
    rc = pf_crypto_decrypt(&ctx, ciphertext, ct_len, decrypted, &dec_len);
    ASSERT("decrypt returns PF_OK", rc == PF_OK);
    ASSERT("decrypted length matches original", dec_len == pt_len);
    ASSERT("decrypted content matches original", memcmp(decrypted, plaintext, pt_len) == 0);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test 2: output size is correct (in_len + IV_LEN + TAG_LEN)
 * ───────────────────────────────────────────────────────────────────────────── */
static void test_output_size(void)
{
    printf("\n=== test_output_size ===\n");

    pf_crypto_t ctx;
    pf_crypto_init(&ctx);
    pf_crypto_set_master(&ctx, "size-test-password", NULL);

    const uint8_t data[] = "12345678901234567890"; /* 20 bytes */
    size_t data_len = sizeof(data) - 1;

    uint8_t out[256];
    size_t out_len = 0;
    int rc = pf_crypto_encrypt(&ctx, data, data_len, out, &out_len);
    ASSERT("encrypt returns PF_OK", rc == PF_OK);
    ASSERT("output size = in_len + IV_LEN + TAG_LEN",
           out_len == data_len + PF_IV_LEN + PF_TAG_LEN);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test 3: lock prevents encrypt and decrypt
 * ───────────────────────────────────────────────────────────────────────────── */
static void test_lock_prevents_ops(void)
{
    printf("\n=== test_lock_prevents_ops ===\n");

    pf_crypto_t ctx;
    pf_crypto_init(&ctx);
    pf_crypto_set_master(&ctx, "lock-test", NULL);

    /* encrypt something first, then lock */
    const uint8_t pt[] = "some data";
    uint8_t ct[256];
    size_t ct_len = 0;
    pf_crypto_encrypt(&ctx, pt, sizeof(pt) - 1, ct, &ct_len);

    pf_crypto_lock(&ctx);
    ASSERT("ctx.unlocked == false after lock", ctx.unlocked == false);

    /* try to encrypt while locked */
    uint8_t out[256];
    size_t out_len = 0;
    int rc = pf_crypto_encrypt(&ctx, pt, sizeof(pt) - 1, out, &out_len);
    ASSERT("encrypt while locked returns PF_ERR_LOCKED", rc == PF_ERR_LOCKED);

    /* try to decrypt while locked */
    uint8_t dec[256];
    size_t dec_len = 0;
    rc = pf_crypto_decrypt(&ctx, ct, ct_len, dec, &dec_len);
    ASSERT("decrypt while locked returns PF_ERR_LOCKED", rc == PF_ERR_LOCKED);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test 4: unlock with saved salt + same password → decrypt data encrypted before lock
 * ───────────────────────────────────────────────────────────────────────────── */
static void test_unlock_and_decrypt(void)
{
    printf("\n=== test_unlock_and_decrypt ===\n");

    pf_crypto_t ctx;
    pf_crypto_init(&ctx);
    pf_crypto_set_master(&ctx, "my-secret-password", NULL);

    /* Save salt before locking */
    uint8_t saved_salt[PF_SALT_LEN];
    memcpy(saved_salt, ctx.salt, PF_SALT_LEN);

    const uint8_t plaintext[] = "data encrypted before lock";
    size_t pt_len = sizeof(plaintext) - 1;

    uint8_t ciphertext[256];
    size_t ct_len = 0;
    pf_crypto_encrypt(&ctx, plaintext, pt_len, ciphertext, &ct_len);

    /* Lock */
    pf_crypto_lock(&ctx);
    ASSERT("locked", ctx.unlocked == false);

    /* Unlock with saved salt */
    int rc = pf_crypto_unlock(&ctx, "my-secret-password", saved_salt);
    ASSERT("unlock with saved salt returns PF_OK", rc == PF_OK);
    ASSERT("ctx.unlocked after unlock", ctx.unlocked == true);

    /* Decrypt */
    uint8_t decrypted[256];
    size_t dec_len = 0;
    rc = pf_crypto_decrypt(&ctx, ciphertext, ct_len, decrypted, &dec_len);
    ASSERT("decrypt after re-unlock returns PF_OK", rc == PF_OK);
    ASSERT("decrypted content matches original", memcmp(decrypted, plaintext, pt_len) == 0);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test 5: export encrypt/decrypt roundtrip with separate password
 * ───────────────────────────────────────────────────────────────────────────── */
static void test_export_roundtrip(void)
{
    printf("\n=== test_export_roundtrip ===\n");

    const uint8_t data[] = "exported config data: proxy=socks5://1.2.3.4:1080";
    size_t data_len = sizeof(data) - 1;

    /* Output buffer: salt + IV + ciphertext + tag */
    uint8_t exported[512];
    size_t  exp_len = 0;

    int rc = pf_crypto_export_encrypt("export-password-123", data, data_len, exported, &exp_len);
    ASSERT("export_encrypt returns PF_OK", rc == PF_OK);
    ASSERT("export_encrypt output size correct",
           exp_len == PF_SALT_LEN + data_len + PF_IV_LEN + PF_TAG_LEN);

    uint8_t recovered[512];
    size_t  rec_len = 0;
    rc = pf_crypto_export_decrypt("export-password-123", exported, exp_len, recovered, &rec_len);
    ASSERT("export_decrypt returns PF_OK", rc == PF_OK);
    ASSERT("recovered length matches original", rec_len == data_len);
    ASSERT("recovered content matches original", memcmp(recovered, data, data_len) == 0);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Test 6: wrong export password returns PF_ERR_AUTH
 * ───────────────────────────────────────────────────────────────────────────── */
static void test_wrong_export_password(void)
{
    printf("\n=== test_wrong_export_password ===\n");

    const uint8_t data[] = "sensitive export data";
    size_t data_len = sizeof(data) - 1;

    uint8_t exported[512];
    size_t  exp_len = 0;
    pf_crypto_export_encrypt("correct-export-pw", data, data_len, exported, &exp_len);

    uint8_t out[512];
    size_t  out_len = 0;
    int rc = pf_crypto_export_decrypt("wrong-export-pw", exported, exp_len, out, &out_len);
    ASSERT("wrong export password returns PF_ERR_AUTH", rc == PF_ERR_AUTH);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Main
 * ───────────────────────────────────────────────────────────────────────────── */
int main(void)
{
    printf("ProxiFlare crypto module tests\n");
    printf("(Argon2id key derivation takes a few seconds per test — please wait)\n");

    test_roundtrip();
    test_output_size();
    test_lock_prevents_ops();
    test_unlock_and_decrypt();
    test_export_roundtrip();
    test_wrong_export_password();

    printf("\n─────────────────────────────────────────\n");
    printf("Results: %d passed, %d failed\n", g_pass, g_fail);

    if (g_fail == 0) {
        printf("ALL CRYPTO TESTS PASSED\n");
        return 0;
    } else {
        printf("SOME TESTS FAILED\n");
        return 1;
    }
}
