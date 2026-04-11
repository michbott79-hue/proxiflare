#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>

#include "sni.h"

int main(void)
{
    /* ── Test 1: Valid ClientHello with SNI "example.com" ── */

    /*
     * Layout (72 bytes total):
     *  [0]     0x16          ContentType: Handshake
     *  [1-2]   0x03 0x01     TLS 1.0
     *  [3-4]   record_len    (fill)
     *  [5]     0x01          ClientHello
     *  [6-8]   hs_body_len   (fill, 3 bytes big-endian)
     *  [9-10]  0x03 0x03     ClientVersion TLS 1.2
     *  [11-42] 32 zero bytes Random
     *  [43]    0x00          SessionID length = 0
     *  [44-45] 0x00 0x02     CipherSuites length = 2
     *  [46-47] 0x00 0x2f     TLS_RSA_WITH_AES_128_CBC_SHA
     *  [48]    0x01          CompressionMethods length = 1
     *  [49]    0x00          null compression
     *  [50-51] exts_len      Extensions total length (fill)
     *  [52-53] 0x00 0x00     Extension type: SNI
     *  [54-55] sni_ext_len   SNI extension data length (fill)
     *  [56-57] list_len      ServerNameList length (fill)
     *  [58]    0x00          NameType: host_name
     *  [59-60] 0x00 0x0b     HostName length = 11
     *  [61-71] "example.com"
     */
    uint8_t hello[] = {
        /* TLS Record Header */
        0x16,                               /* ContentType: Handshake */
        0x03, 0x01,                         /* Version: TLS 1.0 */
        0x00, 0x00,                         /* record length — filled below */
        /* Handshake Header */
        0x01,                               /* HandshakeType: ClientHello */
        0x00, 0x00, 0x00,                   /* handshake body length — filled below */
        /* ClientVersion */
        0x03, 0x03,                         /* TLS 1.2 */
        /* Random (32 bytes) */
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        /* SessionID */
        0x00,                               /* length: 0 */
        /* CipherSuites */
        0x00, 0x02,                         /* length: 2 bytes */
        0x00, 0x2f,                         /* TLS_RSA_WITH_AES_128_CBC_SHA */
        /* CompressionMethods */
        0x01,                               /* length: 1 */
        0x00,                               /* null */
        /* Extensions total length — filled below */
        0x00, 0x00,
        /* SNI Extension */
        0x00, 0x00,                         /* type: server_name (0x0000) */
        0x00, 0x00,                         /* ext data length — filled below */
        0x00, 0x00,                         /* ServerNameList length — filled below */
        0x00,                               /* NameType: host_name */
        0x00, 0x0b,                         /* HostName length: 11 */
        'e','x','a','m','p','l','e','.','c','o','m'
    };

    /*
     * Compute lengths bottom-up:
     *   name_len       = 11
     *   list_len       = 1 (name_type) + 2 (name_len field) + 11 = 14
     *   sni_ext_len    = 2 (list_len field) + list_len = 16
     *   exts_total     = 2 (ext_type) + 2 (ext_len field) + sni_ext_len = 20
     *   hs_body_len    = 2 (ClientVersion) + 32 (Random) + 1 (sid_len)
     *                  + 2 (cs_len field) + 2 (cipher) + 1 (cm_len) + 1 (null)
     *                  + 2 (exts_len field) + exts_total
     *                  = 2+32+1+2+2+1+1+2+20 = 63
     *   record_len     = 4 (hs header) + hs_body_len = 67
     *
     * Offsets of fields to patch:
     *   record_len    → [3-4]
     *   hs_body_len   → [6-8]
     *   exts_total    → [50-51]
     *   sni_ext_len   → [54-55]
     *   list_len      → [56-57]
     */
    const int name_len     = 11;
    const int list_len     = 1 + 2 + name_len;       /* 14 */
    const int sni_ext_len  = 2 + list_len;            /* 16 */
    const int exts_total   = 2 + 2 + sni_ext_len;    /* 20 */
    const int hs_body_len  = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + exts_total; /* 63 */
    const int record_len   = 4 + hs_body_len;         /* 67 */

    hello[3] = (uint8_t)((record_len >> 8) & 0xff);
    hello[4] = (uint8_t)(record_len & 0xff);

    hello[6] = (uint8_t)((hs_body_len >> 16) & 0xff);
    hello[7] = (uint8_t)((hs_body_len >> 8)  & 0xff);
    hello[8] = (uint8_t)(hs_body_len & 0xff);

    /* Extensions total length at [50-51] */
    hello[50] = (uint8_t)((exts_total >> 8) & 0xff);
    hello[51] = (uint8_t)(exts_total & 0xff);

    /* SNI ext data length at [54-55] */
    hello[54] = (uint8_t)((sni_ext_len >> 8) & 0xff);
    hello[55] = (uint8_t)(sni_ext_len & 0xff);

    /* ServerNameList length at [56-57] */
    hello[56] = (uint8_t)((list_len >> 8) & 0xff);
    hello[57] = (uint8_t)(list_len & 0xff);

    char hostname[256] = {0};
    int rc = pf_sni_extract(hello, sizeof(hello), hostname, sizeof(hostname));
    assert(rc == 11);
    assert(strcmp(hostname, "example.com") == 0);
    printf("PASS: extracted SNI 'example.com' from ClientHello\n");

    /* ── Test 2: Not TLS (HTTP) ── */
    {
        const uint8_t http[] = "GET / HTTP/1.1\r\n";
        rc = pf_sni_extract(http, sizeof(http) - 1, hostname, sizeof(hostname));
        assert(rc == 0);
        printf("PASS: non-TLS data returns 0\n");
    }

    /* ── Test 3: Truncated record (only 3 bytes — below the 5-byte minimum) ── */
    rc = pf_sni_extract(hello, 3, hostname, sizeof(hostname));
    assert(rc == 0);
    printf("PASS: truncated data returns 0\n");

    /* ── Test 4: NULL input ── */
    rc = pf_sni_extract(NULL, 0, hostname, sizeof(hostname));
    assert(rc == 0);
    printf("PASS: NULL input returns 0\n");

    /* ── Test 5: NULL output buffer ── */
    rc = pf_sni_extract(hello, sizeof(hello), NULL, 256);
    assert(rc == 0);
    printf("PASS: NULL output returns 0\n");

    /* ── Test 6: Output buffer too small — must truncate + NUL-terminate ── */
    char tiny[5] = {0};
    rc = pf_sni_extract(hello, sizeof(hello), tiny, sizeof(tiny));
    assert(rc == 4);                      /* copied 4, NUL at [4] */
    assert(tiny[4] == '\0');
    assert(memcmp(tiny, "exam", 4) == 0);
    printf("PASS: small output buffer truncates correctly\n");

    /* ── Test 7: Truncated mid-extensions (cuts off before ext data) ── */
    rc = pf_sni_extract(hello, 55, hostname, sizeof(hostname));
    assert(rc == 0);
    printf("PASS: truncated mid-extension returns 0\n");

    /* ── Test 8: TLS record with wrong handshake type (ServerHello = 0x02) ── */
    {
        uint8_t bad[sizeof(hello)];
        memcpy(bad, hello, sizeof(hello));
        bad[5] = 0x02;  /* ServerHello, not ClientHello */
        rc = pf_sni_extract(bad, sizeof(bad), hostname, sizeof(hostname));
        assert(rc == 0);
        printf("PASS: ServerHello (not ClientHello) returns 0\n");
    }

    printf("ALL SNI TESTS PASSED\n");
    return 0;
}
