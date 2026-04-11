#include "sni.h"

#include <string.h>

/* ──────────────────────────────────────────────────────────────────────────
 * Bounds-safe byte reads
 * ────────────────────────────────────────────────────────────────────────── */
#define CHECK(off, need)  do { if ((size_t)(off) + (size_t)(need) > len) return 0; } while (0)
#define U8(off)           (data[(off)])
#define U16BE(off)        ((uint16_t)(((uint16_t)data[(off)] << 8) | data[(off) + 1]))
#define U24BE(off)        ((uint32_t)(((uint32_t)data[(off)] << 16) | \
                                      ((uint32_t)data[(off)+1] << 8) | \
                                       data[(off)+2]))

/* ──────────────────────────────────────────────────────────────────────────
 * TLS record / handshake constants
 * ────────────────────────────────────────────────────────────────────────── */
#define TLS_CONTENT_HANDSHAKE   0x16
#define TLS_HS_CLIENT_HELLO     0x01
#define TLS_EXT_SNI             0x0000
#define TLS_SNI_TYPE_HOST       0x00

/* Minimum version byte that looks like TLS (major == 3) */
#define TLS_VERSION_MAJOR       0x03

/* ──────────────────────────────────────────────────────────────────────────
 * pf_sni_extract
 *
 * Parses the on-wire TLS record to pull the SNI hostname out of the
 * server_name extension in a ClientHello message.  Every read is guarded
 * by an explicit bounds check; any malformed/truncated input causes an
 * immediate return of 0.
 * ────────────────────────────────────────────────────────────────────────── */
int pf_sni_extract(const uint8_t *data, size_t len, char *out, size_t out_max)
{
    if (!data || !out || out_max == 0)
        return 0;

    /* ── TLS Record header (5 bytes) ── */
    CHECK(0, 5);

    if (U8(0) != TLS_CONTENT_HANDSHAKE)
        return 0;

    /* Version major byte must be 3 (TLS 1.0 / 1.1 / 1.2 / 1.3) */
    if (U8(1) != TLS_VERSION_MAJOR)
        return 0;

    uint16_t record_len = U16BE(3);

    /* The record payload starts at offset 5; ensure it fits in our buffer */
    CHECK(5, record_len);

    /* ── Handshake header (4 bytes: type + 3-byte length) ── */
    /* offset 5 */
    CHECK(5, 4);

    if (U8(5) != TLS_HS_CLIENT_HELLO)
        return 0;

    (void)U24BE(6);  /* handshake body length — we use record_len + offset bounds */

    /* ── ClientHello body starts at offset 9 ── */
    size_t off = 9;

    /* ClientVersion (2 bytes) */
    CHECK(off, 2);
    off += 2;

    /* Random (32 bytes) */
    CHECK(off, 32);
    off += 32;

    /* SessionID length (1 byte) + SessionID */
    CHECK(off, 1);
    uint8_t sid_len = U8(off);
    off += 1;
    CHECK(off, sid_len);
    off += sid_len;

    /* CipherSuites length (2 bytes) + suites */
    CHECK(off, 2);
    uint16_t cs_len = U16BE(off);
    off += 2;
    CHECK(off, cs_len);
    off += cs_len;

    /* CompressionMethods length (1 byte) + methods */
    CHECK(off, 1);
    uint8_t cm_len = U8(off);
    off += 1;
    CHECK(off, cm_len);
    off += cm_len;

    /* Extensions total length (2 bytes) — optional if ClientHello is short */
    CHECK(off, 2);
    uint16_t exts_total = U16BE(off);
    off += 2;

    /* Sanity: make sure the extension block is within the buffer */
    CHECK(off, exts_total);

    size_t exts_end = off + exts_total;

    /* ── Iterate extensions ── */
    while (off + 4 <= exts_end) {
        uint16_t ext_type = U16BE(off);
        off += 2;
        uint16_t ext_len  = U16BE(off);
        off += 2;

        /* Ensure extension data fits */
        if (off + ext_len > exts_end)
            return 0;

        if (ext_type == TLS_EXT_SNI) {
            /* SNI extension body:
             *   [0-1]  ServerNameList length (2 bytes)
             *   [2]    NameType  (1 byte, 0x00 = host_name)
             *   [3-4]  HostName length (2 bytes)
             *   [5..]  HostName bytes
             */
            size_t sni_off = off;
            size_t sni_end = off + ext_len;

            /* ServerNameList length */
            if (sni_off + 2 > sni_end)
                return 0;
            /* uint16_t list_len = U16BE(sni_off); — not needed further */
            sni_off += 2;

            /* NameType */
            if (sni_off + 1 > sni_end)
                return 0;
            if (U8(sni_off) != TLS_SNI_TYPE_HOST)
                return 0;
            sni_off += 1;

            /* HostName length */
            if (sni_off + 2 > sni_end)
                return 0;
            uint16_t name_len = U16BE(sni_off);
            sni_off += 2;

            /* HostName bytes */
            if (sni_off + name_len > sni_end)
                return 0;
            if (name_len == 0)
                return 0;

            /* Copy to caller buffer, truncate if necessary, always NUL-terminate */
            size_t copy_len = name_len;
            if (copy_len >= out_max)
                copy_len = out_max - 1;

            memcpy(out, data + sni_off, copy_len);
            out[copy_len] = '\0';

            return (int)copy_len;
        }

        off += ext_len;
    }

    /* SNI extension not present */
    return 0;
}
