/* ─────────────────────────────────────────────────────────────────────────────
 * body_decode.c — Decompress HTTP bodies (gzip / brotli / zstd) for capture.
 *
 * Called from on_inspect_data() so the stored body is always readable text
 * (JSON/HTML/XML) rather than opaque compressed bytes. Matches the standard
 * behaviour of mitmproxy/Charles/Burp which decode on capture, not on view.
 * ───────────────────────────────────────────────────────────────────────────── */

#include "body_decode.h"

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <zlib.h>
#include <brotli/decode.h>
#include <zstd.h>

static int copy_identity(const void *in, size_t inlen,
                         void *out, size_t *out_cap)
{
    size_t n = inlen < *out_cap ? inlen : *out_cap;
    memcpy(out, in, n);
    *out_cap = n;
    return 0;
}

static int decode_gzip(const void *in, size_t inlen,
                       void *out, size_t *out_cap)
{
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    /* windowBits = 15 + 32 → auto-detect gzip or zlib-wrapped deflate.
     * This makes us lenient when a server mislabels "deflate" as zlib. */
    if (inflateInit2(&zs, 15 + 32) != Z_OK) return -1;

    zs.next_in   = (Bytef *)in;
    zs.avail_in  = (uInt)inlen;
    zs.next_out  = (Bytef *)out;
    zs.avail_out = (uInt)(*out_cap);

    int rc = inflate(&zs, Z_FINISH);
    size_t produced = *out_cap - zs.avail_out;
    inflateEnd(&zs);

    /* Z_STREAM_END means success; Z_BUF_ERROR with some output means truncation
     * (output buffer too small) which we still accept — better a truncated
     * readable prefix than a "decompression failed" hole. */
    if (rc != Z_STREAM_END && !(rc == Z_BUF_ERROR && produced > 0)) return -1;
    *out_cap = produced;
    return 0;
}

static int decode_brotli(const void *in, size_t inlen,
                         void *out, size_t *out_cap)
{
    size_t produced = *out_cap;
    BrotliDecoderResult rc =
        BrotliDecoderDecompress(inlen, (const uint8_t *)in,
                                &produced, (uint8_t *)out);
    /* SUCCESS = complete decode; NEEDS_MORE_OUTPUT = truncated but we keep
     * what we got (same rationale as gzip). */
    if (rc != BROTLI_DECODER_RESULT_SUCCESS &&
        rc != BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) return -1;
    *out_cap = produced;
    return 0;
}

static int decode_zstd(const void *in, size_t inlen,
                       void *out, size_t *out_cap)
{
    /* ZSTD_decompress succeeds for complete frames; for truncated output we
     * fall back to streaming to capture as much as fits in *out_cap. */
    size_t n = ZSTD_decompress(out, *out_cap, in, inlen);
    if (!ZSTD_isError(n)) {
        *out_cap = n;
        return 0;
    }
    /* Streaming path for partial decode */
    ZSTD_DCtx *dctx = ZSTD_createDCtx();
    if (!dctx) return -1;
    ZSTD_inBuffer  zin  = { in, inlen, 0 };
    ZSTD_outBuffer zout = { out, *out_cap, 0 };
    size_t rc;
    do {
        rc = ZSTD_decompressStream(dctx, &zout, &zin);
    } while (!ZSTD_isError(rc) && rc != 0 &&
             zout.pos < zout.size && zin.pos < zin.size);
    ZSTD_freeDCtx(dctx);
    if (zout.pos == 0) return -1;
    *out_cap = zout.pos;
    return 0;
}

int pf_body_decode(const char *encoding,
                   const void *in, size_t inlen,
                   void *out, size_t *out_cap)
{
    if (!out || !out_cap || *out_cap == 0) return -1;
    if (!in || inlen == 0) { *out_cap = 0; return 0; }

    if (!encoding || !encoding[0] ||
        strcasecmp(encoding, "identity") == 0)
        return copy_identity(in, inlen, out, out_cap);

    /* Some servers send "gzip, ..." or multi-coding — try the first token. */
    if (strncasecmp(encoding, "gzip", 4) == 0 ||
        strncasecmp(encoding, "x-gzip", 6) == 0 ||
        strncasecmp(encoding, "deflate", 7) == 0)
        return decode_gzip(in, inlen, out, out_cap);

    if (strncasecmp(encoding, "br", 2) == 0)
        return decode_brotli(in, inlen, out, out_cap);

    if (strncasecmp(encoding, "zstd", 4) == 0)
        return decode_zstd(in, inlen, out, out_cap);

    /* Unknown encoding — keep compressed bytes so the user at least sees
     * something and knows an unhandled codec was in play. */
    return copy_identity(in, inlen, out, out_cap);
}
