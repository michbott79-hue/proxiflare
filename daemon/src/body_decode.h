#ifndef PF_BODY_DECODE_H
#define PF_BODY_DECODE_H

#include <stddef.h>

/* Decompress an HTTP body based on the Content-Encoding header value.
 *   encoding   — e.g. "gzip", "br", "zstd", or NULL/"" (= identity, copy)
 *   in / inlen — compressed bytes (may be identity)
 *   out        — caller-owned buffer of size *out_cap
 *   out_cap    — size of `out` (in). On success, *out_cap is set to decoded
 *                byte count actually written.
 *
 * Returns 0 on success, -1 on any failure (invalid format, unknown encoding,
 * buffer too small, library missing). On failure, *out_cap is left as input.
 *
 * When encoding is NULL/empty/"identity", the function copies up to *out_cap
 * bytes from in and sets *out_cap to the copied count, returning 0.
 *
 * The output is NOT NUL-terminated — callers using it as a C string must add
 * their own NUL within the returned length.
 */
int pf_body_decode(const char *encoding,
                   const void *in, size_t inlen,
                   void *out, size_t *out_cap);

#endif /* PF_BODY_DECODE_H */
