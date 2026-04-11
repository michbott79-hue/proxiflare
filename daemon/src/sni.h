#ifndef PF_SNI_H
#define PF_SNI_H

#include <stdint.h>
#include <stddef.h>

/* Extract SNI hostname from TLS ClientHello.
   Returns length of hostname copied to out, or 0 if not found/not TLS.
   Read-only — does not modify packet data. */
int pf_sni_extract(const uint8_t *data, size_t len, char *out, size_t out_max);

#endif /* PF_SNI_H */
