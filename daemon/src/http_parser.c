#include "http_parser.h"
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>

/* ──────────────────────────────────────────────────────────────────────────
 * Internal: find \r\n\r\n boundary (end of headers)
 * Returns offset past the boundary, or 0 if not found.
 * ────────────────────────────────────────────────────────────────────────── */

static size_t find_header_end(const char *buf, size_t len)
{
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n' &&
            buf[i+2] == '\r' && buf[i+3] == '\n')
            return i + 4;
    }
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Internal: parse headers from after the first line until \r\n\r\n
 * ────────────────────────────────────────────────────────────────────────── */

static int parse_headers(const char *start, size_t len, pf_http_msg_t *msg)
{
    const char *p   = start;
    const char *end = start + len;

    msg->header_count = 0;

    while (p < end && msg->header_count < PF_HTTP_MAX_HEADERS) {
        /* End of headers */
        if (p[0] == '\r' && p + 1 < end && p[1] == '\n')
            break;

        /* Find end of this header line */
        const char *eol = memchr(p, '\r', (size_t)(end - p));
        if (!eol) break;

        /* Find colon separator */
        const char *colon = memchr(p, ':', (size_t)(eol - p));
        if (!colon) { p = eol + 2; continue; }

        pf_http_header_t *h = &msg->headers[msg->header_count];

        /* Key */
        size_t klen = (size_t)(colon - p);
        if (klen >= sizeof(h->key)) klen = sizeof(h->key) - 1;
        memcpy(h->key, p, klen);
        h->key[klen] = '\0';

        /* Value (skip ": " prefix whitespace) */
        const char *val = colon + 1;
        while (val < eol && (*val == ' ' || *val == '\t')) val++;
        size_t vlen = (size_t)(eol - val);
        if (vlen >= sizeof(h->value)) vlen = sizeof(h->value) - 1;
        memcpy(h->value, val, vlen);
        h->value[vlen] = '\0';

        msg->header_count++;
        p = eol + 2; /* skip \r\n */
    }

    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * pf_http_parse_request
 * ────────────────────────────────────────────────────────────────────────── */

int pf_http_parse_request(const char *buf, size_t len, pf_http_msg_t *msg)
{
    if (!buf || !msg || len < 10) return -1;

    memset(msg, 0, sizeof(*msg));
    msg->is_request = 1;

    /* Find header boundary */
    size_t hend = find_header_end(buf, len);
    if (hend == 0) return -1; /* incomplete */
    msg->header_end = hend;
    msg->complete = 1;

    /* Parse request line: METHOD SP URL SP VERSION\r\n */
    const char *eol = memchr(buf, '\r', len);
    if (!eol) return -1;

    const char *p = buf;

    /* Method */
    const char *sp1 = memchr(p, ' ', (size_t)(eol - p));
    if (!sp1) return -1;
    size_t mlen = (size_t)(sp1 - p);
    if (mlen >= sizeof(msg->method)) mlen = sizeof(msg->method) - 1;
    memcpy(msg->method, p, mlen);

    /* URL */
    p = sp1 + 1;
    const char *sp2 = memchr(p, ' ', (size_t)(eol - p));
    if (!sp2) return -1;
    size_t ulen = (size_t)(sp2 - p);
    if (ulen >= sizeof(msg->url)) ulen = sizeof(msg->url) - 1;
    memcpy(msg->url, p, ulen);

    /* Version */
    p = sp2 + 1;
    size_t vlen = (size_t)(eol - p);
    if (vlen >= sizeof(msg->version)) vlen = sizeof(msg->version) - 1;
    memcpy(msg->version, p, vlen);

    /* Parse headers (start after first \r\n) */
    parse_headers(eol + 2, hend - (size_t)(eol + 2 - buf), msg);

    /* Content-Length */
    const char *cl = pf_http_get_header(msg, "Content-Length");
    if (cl) msg->content_length = (size_t)atol(cl);

    /* Body pointer */
    if (hend < len) {
        msg->body = buf + hend;
        msg->body_len = len - hend;
        if (msg->body_len > PF_HTTP_MAX_BODY_LEN)
            msg->body_len = PF_HTTP_MAX_BODY_LEN;
    }

    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * pf_http_parse_response
 * ────────────────────────────────────────────────────────────────────────── */

int pf_http_parse_response(const char *buf, size_t len, pf_http_msg_t *msg)
{
    if (!buf || !msg || len < 10) return -1;

    memset(msg, 0, sizeof(*msg));
    msg->is_request = 0;

    size_t hend = find_header_end(buf, len);
    if (hend == 0) return -1;
    msg->header_end = hend;
    msg->complete = 1;

    /* Parse status line: HTTP/X.Y SP STATUS SP TEXT\r\n */
    const char *eol = memchr(buf, '\r', len);
    if (!eol) return -1;

    const char *p = buf;

    /* Version */
    const char *sp1 = memchr(p, ' ', (size_t)(eol - p));
    if (!sp1) return -1;
    size_t vlen = (size_t)(sp1 - p);
    if (vlen >= sizeof(msg->version)) vlen = sizeof(msg->version) - 1;
    memcpy(msg->version, p, vlen);

    /* Status code */
    p = sp1 + 1;
    msg->status_code = (int)strtol(p, NULL, 10);

    /* Status text */
    const char *sp2 = memchr(p, ' ', (size_t)(eol - p));
    if (sp2) {
        p = sp2 + 1;
        size_t tlen = (size_t)(eol - p);
        if (tlen >= sizeof(msg->status_text)) tlen = sizeof(msg->status_text) - 1;
        memcpy(msg->status_text, p, tlen);
    }

    parse_headers(eol + 2, hend - (size_t)(eol + 2 - buf), msg);

    const char *cl = pf_http_get_header(msg, "Content-Length");
    if (cl) msg->content_length = (size_t)atol(cl);

    if (hend < len) {
        msg->body = buf + hend;
        msg->body_len = len - hend;
        if (msg->body_len > PF_HTTP_MAX_BODY_LEN)
            msg->body_len = PF_HTTP_MAX_BODY_LEN;
    }

    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * pf_http_get_header — case-insensitive header lookup
 * ────────────────────────────────────────────────────────────────────────── */

const char *pf_http_get_header(const pf_http_msg_t *msg, const char *key)
{
    if (!msg || !key) return NULL;
    for (int i = 0; i < msg->header_count; i++) {
        if (strcasecmp(msg->headers[i].key, key) == 0)
            return msg->headers[i].value;
    }
    return NULL;
}
