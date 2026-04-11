#ifndef PF_HTTP_PARSER_H
#define PF_HTTP_PARSER_H

#include <stddef.h>
#include <stdint.h>

#define PF_HTTP_MAX_HEADERS     64
#define PF_HTTP_MAX_HEADER_LEN  4096
#define PF_HTTP_MAX_URL_LEN     2048
#define PF_HTTP_MAX_BODY_LEN    (256 * 1024)  /* 256KB max body capture */

typedef struct {
    char key[256];
    char value[PF_HTTP_MAX_HEADER_LEN];
} pf_http_header_t;

typedef struct {
    /* Request line */
    char method[16];
    char url[PF_HTTP_MAX_URL_LEN];
    char version[16];

    /* Headers */
    pf_http_header_t headers[PF_HTTP_MAX_HEADERS];
    int              header_count;

    /* Body */
    const char *body;       /* pointer into original buffer */
    size_t      body_len;
    size_t      content_length;

    /* Status (for responses) */
    int          status_code;
    char         status_text[64];

    /* Parse state */
    int          is_request;    /* 1 = request, 0 = response */
    int          complete;      /* 1 = all headers parsed */
    size_t       header_end;    /* offset of end of headers (\r\n\r\n) in buffer */
} pf_http_msg_t;

/* Parse an HTTP request from a buffer. Returns 0 on success, -1 if incomplete/invalid.
 * msg->body points into buf (not copied). */
int pf_http_parse_request(const char *buf, size_t len, pf_http_msg_t *msg);

/* Parse an HTTP response from a buffer. Returns 0 on success, -1 if incomplete/invalid. */
int pf_http_parse_response(const char *buf, size_t len, pf_http_msg_t *msg);

/* Get a header value by key (case-insensitive). Returns NULL if not found. */
const char *pf_http_get_header(const pf_http_msg_t *msg, const char *key);

#endif /* PF_HTTP_PARSER_H */
