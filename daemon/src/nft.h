#ifndef PF_NFT_H
#define PF_NFT_H

#include "proxiflare.h"

int pf_nft_init(void);                         /* Create table + base chains */
int pf_nft_cleanup(void);                      /* Flush and delete table */
int pf_nft_setup_dns_redirect(void);           /* Redirect DNS to NFQUEUE */
int pf_nft_setup_tproxy(int port);             /* Setup TPROXY for marked traffic */
int pf_nft_add_cgroup_mark(int rule_id);       /* Mark traffic from cgroup */
int pf_nft_remove_cgroup_mark(int rule_id);
int pf_nft_dns_leak_protect(const char *dns_server); /* DNAT all DNS to secure server (direct) */
int pf_nft_dns_via_proxy(int local_port);            /* REDIRECT cgroup DNS to local resolver on 127.0.0.1:<port> */
int pf_nft_dns_leak_disable(void);                   /* Remove all DNS rules (either mode) */
int pf_nft_block_quic(void);                         /* REJECT UDP:443 from proxiflare cgroup — force TCP+TLS fallback */
int pf_nft_unblock_quic(void);                       /* Remove QUIC block */

#endif /* PF_NFT_H */
