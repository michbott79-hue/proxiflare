#ifndef PF_NFT_H
#define PF_NFT_H

#include "proxiflare.h"

int pf_nft_init(void);                         /* Create table + base chains */
int pf_nft_cleanup(void);                      /* Flush and delete table */
int pf_nft_setup_dns_redirect(void);           /* Redirect DNS to NFQUEUE */
int pf_nft_setup_tproxy(int port);             /* Setup TPROXY for marked traffic */
int pf_nft_add_cgroup_mark(int rule_id);       /* Mark traffic from cgroup */
int pf_nft_remove_cgroup_mark(int rule_id);

#endif /* PF_NFT_H */
