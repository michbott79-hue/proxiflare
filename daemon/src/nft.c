#include "nft.h"
#include "logger.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal helper: pipe nft commands via "nft -f -"
 * ───────────────────────────────────────────────────────────────────────────── */

static int nft_run(const char *cmd)
{
    FILE *fp = popen("nft -f -", "w");
    if (!fp) {
        pf_log_error("nft: popen failed: %s", strerror(errno));
        return PF_ERR;
    }
    int r = fputs(cmd, fp);
    int rc = pclose(fp);
    if (r == EOF || rc != 0) {
        pf_log_error("nft: command failed (rc=%d)", rc);
        return PF_ERR;
    }
    return PF_OK;
}

static int run_cmd(const char *cmd)
{
    int rc = system(cmd);
    if (rc != 0)
        pf_log_warn("nft: system('%s') returned %d", cmd, rc);
    return rc == 0 ? PF_OK : PF_ERR;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_nft_init — Create tables and policy routing for TPROXY
 *
 * Two tables:
 *   - inet proxiflare: output chain for DNS NFQUEUE + cgroup marking
 *   - ip proxiflare_tproxy: prerouting chain for TPROXY redirect
 *
 * Also sets up ip rule + ip route for TPROXY:
 *   ip rule add fwmark 1 lookup 100
 *   ip route add local 0.0.0.0/0 dev lo table 100
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_nft_init(void)
{
    /* Clean any stale tables first */
    nft_run("delete table inet proxiflare\n");
    nft_run("delete table ip proxiflare_tproxy\n");

    /* Main table: inet (output chain for DNS + cgroup marking) */
    const char *main_table =
        "table inet proxiflare {\n"
        "    chain output {\n"
        "        type route hook output priority 0; policy accept;\n"
        "    }\n"
        "}\n";

    if (nft_run(main_table) != PF_OK) {
        pf_log_error("nft: failed to create inet proxiflare table");
        return PF_ERR;
    }
    pf_log_info("nft: table inet proxiflare created");

    /* TPROXY table: ip (prerouting chain, needs mangle priority) */
    const char *tproxy_table =
        "table ip proxiflare_tproxy {\n"
        "    chain prerouting {\n"
        "        type filter hook prerouting priority mangle; policy accept;\n"
        "    }\n"
        "}\n";

    if (nft_run(tproxy_table) != PF_OK) {
        pf_log_warn("nft: failed to create tproxy table (non-fatal)");
    } else {
        pf_log_info("nft: table ip proxiflare_tproxy created");
    }

    /* Policy routing for TPROXY: marked packets go to loopback */
    run_cmd("ip rule del fwmark 1 lookup 100 2>/dev/null");
    run_cmd("ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null");
    run_cmd("ip rule add fwmark 1 lookup 100");
    run_cmd("ip route add local 0.0.0.0/0 dev lo table 100");
    pf_log_info("nft: policy routing for TPROXY configured");

    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_nft_cleanup — Remove all tables and policy routing
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_nft_cleanup(void)
{
    nft_run("delete table inet proxiflare\n");
    nft_run("delete table ip proxiflare_tproxy\n");
    run_cmd("ip rule del fwmark 1 lookup 100 2>/dev/null");
    run_cmd("ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null");
    pf_log_info("nft: all tables and routing cleaned up");
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_nft_setup_dns_redirect — Send DNS to NFQUEUE for interception
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_nft_setup_dns_redirect(void)
{
    if (nft_run("add rule inet proxiflare output udp dport 53 queue num 0\n") != PF_OK) {
        pf_log_error("nft: failed to add DNS NFQUEUE rule");
        return PF_ERR;
    }
    pf_log_info("nft: DNS redirect to NFQUEUE 0 installed");
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_nft_setup_tproxy — Redirect marked TCP to TPROXY listener
 *
 * Uses the ip table (not inet) with proper tproxy syntax.
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_nft_setup_tproxy(int port)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "add rule ip proxiflare_tproxy prerouting ip protocol tcp meta mark 1 tproxy to 127.0.0.1:%d\n",
        port);

    if (nft_run(cmd) != PF_OK) {
        pf_log_error("nft: failed to add TPROXY rule on port %d", port);
        return PF_ERR;
    }
    pf_log_info("nft: TPROXY rule installed on port %d (mark=0x1)", port);
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_nft_add_cgroup_mark — Mark traffic from a cgroup with fwmark 1
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_nft_add_cgroup_mark(int rule_id)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "add rule inet proxiflare output meta cgroup %d meta mark set 1\n",
        rule_id);

    if (nft_run(cmd) != PF_OK) {
        pf_log_error("nft: failed to add cgroup mark for rule_%d", rule_id);
        return PF_ERR;
    }
    pf_log_info("nft: cgroup mark rule added for rule_%d", rule_id);
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_nft_remove_cgroup_mark
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_nft_remove_cgroup_mark(int rule_id)
{
    pf_log_info("nft: cgroup mark for rule_%d flagged for removal (requires reload)", rule_id);
    (void)rule_id;
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_nft_dns_leak_protect — DNAT all DNS to a secure server
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_nft_dns_leak_protect(const char *dns_server)
{
    if (!dns_server || !dns_server[0]) {
        pf_log_error("nft: dns_leak: invalid server");
        return PF_ERR;
    }

    char cmd[512];

    /* UDP DNS */
    snprintf(cmd, sizeof(cmd),
        "add rule inet proxiflare output udp dport 53 ip daddr != %s counter dnat to %s\n",
        dns_server, dns_server);
    if (nft_run(cmd) != PF_OK) {
        pf_log_error("nft: dns_leak: UDP rule failed");
        return PF_ERR;
    }

    /* TCP DNS */
    snprintf(cmd, sizeof(cmd),
        "add rule inet proxiflare output tcp dport 53 ip daddr != %s counter dnat to %s\n",
        dns_server, dns_server);
    if (nft_run(cmd) != PF_OK) {
        pf_log_error("nft: dns_leak: TCP rule failed");
        return PF_ERR;
    }

    pf_log_info("nft: DNS leak protection active → %s", dns_server);
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_nft_dns_leak_disable — Remove DNS DNAT, restore NFQUEUE
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_nft_dns_leak_disable(void)
{
    /* Flush output chain and re-add base DNS NFQUEUE rule */
    nft_run("flush chain inet proxiflare output\n");
    nft_run("add rule inet proxiflare output udp dport 53 queue num 0\n");
    pf_log_info("nft: DNS leak protection disabled");
    return PF_OK;
}
