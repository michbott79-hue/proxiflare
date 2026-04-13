#include "nft.h"
#include "logger.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <arpa/inet.h>

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
 * nft_delete_by_comment — remove all rules in a chain whose comment contains
 * the given substring.  Works by listing rules with handles (-a), parsing
 * for the comment and handle, then deleting by handle.
 *
 * table_type: "inet" or "ip"
 * table:      "proxiflare" or "proxiflare_tproxy"
 * chain:      "output" or "prerouting"
 * comment:    substring to match in comment field (e.g. "pf_dns_leak")
 * ───────────────────────────────────────────────────────────────────────────── */
static int nft_delete_by_comment(const char *table_type, const char *table,
                                  const char *chain, const char *comment)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nft -a list chain %s %s %s 2>/dev/null",
             table_type, table, chain);

    FILE *fp = popen(cmd, "r");
    if (!fp) return PF_ERR;

    char line[1024];
    int deleted = 0;
    /* Collect all matching handles first, THEN delete — never close fp
     * inside the fgets loop (that was a UAF on fp). */
    int handles[256];
    int handle_count = 0;

    while (fgets(line, sizeof(line), fp) && handle_count < (int)(sizeof(handles)/sizeof(handles[0]))) {
        if (!strstr(line, comment)) continue;
        const char *hstr = strstr(line, "# handle ");
        if (!hstr) continue;

        int handle = atoi(hstr + 9);
        if (handle <= 0) continue;

        handles[handle_count++] = handle;
    }
    pclose(fp);

    /* Deletes run highest-handle-first so earlier handles stay valid */
    for (int i = handle_count - 1; i >= 0; i--) {
        char del[256];
        snprintf(del, sizeof(del),
                 "delete rule %s %s %s handle %d\n",
                 table_type, table, chain, handles[i]);
        if (nft_run(del) == PF_OK) deleted++;
    }

    if (deleted > 0)
        pf_log_info("nft: deleted %d rules with comment '%s' from %s %s %s",
                     deleted, comment, table_type, table, chain);

    return PF_OK;
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

    /* Main table: inet
     * Two output chains:
     *   - output: type route for cgroup marking + DNS NFQUEUE
     *   - output_nat: type nat for DNS DNAT (leak protection)
     * DNAT only works in nat chains, not route chains. */
    const char *main_table =
        "table inet proxiflare {\n"
        "    chain output {\n"
        "        type route hook output priority 0; policy accept;\n"
        "    }\n"
        "    chain output_nat {\n"
        /* priority -100 = dstnat, the canonical spot for DNAT in the output
         * hook. At priority 0 (filter) DNAT runs after the routing decision
         * has already been made on the original destination, so the packet
         * goes out on the wrong path (classic symptom: DNAT rule counters
         * increment but traffic still times out). */
        "        type nat hook output priority -100; policy accept;\n"
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
    /* Intercept DNS queries ONLY from processes inside proxiflare cgroups,
     * not system-wide. Without this scope, any hiccup in the daemon's NFQUEUE
     * consumer (stall, crash, restart) kills DNS for the entire box (apt,
     * ssh, systemd-resolved, everything) — "rete bloccata" symptom Mich
     * observed even after the safety-net commits.
     *
     * level 1 "proxiflare" matches any sub-cgroup (rule_N), so this still
     * populates the IP→domain cache used for SNI-less rule matching. */
    if (nft_run("add rule inet proxiflare output "
                "socket cgroupv2 level 1 \"proxiflare\" "
                "udp dport 53 queue num 0 bypass "
                "comment \"pf_dns_nfqueue\"\n") != PF_OK) {
        pf_log_error("nft: failed to add DNS NFQUEUE rule");
        return PF_ERR;
    }
    pf_log_info("nft: DNS NFQUEUE installed (scope: proxiflare cgroup only, bypass on failure)");
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
    /* Ensure the cgroup directory exists (idempotent) */
    char cg_path[256];
    snprintf(cg_path, sizeof(cg_path), "/sys/fs/cgroup/proxiflare/rule_%d", rule_id);
    mkdir(cg_path, 0755);

    /* Use cgroupv2 socket matching — this is the correct nftables syntax
     * for matching processes in a specific cgroup hierarchy node.
     * "level 2" means 2 levels deep in the hierarchy: proxiflare/rule_N
     * Comment tag enables targeted removal without flushing the chain. */
    /* Mark only TCP. If we mark UDP/ICMP too, fwmark+table 100 sends them
     * to loopback where nothing listens → black hole. DNS (UDP 53) in
     * particular breaks: the packet gets marked, routed to lo, dropped.
     * DNS needs to flow normally (or through NFQUEUE/DNAT in leak mode),
     * not through TPROXY. */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "add rule inet proxiflare output socket cgroupv2 level 2 "
        "\"proxiflare/rule_%d\" meta l4proto tcp meta mark set 1 "
        "comment \"pf_cgroup_%d\"\n",
        rule_id, rule_id);

    if (nft_run(cmd) != PF_OK) {
        pf_log_error("nft: failed to add cgroup mark for rule_%d", rule_id);
        return PF_ERR;
    }
    pf_log_info("nft: cgroup mark rule added for rule_%d (cgroupv2)", rule_id);
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_nft_remove_cgroup_mark
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_nft_remove_cgroup_mark(int rule_id)
{
    char comment[64];
    snprintf(comment, sizeof(comment), "pf_cgroup_%d", rule_id);
    int rc = nft_delete_by_comment("inet", "proxiflare", "output", comment);
    if (rc == PF_OK)
        pf_log_info("nft: cgroup mark rule removed for rule_%d", rule_id);
    return rc;
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

    /* Validate dns_server is a bare IPv4 or IPv6 literal BEFORE interpolating
     * into an nft command. Rejects newlines, shell metacharacters, hostnames,
     * and anything else that could break out of the `add rule` statement into
     * `flush ruleset` or similar mischief. */
    struct in_addr  v4;
    struct in6_addr v6;
    if (inet_pton(AF_INET, dns_server, &v4) != 1 &&
        inet_pton(AF_INET6, dns_server, &v6) != 1) {
        pf_log_error("nft: dns_leak: dns_server '%s' is not a valid IP literal",
                     dns_server);
        return PF_ERR;
    }

    /* Remove any existing DNS DNAT rules first (prevents duplicates on server change) */
    nft_delete_by_comment("inet", "proxiflare", "output_nat", "pf_dns_leak");

    char cmd[512];

    /* Scope DNAT to proxiflare cgroup only. Rewriting all outbound UDP/TCP
     * 53 system-wide breaks the local resolver (systemd-resolved on
     * 127.0.0.53) because the loopback→DNAT→remote return path isn't SNAT'd
     * and conntrack mismatches. Scoping to the cgroup leaves the rest of the
     * system on its normal resolver while still forcing intercepted apps
     * through the chosen DNS server. */

    /* DNAT matrix:
     *   - scope:  only packets from proxiflare cgroup (no system impact)
     *   - src:    skip 127.0.0.0/8 destinations — DNAT'ing loopback traffic
     *             (e.g. dig → 127.0.0.53 → systemd-resolved) to an external
     *             IP breaks conntrack reverse-NAT: the reply comes back on
     *             eth0 with src=1.1.1.1 but the original socket was bound
     *             to lo, lookup fails, dig times out. Leaving loopback DNS
     *             alone keeps systemd-resolved working as usual for the app.
     *   - dst:    also skip the target DNS server itself (anti-loop).
     * Net effect: apps that try to contact an external DNS server directly
     * (e.g. Firefox DoH pointing to 8.8.8.8) are redirected to the chosen
     * leak-protection server. Apps using the local resolver pass through. */

    /* UDP DNS */
    snprintf(cmd, sizeof(cmd),
        "add rule inet proxiflare output_nat "
        "socket cgroupv2 level 1 \"proxiflare\" "
        "udp dport 53 ip daddr != { 127.0.0.0/8, %s } "
        "counter dnat to %s comment \"pf_dns_leak\"\n",
        dns_server, dns_server);
    if (nft_run(cmd) != PF_OK) {
        pf_log_error("nft: dns_leak: UDP rule failed");
        return PF_ERR;
    }

    /* TCP DNS */
    snprintf(cmd, sizeof(cmd),
        "add rule inet proxiflare output_nat "
        "socket cgroupv2 level 1 \"proxiflare\" "
        "tcp dport 53 ip daddr != { 127.0.0.0/8, %s } "
        "counter dnat to %s comment \"pf_dns_leak\"\n",
        dns_server, dns_server);
    if (nft_run(cmd) != PF_OK) {
        pf_log_error("nft: dns_leak: TCP rule failed");
        return PF_ERR;
    }

    pf_log_info("nft: DNS leak protection active → %s", dns_server);
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_nft_dns_via_proxy — REDIRECT cgroup DNS to local resolver on <local_port>
 *
 * Unlike pf_nft_dns_leak_protect (which DNATs to an external DNS server and
 * lets the query leak from the real IP), this redirects UDP/TCP :53 from the
 * proxiflare cgroup to a local listener. The listener (pf_dns_resolver) then
 * forwards each query as DNS-over-HTTPS through the configured proxy, so the
 * real IP never emits a DNS packet.
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_nft_dns_via_proxy(int local_port)
{
    if (local_port <= 0 || local_port > 65535) {
        pf_log_error("nft: dns_via_proxy: invalid port %d", local_port);
        return PF_ERR;
    }

    /* Clean any existing pf_dns_leak rules (either mode) to avoid duplicates. */
    nft_delete_by_comment("inet", "proxiflare", "output_nat", "pf_dns_leak");

    char cmd[512];

    /* UDP DNS → local resolver.
     *   - `redirect to :port` rewrites dst to 127.0.0.1:port in OUTPUT chain.
     *   - conntrack reverses the NAT on reply so the client sees the answer
     *     as if it came from the originally queried server.
     *   - Excluding 127.0.0.0/8 leaves loopback resolver traffic alone. */
    snprintf(cmd, sizeof(cmd),
        "add rule inet proxiflare output_nat "
        "socket cgroupv2 level 1 \"proxiflare\" "
        "udp dport 53 ip daddr != 127.0.0.0/8 "
        "counter redirect to :%d comment \"pf_dns_leak\"\n",
        local_port);
    if (nft_run(cmd) != PF_OK) {
        pf_log_error("nft: dns_via_proxy: UDP redirect rule failed");
        return PF_ERR;
    }

    /* TCP DNS → local resolver (same as UDP). The local resolver should
     * accept both UDP and TCP on the same port. */
    snprintf(cmd, sizeof(cmd),
        "add rule inet proxiflare output_nat "
        "socket cgroupv2 level 1 \"proxiflare\" "
        "tcp dport 53 ip daddr != 127.0.0.0/8 "
        "counter redirect to :%d comment \"pf_dns_leak\"\n",
        local_port);
    if (nft_run(cmd) != PF_OK) {
        pf_log_error("nft: dns_via_proxy: TCP redirect rule failed");
        return PF_ERR;
    }

    pf_log_info("nft: DNS via proxy active → local resolver :%d", local_port);
    return PF_OK;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pf_nft_dns_leak_disable — Remove DNS rules (direct-mode or via-proxy mode)
 * ───────────────────────────────────────────────────────────────────────────── */

int pf_nft_dns_leak_disable(void)
{
    /* Remove ONLY DNS rules from the nat chain (matched by comment).
     * The output chain (route type) with cgroup marks is untouched. */
    nft_delete_by_comment("inet", "proxiflare", "output_nat", "pf_dns_leak");
    pf_log_info("nft: DNS leak protection disabled (cgroup marks preserved)");
    return PF_OK;
}
