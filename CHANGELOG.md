# Changelog

All notable changes to ProxiFlare will be documented in this file.

Format follows [Semantic Versioning](https://semver.org/):
- **MAJOR** (1.0.0): Stable release, breaking API changes
- **MINOR** (0.x.0): New features, backward compatible
- **PATCH** (0.0.x): Bug fixes, UI tweaks

---

## [Unreleased] — 2026-04-13

### Added
- **GUI daemon auto-lifecycle**: opening the GUI starts `proxiflare-daemon` via systemd;
  closing the window (or SIGTERM/SIGINT/SIGHUP) cleanly stops it. Tracks whether the
  GUI started the daemon (via `systemctl is-active` check) so a pre-running daemon is
  left untouched on close.
  - New polkit rule (`scripts/50-proxiflare.rules`) authorises the `sudo` group to
    `start/stop/restart/reload` the unit without a password prompt.
  - New Rust dep: `signal-hook` for SIGTERM/SIGINT/SIGHUP handling in a dedicated
    thread.
- **DNS via proxy (DoH)** — new routing mode that completely eliminates the DNS leak
  for apps in the proxiflare cgroup.
  - New daemon module `daemon/src/dns_resolver.{c,h}`: UDP listener on
    `127.0.0.1:5353` with a per-query detached thread performing DoH (HTTP/1.1 POST
    `/dns-query`, `application/dns-message`) through the configured proxy to
    `cloudflare-dns.com:443`.
  - `pf_nft_dns_via_proxy(port)` in `daemon/src/nft.c`: REDIRECTs cgroup UDP/TCP :53
    to the local resolver instead of DNAT to an external server.
  - IPC: `dns_leak.enable` now accepts `{mode: "force-server" | "via-proxy"}`;
    `dns_leak.status` returns the active mode. Mode is persisted in config and
    restored across daemon restarts.
  - GUI: new radio selector in Settings → DNS Leak Protection with two options —
    *Force DNS server (direct)* and *Route DNS through proxy (DoH)*.
  - Proxy selection: honours config `dns_proxy_id` if set, otherwise picks the first
    enabled HTTP/SOCKS5 proxy. SSH proxies are skipped.
- **Proxy provider import**: new `ImportProviderModal` in the GUI backed by a Rust
  provider abstraction (`gui/src-tauri/src/providers/`). First provider: proxy-cheap
  (live API, filters `status=ACTIVE`, expands each entry into HTTP + SOCKS5 rows).

### Why Cloudflare (DoH) and not Quad9 or DoT
- Quad9 DoH requires HTTP/2 (RFC 8484 §5.2) which would need `nghttp2` linking.
- DoT on port 853 is rejected by most residential HTTP CONNECT proxies (whitelist 443).
- Cloudflare DoH on 443 works over HTTP/1.1 and port 443 is universally allowed.

---

## [0.1.0-alpha] — 2026-04-11

### Added
- **Daemon (C)**: Full proxy routing daemon with epoll event loop
  - SQLite config with proxy/rule/chain CRUD
  - AES-256-GCM credentials encryption with Argon2id key derivation
  - IPC server (Unix socket, JSON-NL protocol)
  - Rule engine: match by app, domain, subdomain, IP/CIDR, port range
  - SOCKS4/4a and SOCKS5 proxy connectors
  - HTTP CONNECT proxy connector with Basic auth
  - SSH tunnel manager with session pooling (libssh2)
  - Multi-hop proxy chain router
  - DNS interceptor via NFQUEUE with domain caching
  - TLS ClientHello SNI parser
  - TPROXY transparent proxy handler
  - cgroups v2 per-app traffic classification
  - nftables rule manager
  - Process monitor via netlink proc connector
  - Stats collector (per-proxy bandwidth/latency)
  - Dual logger: real-time IPC push + disk with rotation
- **GUI (Tauri + React)**: Desktop application
  - Tab-based layout: Proxies, Rules, Chains, Log, Settings
  - Proxy management: add/edit/delete/test, card grid, health status
  - Rule management: drag-to-reorder, colored match/action badges
  - Chain builder: visual hop editor with test
  - Real-time log viewer with filters and pause/resume
  - Settings: master password, start-at-boot, disk logging toggle
  - Dark theme (Proxifier-inspired)
  - Custom dropdowns (no native select elements)
- **Installer**: .deb package, systemd service, polkit policy, desktop entry

### Known Issues
- NFQUEUE requires `nf_queue` kernel module loaded
- TPROXY nftables syntax needs kernel 5.13+ with `xt_TPROXY`
- AppImage build fails (linuxdeploy issue, .deb works fine)

---

## Versioning Roadmap

| Version | Milestone |
|---------|-----------|
| 0.1.0-alpha | Core daemon + GUI — functional prototype |
| 0.2.0-alpha | Bug fixes from testing, UI polish |
| 0.3.0-beta | Proxy health checks, auto-failover |
| 0.4.0-beta | Export/import config encrypted |
| 0.5.0-beta | Log to disk with rotation, stats dashboard |
| 0.9.0-rc | Release candidate — full testing |
| 1.0.0 | Stable release |
