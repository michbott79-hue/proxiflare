# Changelog

All notable changes to ProxiFlare will be documented in this file.

Format follows [Semantic Versioning](https://semver.org/):
- **MAJOR** (1.0.0): Stable release, breaking API changes
- **MINOR** (0.x.0): New features, backward compatible
- **PATCH** (0.0.x): Bug fixes, UI tweaks

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
