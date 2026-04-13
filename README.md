# ProxiFlare

Professional per-app proxy router for Linux — like Proxifier, but native, open source, and GPU-free.

Route specific applications or domains through SOCKS5/SOCKS4/HTTP/SSH proxies without VPN. Set a rule such as "Firefox on `*.dazn.com` → IT residential proxy", keep the rest of your traffic direct.

![version](https://img.shields.io/badge/version-0.1.0--alpha-orange)
![platform](https://img.shields.io/badge/platform-Linux-blue)
![license](https://img.shields.io/badge/license-MIT-green)

## Architecture

```
┌─────────────────────────┐         Unix socket (JSON-RPC)         ┌──────────────────────────┐
│ Tauri + React GUI       │◄───────────────────────────────────────│ proxiflare-daemon (C)    │
│ (user)                  │         /run/proxiflare/*.sock         │ (root, systemd)          │
└─────────────────────────┘                                        └──────────────────────────┘
                                                                              │
                                                                              ▼
                                                   ┌────────────────────────────────────────┐
                                                   │ cgroup v2 socket match (per-app)       │
                                                   │ nftables mark → fwmark 0x1             │
                                                   │ ip rule fwmark → table 100 → lo        │
                                                   │ TPROXY 127.0.0.1:12345                 │
                                                   │ SNI peek → per-domain routing decision │
                                                   │ SOCKS5 / SOCKS4 / HTTP / SSH proxy     │
                                                   │ optional MITM (HTTP/1.1 downgrade)     │
                                                   └────────────────────────────────────────┘
```

## Features

- **Per-application routing** via cgroup v2 + nftables socket match (kernel-level, no LD_PRELOAD)
- **Per-domain rules** with wildcards (`*.sky.it, *.skygo.it, *.dazn.com`)
- **Multiple proxy protocols**: SOCKS5, SOCKS4, HTTP CONNECT, SSH tunnel
- **Proxy chains** (hop through multiple proxies)
- **Live configuration** — add/edit/toggle rules and proxies without restarting apps
- **DNS leak protection** via NFQUEUE + DNAT
- **HTTPS MITM** for request inspection (ALPN downgrade to HTTP/1.1, EC P-256 per-domain certs)
- **Auto-cleanup safety net** — if the daemon crashes, nftables and ip rule state are wiped automatically (no more "rete bloccata → reboot")
- **Hot-assign** already-running PIDs to new rules — no need to restart Firefox/Chrome when you add a rule

## Components

| Path           | Stack                         | Role                                            |
|----------------|-------------------------------|-------------------------------------------------|
| `daemon/`      | C11, CMake, epoll, SQLite     | Routing engine, TPROXY, MITM, IPC server        |
| `gui/`         | Tauri v2 + React + TS + Tailwind | Proxy/Rule CRUD, real-time log, MITM inspect |
| `scripts/`     | bash, systemd, polkit         | `install.sh`, `pf-panic` network recovery       |

## Requirements

- Linux kernel ≥ 5.10 with cgroup v2 and `nft socket cgroupv2 level N` support
- `nftables`, `iproute2`
- Build: `build-essential cmake pkg-config libsqlite3-dev libnetfilter-queue-dev libnfnetlink-dev libssh2-1-dev libssl-dev libargon2-dev`
- GUI build: Node.js ≥ 18, Rust ≥ 1.77

## Install

```bash
git clone https://github.com/<user>/proxiflare.git
cd proxiflare
sudo ./scripts/install.sh
sudo systemctl enable --now proxiflare-daemon
proxiflare    # launch GUI
```

`install.sh` compiles the daemon and the GUI, installs binaries in `/usr/local/bin/` and `/usr/bin/`, places the systemd unit and the polkit policy, and drops the `pf-panic` emergency recovery script.

## Emergency recovery

If something goes wrong and your network freezes (shouldn't happen with the safety net, but just in case):

```bash
sudo pf-panic
```

This kills the daemon and flushes all nftables/ip rule/route table/cgroup state in ~1 second. systemd's `ExecStopPost` also runs it automatically whenever the daemon exits for any reason — including hard crashes.

## Project status

**0.1.0-alpha.** Works end-to-end on the author's setup (Ubuntu 24.04, kernel 6.17). Routing, MITM, live config, hot-assign, DNS leak protection all tested. SSH proxy relay path and HTTP/3 (QUIC) interception still incomplete.

Expect breaking changes before 0.1.0 final.

## License

MIT
