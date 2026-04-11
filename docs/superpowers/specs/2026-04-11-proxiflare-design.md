# ProxiFlare — Design Specification

**Date**: 2026-04-11
**Status**: Approved
**Author**: Mich + Claude

## Overview

ProxiFlare is a professional per-application and per-domain proxy router for Linux, inspired by Proxifier but superior — combining DNS interception with TLS SNI inspection for robust domain-based routing. Architecture: C daemon (root) + Tauri/React GUI (user).

## Architecture

```
┌──────────────────────────────────┐
│  GUI: React + Tailwind (Tauri)   │  user-space, no privileges
├──────────────────────────────────┤
│  Tauri shell (Rust, bridge)      │  IPC bridge only
├──────────────────────────────────┤
│  IPC: Unix socket (JSON-NL)     │  /run/proxiflare.sock
├──────────────────────────────────┤
│  Core daemon: C                  │  root — kernel interaction
│  - DNS interceptor (NFQUEUE)     │
│  - SNI parser (TLS ClientHello)  │
│  - Rule engine                   │
│  - Proxy connectors              │
│  - SSH tunnel manager            │
│  - Chain router                  │
│  - cgroups v2 manager            │
│  - nftables rule manager         │
│  - Process monitor (netlink)     │
│  - Logger (real-time + file)     │
│  - Stats collector               │
│  - Crypto (AES-256-GCM)         │
├──────────────────────────────────┤
│  Storage: SQLite (encrypted)     │  /var/lib/proxiflare/
└──────────────────────────────────┘
```

### Privilege Separation

- **Daemon** (`proxiflare-daemon`): runs as root, manages nftables/cgroups/DNS/TPROXY
- **GUI** (`proxiflare`): runs as user, communicates with daemon via Unix socket
- **Polkit policy**: allows user to start/stop/control daemon without full root

### Data Flow

1. App makes DNS query → netfilter redirects to NFQUEUE → daemon intercepts
2. Daemon matches domain against rules → marks packet with routing decision
3. App opens TCP connection → nftables TPROXY redirects to daemon
4. Daemon reads SNI from TLS ClientHello (confirms domain)
5. Daemon looks up rule → connects via selected proxy/chain
6. All events pushed to GUI via IPC for real-time log

## Project Structure

```
proxiflare/
├── daemon/
│   ├── src/
│   │   ├── main.c              # Entry, signal handling, pidfile, event loop
│   │   ├── config.c/h          # SQLite config load/save
│   │   ├── crypto.c/h          # AES-256-GCM encrypt/decrypt (openssl)
│   │   ├── ipc.c/h             # Unix socket server, JSON-NL protocol
│   │   ├── dns.c/h             # DNS interceptor via NFQUEUE
│   │   ├── sni.c/h             # TLS ClientHello SNI parser
│   │   ├── rules.c/h           # Rule engine with priority matching
│   │   ├── proxy_socks.c/h     # SOCKS4/5 connector
│   │   ├── proxy_http.c/h      # HTTP CONNECT connector
│   │   ├── proxy_ssh.c/h       # SSH tunnel manager (libssh2)
│   │   ├── chain.c/h           # Multi-hop proxy chaining
│   │   ├── tproxy.c/h          # TPROXY transparent proxy handler
│   │   ├── cgroup.c/h          # cgroups v2 management
│   │   ├── nft.c/h             # nftables rule management
│   │   ├── monitor.c/h         # Process monitor (proc_event netlink)
│   │   ├── logger.c/h          # Dual logger: IPC push + optional disk
│   │   └── stats.c/h           # Per-proxy/app/domain bandwidth/latency
│   ├── include/
│   │   └── proxiflare.h        # Shared types, constants, error codes
│   ├── vendor/                 # Vendored: cJSON
│   └── CMakeLists.txt
│
├── gui/
│   ├── src-tauri/
│   │   ├── src/
│   │   │   ├── main.rs         # Tauri entry
│   │   │   ├── ipc.rs          # Unix socket client → daemon
│   │   │   └── commands.rs     # Tauri commands exposed to React
│   │   ├── Cargo.toml
│   │   └── tauri.conf.json
│   ├── src/
│   │   ├── App.tsx             # Root layout + tab router
│   │   ├── main.tsx            # React entry
│   │   ├── pages/
│   │   │   ├── Proxies.tsx     # Proxy management
│   │   │   ├── Rules.tsx       # Rule management
│   │   │   ├── Chains.tsx      # Chain builder
│   │   │   ├── Log.tsx         # Real-time log viewer
│   │   │   └── Settings.tsx    # App settings
│   │   ├── components/
│   │   │   ├── ProxyCard.tsx
│   │   │   ├── RuleRow.tsx
│   │   │   ├── ChainBuilder.tsx
│   │   │   ├── LogEntry.tsx
│   │   │   ├── StatusBadge.tsx
│   │   │   ├── MasterPasswordDialog.tsx
│   │   │   └── Sidebar.tsx
│   │   ├── hooks/
│   │   │   ├── useDaemon.ts    # IPC hook: send commands, receive events
│   │   │   └── useLog.ts       # Log stream hook with virtual scroll
│   │   ├── lib/
│   │   │   ├── api.ts          # Typed IPC wrapper
│   │   │   └── types.ts        # Shared TypeScript types
│   │   └── styles/
│   │       └── globals.css     # Tailwind + custom theme
│   ├── index.html
│   ├── package.json
│   ├── tailwind.config.js
│   ├── tsconfig.json
│   └── vite.config.ts
│
├── assets/
│   ├── logo.svg                # App logo
│   ├── icon-16.png
│   ├── icon-32.png
│   ├── icon-128.png
│   ├── icon-256.png
│   └── icon-512.png
│
├── scripts/
│   ├── install.sh              # Full installer
│   ├── uninstall.sh            # Clean uninstaller
│   ├── proxiflare-daemon.service  # Systemd unit
│   └── com.proxiflare.policy   # Polkit policy
│
├── docs/
│   └── superpowers/specs/
│       └── 2026-04-11-proxiflare-design.md
│
└── README.md
```

## Proxy Types

| Type | Protocol | Auth | Notes |
|------|----------|------|-------|
| SOCKS4 | SOCKS4/4a | No auth / userid | Legacy support |
| SOCKS5 | SOCKS5 | None / user:pass | Primary, supports UDP |
| HTTP | HTTP CONNECT | None / Basic / Digest | HTTPS tunneling |
| SSH | SSH tunnel (-D/-L) | Key / password | Via libssh2, on-demand tunnel |

### Proxy Chaining

Multi-hop chains: traffic flows through N proxies sequentially.
Example: App → SOCKS5 (CH) → SOCKS5 (DE) → destination.

Implementation: daemon opens connection to proxy 1, negotiates, then requests proxy 1 to connect to proxy 2, etc. Each hop supports different proxy types.

### Proxy Health Check

- Periodic connectivity test (configurable interval, default 60s)
- Latency measurement
- Auto-failover: if a proxy in a rule goes offline, optionally switch to backup proxy
- Status: online / offline / slow (>500ms) / error

## Rule Engine

### Priority System

Rules evaluated top-to-bottom by priority. First match wins.

| Priority | Match Type | Example |
|----------|------------|---------|
| 1 (highest) | App + Domain | Firefox + `*.netflix.com` → Proxy US |
| 2 | Exact domain | `api.sky.ch` → Proxy CH |
| 3 | Subdomain wildcard | `*.sunrise.ch` → Proxy CH |
| 4 | TLD wildcard | `*.ch` → Proxy CH |
| 5 | App only | `/usr/bin/curl` → Proxy DE |
| 6 | IP/Subnet | `10.0.0.0/8` → Proxy FR |
| 7 (lowest) | Default | Everything else → DIRECT |

### Match Patterns

```
Domain:   sky.ch              exact
          *.sky.ch            all subdomains
          *.ch                all .ch domains
          *streaming*         contains "streaming"

App:      /usr/bin/firefox    exact path
          firefox             process name
          /opt/google/**      path wildcard

IP:       192.168.1.0/24      CIDR notation
          10.0.0.1-10.0.0.50  IP range

Port:     :443                specific port
          :8000-9000          port range
```

### Rule Actions

- **DIRECT** — no proxy, direct connection
- **PROXY** — route through specific proxy
- **CHAIN** — route through proxy chain
- **BLOCK** — silently drop connection
- **REJECT** — reject with TCP RST / ICMP unreachable

### Database Schema

```sql
CREATE TABLE proxies (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    type        TEXT NOT NULL CHECK(type IN ('socks4','socks5','http','ssh')),
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL,
    username    BLOB,           -- encrypted
    password    BLOB,           -- encrypted
    ssh_key     BLOB,           -- encrypted, for SSH type
    enabled     BOOLEAN DEFAULT 1,
    health      TEXT DEFAULT 'unknown',
    latency_ms  INTEGER,
    check_interval INTEGER DEFAULT 60,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE chains (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    enabled     BOOLEAN DEFAULT 1,
    created_at  INTEGER NOT NULL
);

CREATE TABLE chain_hops (
    id          INTEGER PRIMARY KEY,
    chain_id    INTEGER NOT NULL REFERENCES chains(id) ON DELETE CASCADE,
    proxy_id    INTEGER NOT NULL REFERENCES proxies(id),
    hop_order   INTEGER NOT NULL,
    UNIQUE(chain_id, hop_order)
);

CREATE TABLE rules (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    enabled     BOOLEAN DEFAULT 1,
    priority    INTEGER NOT NULL DEFAULT 100,
    match_app   TEXT,
    match_domain TEXT,
    match_ip    TEXT,
    match_port  TEXT,
    action      TEXT NOT NULL CHECK(action IN ('DIRECT','PROXY','CHAIN','BLOCK','REJECT')),
    proxy_id    INTEGER REFERENCES proxies(id),
    chain_id    INTEGER REFERENCES chains(id),
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE config (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);

-- Indexes
CREATE INDEX idx_rules_priority ON rules(priority);
CREATE INDEX idx_rules_enabled ON rules(enabled) WHERE enabled = 1;
CREATE INDEX idx_chain_hops_chain ON chain_hops(chain_id, hop_order);
```

## IPC Protocol

Unix socket at `/run/proxiflare.sock`. JSON newline-delimited protocol.

### Request Format
```json
{"id": 1, "method": "namespace.action", "params": {}}
```

### Response Format
```json
{"id": 1, "result": {}}
{"id": 1, "error": {"code": 401, "message": "Credentials locked"}}
```

### Push Events (server → client)
```json
{"id": null, "event": "log.entry", "data": {"ts": 1712834400, "app": "firefox", "pid": 1234, "domain": "sky.ch", "dst_ip": "1.2.3.4", "dst_port": 443, "proxy": "CH", "action": "PROXY", "bytes_tx": 1024, "bytes_rx": 14320, "latency_ms": 42}}
{"id": null, "event": "proxy.status", "data": {"proxy_id": 1, "status": "offline", "latency_ms": null}}
{"id": null, "event": "stats.update", "data": {"proxy_id": 1, "bytes_tx": 102400, "bytes_rx": 1048576, "connections": 42}}
```

### Method Reference

| Namespace | Methods |
|-----------|---------|
| proxy | list, add, edit, delete, test, import, export |
| rule | list, add, edit, delete, reorder, enable, disable |
| chain | list, add, edit, delete, test |
| log | subscribe, unsubscribe, clear, disk_enable, disk_disable |
| stats | get, reset |
| config | get, set |
| credentials | unlock, lock, change_master, export, import |
| system | status, version, shutdown |

## Credentials Management

### Master Password

- Required at first launch to set up
- AES-256-GCM encryption of all proxy credentials
- Key derivation: Argon2id (memory=64MB, iterations=3, parallelism=4)
- Encrypted credentials stored as BLOB in SQLite
- Session-based unlock: decrypt to memory, lock on timeout or manual lock

### View Credentials

- GUI can request decrypted credentials after unlock
- Displayed in modal with copy-to-clipboard, auto-clear after 30s
- Never logged to disk

### Export/Import

- Export: all proxies + rules + chains → single `.pfe` (ProxiFlare Export) file
- Encrypted with AES-256-GCM using a separate export password
- Import: decrypt `.pfe` file, merge or replace existing config
- Format: encrypted JSON archive

## Logging

### Real-time Log (GUI)

- Pushed via IPC events
- Virtual-scrolling list (handles 100k+ entries)
- Color-coded by action: DIRECT (gray), PROXY (blue), CHAIN (purple), BLOCK (red)
- Filterable by: app, domain, proxy, action
- Searchable

### Disk Log (optional)

- Toggle on/off from Settings
- Path: `/var/log/proxiflare/proxiflare.log`
- Format: `[timestamp] [app:pid] domain → proxy (action) tx/rx latency`
- Log rotation: configurable max size, default 100MB, keep 5 files

## GUI Design

### Layout

Tab bar at top (Proxifier-style), content area below. Dark theme default with light theme option.

### Tabs

1. **Proxies**: card grid showing each proxy with name, type, host:port, status badge (green/red/yellow), latency. Add/Edit modal. Test button. Bulk import/export.

2. **Rules**: sortable table with drag-to-reorder. Columns: priority, name, match (app/domain/IP), action, proxy/chain, enabled toggle. Quick-add wizard. Inline edit.

3. **Chains**: visual chain builder. Drag proxies from sidebar into chain slots. Shows hop order with arrows. Test chain end-to-end.

4. **Log**: real-time scrolling log. Filter bar at top. Pause/resume button. Clear button. Toggle disk logging.

5. **Settings**: master password management, start-at-boot toggle, log settings, theme, about/version.

### Color Scheme

- Background: `#0f1117` (dark navy)
- Cards/panels: `#1a1d27`
- Accent: `#6366f1` (indigo)
- Success: `#22c55e`
- Error: `#ef4444`
- Warning: `#f59e0b`
- Text: `#e2e8f0`

## Installer

### `install.sh`

```
Usage: sudo ./scripts/install.sh [--uninstall]

Steps:
1. Check Linux, root, arch (x86_64/aarch64)
2. Check/install dependencies: build-essential, cmake, libsqlite3-dev,
   libnetfilter-queue-dev, libnfnetlink-dev, libssh2-1-dev, libssl-dev,
   nftables, pkg-config
3. Compile daemon: cmake + make in daemon/
4. Build GUI: npm install + npm run tauri build in gui/
5. Install:
   - /usr/local/bin/proxiflare-daemon
   - /usr/local/bin/proxiflare (GUI binary)
   - /etc/proxiflare/ (config dir)
   - /var/lib/proxiflare/ (database)
   - /var/log/proxiflare/ (logs)
   - /usr/share/applications/proxiflare.desktop
   - /usr/share/icons/hicolor/*/apps/proxiflare.png
   - /usr/share/polkit-1/actions/com.proxiflare.policy
   - /etc/systemd/system/proxiflare-daemon.service (disabled)
6. Print success + usage instructions
```

### `uninstall.sh`

Removes all installed files, stops service, removes systemd unit. Optionally keeps config/database (asks user).

## Build Dependencies

### Daemon (C)
- gcc/clang
- cmake >= 3.16
- libsqlite3-dev
- libnetfilter-queue-dev
- libnfnetlink-dev
- libssh2-1-dev
- libssl-dev (OpenSSL 3.x)
- nftables
- pkg-config

### GUI (Tauri + React)
- Node.js >= 18
- Rust >= 1.70
- cargo + rustup
- webkit2gtk-4.1-dev (Tauri Linux dependency)
- libappindicator3-dev
- librsvg2-dev

## Non-Goals (v1)

- Windows/macOS support
- UDP proxying (SOCKS5 UDP relay — future)
- GUI proxy auto-discovery
- PAC file support
- Built-in packet capture (use tshark)
