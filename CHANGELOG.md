# Changelog

All notable changes to ProxiFlare will be documented in this file.

Format follows [Semantic Versioning](https://semver.org/):
- **MAJOR** (1.0.0): Stable release, breaking API changes
- **MINOR** (0.x.0): New features, backward compatible
- **PATCH** (0.0.x): Bug fixes, UI tweaks

---

## [0.4.0-alpha] — 2026-04-14

Major capture architecture rework + professional Inspect UX.

### Added — async capture architecture (zero-overhead hot path)
- New `daemon/src/capture_queue.{c,h}`: MPSC ring (4096 slots) guarded by a
  short-held mutex, woken via `eventfd`. Producers (TPROXY relay threads)
  push heap-allocated `pf_capture_msg_t` with the raw bytes inline after
  the struct; consumer drains in batches of 64. On overflow the oldest
  undequeued message is dropped and a `dropped` counter is bumped —
  capture fidelity is sacrificed to keep the relay thread non-blocking.
- New `daemon/src/capture_worker.{c,h}`: single consumer thread that
  blocks on the eventfd, drains the queue, and invokes a user-supplied
  processing callback. Cleanly joined at daemon shutdown.
- **`on_inspect_data` is now a thin producer** — validates, rejects
  tracker domains, snapshots bytes + connection metadata, enqueues.
  Microseconds on the relay path.
- **`capture_process_msg` is the consumer** — runs on the worker thread.
  Does the original synchronous work: HTTP/2 preface detection, HTTP/1.1
  parse, gzip/br/zstd decompression, cJSON construction, insertion into
  the inspect ring under `g_inspect_ring_lock`.
- **`tproxy.c` relay reordered**: peer write happens BEFORE the inspect
  callback, so peer latency is never gated on capture under any
  condition (malloc pressure, worker backlog, full queue, etc.).

Expected effect: DAZN/streaming pages no longer hang when capture is
enabled. The relay thread's work is bounded by `malloc+memcpy+mutex` —
~1 μs per chunk.

### Added — Copy as code (10 target languages)
- New `gui/src/lib/snippet-gen/` module with HAR-shaped intermediate
  (`har.ts`) and per-language generators for: cURL, Python requests,
  Python httpx, Node fetch, Node axios, PHP cURL, PHP Guzzle, Go
  net/http, Rust reqwest, Java OkHttp.
- Auto-strips `Content-Length`, `Content-Encoding`, `Transfer-Encoding`,
  `Host`, `Connection`, and all `:*` h2 pseudo-headers before export.
- Binary body detection via null-byte heuristic on first 512 chars →
  emits base64 + decode call in the target language.
- Proper escaping per language: bash single-quote `'\''` trick, Python
  `\xNN`, Node backticks, PHP `<<<'EOD'` nowdoc, Go backtick concat,
  Rust `r#""#` with dynamic hash count, Java `\"` + concat.
- TLS-verify-off flag commented and disabled by default in every
  snippet so a copy-paste doesn't silently accept bad certs.
- Inspect detail panel: new "Copy as ▼" dropdown matching the existing
  dark-theme dropdowns; inline 2 s "Copied as X!" toast.

### Changed — MITM perf polish
- **Cert cache is now O(1) hash** (open addressing, FNV-1a 64, 16-slot
  probe window). Old implementation was a linear array with
  `memmove`-based LRU eviction — dominant on first DAZN page load which
  opens 50+ unique hostnames. API unchanged.
- **TLS session resumption** enabled on the client-facing (browser-side)
  `SSL_CTX`: `SSL_SESS_CACHE_SERVER` + 1024-slot cache, session ID
  context set, `SSL_CTX_set_num_tickets(2)` for TLS 1.3 ticket
  issuance. Subsequent handshakes from the same Firefox session drop
  from ~5 ms to <0.5 ms. Resumption logged in the `wrap_client` path.

---

## [0.3.0-alpha] — 2026-04-14

### Added — capture that actually works on 2026 sites

Background. Diagnosis revealed the real cause of the "panel empty while
the browser is obviously fetching" symptom on sites like DAZN, banks,
and news backends:

1. **QUIC (HTTP/3)** — Firefox/Chrome speak HTTP/3 over UDP:443 for a
   growing share of sites (alt-svc cached). TPROXY only handles TCP, so
   QUIC connections bypass our MITM engine entirely — invisible.
2. **HTTP/2 server-side** — ~85% of 2026 traffic is HTTP/2+. Our
   hand-rolled HTTP/1.1 parser chokes silently on h2 frames (the first
   24 bytes of any h2 session are the fixed CLIENT_PREFACE
   `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`).

Measurement on a real browsing session before the fix:
`823 TLS handshakes vs 500 captured entries` — ~40% of intercepted
streams were silently dropped.

Fixes in this release:

- **QUIC blocking** (`pf_nft_block_quic` in daemon/src/nft.c). New
  `output_filter` chain in the `inet proxiflare` table, scoped to the
  proxiflare cgroup, REJECTs UDP:443 with ICMP admin-prohibited. REJECT
  (not DROP) triggers Firefox's alt-svc fast-fallback timer → browser
  falls back to TCP+TLS in ~100 ms instead of waiting on the UDP
  timeout. Enabled by default on startup; persisted in config under
  `quic_block_enabled`. IPC toggle:
  `quic_block.enable` / `.disable` / `.status`.
- **HTTP/2 CLIENT_PREFACE detection** in `on_inspect_data`. When the
  browser and proxy negotiate `h2` via ALPN, the stream opens with the
  24-byte magic preface. We now detect that and increment a
  `skipped_h2` counter instead of feeding it to the h1.1 parser where
  it would silently fail.
- **Diagnostic counters surfaced in `inspect.status`**: `ring_count`,
  `skipped_h2`, `parse_failures`. GUI toolbar shows these next to the
  cached-certs count so the user can see exactly why the ring is
  underpopulated — and whether the fix is needed yet (native h2 parser
  via nghttp2 is the next step, tracked separately).

### Deferred to a follow-up release
- **Native HTTP/2 parsing via nghttp2** on the server-facing leg.
  Needed for full capture of the ~50% of modern sites whose CDN/origin
  insists on h2 frames even when we offer `http/1.1` via ALPN.
  Architecture: `nghttp2_session_client_new` on the upstream SSL, use
  `on_header_cb` / `on_data_chunk_cb` to reconstruct virtual
  HTTP/1.1-shaped messages for our existing parser+capture path.
  Estimated 1.5-2 days of focused work.

---

## [0.2.3-alpha] — 2026-04-14

### Fixed — GUI hang "ProxiFlare is not responding"
Root cause: `inspect.list` returned the full ring (up to 5000 entries ×
up to 8 KB decoded body) on every 2 s poll — ~40 MB of JSON that Tauri
deserialised on the renderer's main thread, freezing the UI.

Rewrote the capture IPC path around a clean list/detail split:

1. **Daemon `inspect.list`** now returns SLIM summary rows only — no
   headers, no body — and is hard-capped at `limit` entries per call
   (default 500, max 1000). Rows are picked newest-first so under cap
   we keep the most recent, not the oldest. Payload per poll: ≤200 KB.
2. **Daemon `inspect.get(seq)`** — new endpoint that returns the FULL
   entry (headers + body + all fields) for one seq. Called on row click.
3. **GUI poll guard**: skip if a previous poll is still pending
   (`pollInFlight` ref) — prevents pile-up while the daemon is busy.
4. **GUI visibility guard**: skip poll when `document.hidden` (user on
   another tab or window minimised). Resume immediately on
   `visibilitychange`.
5. **GUI poll interval** 2 s → 3 s, and local entry cap 5000 → 2000
   (summary rows are cheap enough; React stays responsive).
6. **Row click** loads the full entry lazily via `inspect_get` so the
   detail panel shows headers + body on demand. Spinner surfaced while
   fetching.

Net effect: poll payload reduced ~200× (~40 MB → ~200 KB); main-thread
deserialise time drops from seconds to milliseconds; the GUI stays
responsive even under heavy capture load.

---

## [0.2.2-alpha] — 2026-04-14

### Fixed — navigation slowness + low capture count on DAZN
- **DNS cache in the DoH resolver**. Every DNS query through the proxy was
  paying a full TLS handshake — measured ~1.3 s each. A page opening 30
  unique hostnames therefore burned 40 s of DNS wait, which also meant
  Firefox timed out on many resources and the Inspect ring looked almost
  empty. Added an LRU cache (512 entries, 60 s TTL, keyed on
  lowercased-name + qtype) that stores the DNS wire response without the
  per-query id. On hit we prepend the caller's id and reply in microseconds.
  First query per domain still pays the round-trip; repeats across a page
  load (CDN / api / auth subdomains shared between pages) are free.

---

## [0.2.1-alpha] — 2026-04-14

### Fixed
- **Inspect tab showed 0 entries while daemon ring was full**. Root cause:
  `inspectList()` in `gui/src/lib/api.ts` did not unwrap the daemon's
  `{result:{result:[...]}}` double envelope, so `Array.isArray(raw)` was
  `false` and we returned `[]`. Same fix applied defensively to
  `logRecent()` which had the identical shape bug.

---

## [0.2.0-alpha] — 2026-04-14

Cumulative release covering two sessions of work on lifecycle, DNS privacy,
and capture quality.

### Added — HTTP capture: decompression + noise filters + bigger ring
- **Body decompression on capture** (`daemon/src/body_decode.{c,h}`): the captured
  body is decompressed before being stored in the inspect ring. Supported
  encodings: gzip/deflate (zlib), brotli (libbrotlidec), zstd (libzstd). Matches
  the standard behaviour of mitmproxy/Charles/Burp — decode on capture, not on
  view. Result: bodies are readable JSON/HTML/XML instead of opaque compressed
  bytes.
- **Tracker-domain pre-buffer filter**: a curated blocklist of ~40 ad/tracker
  backends (doubleclick, adsrvr.org, criteo, rubiconproject, adnxs,
  amazon-adsystem, teads, pubmatic, scorecardresearch, nr-data.net, etc.) is
  matched against the connection domain before HTTP parsing. Matching entries
  are dropped silently so they never fill the ring.
- **Content-Type pre-buffer filter**: response Content-Type is inspected after
  parse and `image/*`, `font/*`, `audio/*`, `video/*`, `application/font*`, and
  `application/octet-stream` are dropped — they never carry debuggable payload.
- **Inspect ring grown** from 200 → 5000 entries. At ~8 KB of decoded body per
  entry and ~500 B JSON overhead this is ~42 MB RAM, acceptable.

### Added — Inspect GUI
- Content-Type dropdown (all / JSON / HTML / XML / text / other) and HTTP status
  class dropdown (all / 2xx / 3xx / 4xx / 5xx) in the Inspect toolbar — applied
  against the paired response via a domain+port+ts-bucket index so the request
  row is the filter unit.
- Body panel now surfaces the original `Content-Encoding` and whether decoding
  succeeded, so a stray unhandled codec is visible rather than silent garbage.
- GUI in-memory cap aligned with the daemon ring (500 → 5000).

### Added — Inspect UI polish
- Native `<select>` dropdowns replaced with dark-theme custom dropdowns
  (Linux WebKit renders native selects as bright-white, breaking the dark
  UI). Matches the existing pattern used in Settings → DNS preset dropdown.
- **Daemon-restart detection** in the Inspect poll: if the returned list
  contains any `seq` lower than the GUI's last seen seq, assume the daemon
  restarted (seq resets to 1) and refresh state from scratch — otherwise
  the GUI would silently show "0 entries" while the daemon's ring is full.

### Why not HTTP/2 native
Our MITM forces ALPN=http/1.1 which covers ~85% of real-world traffic. Native
h2 parsing needs nghttp2 + stream multiplexing + HPACK — ~3-5 days of work for
the remaining 15% (mostly gRPC and a few sites). Deferred until requested.

---

### Added — 2026-04-13 (folded into 0.2.0-alpha)
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
