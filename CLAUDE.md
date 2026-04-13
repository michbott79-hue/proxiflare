# ProxiFlare — Project Instructions

## Progetto
ProxiFlare — proxy router professionale per Linux (stile Proxifier). C daemon + Tauri/React GUI.
Repository: `~/projects/proxiflare/`, Branch principale: `dev`

## Architettura

```
Daemon C (root)  ←→  Unix socket IPC (JSON-NL)  ←→  Tauri GUI (user)
/run/proxiflare/proxiflare.sock
```

- **Daemon**: `daemon/` — C11, CMake, epoll, 18 moduli
- **GUI**: `gui/` — Tauri v2 + React + TypeScript + Tailwind v4
- **Installer**: `scripts/` — systemd, polkit, install.sh/uninstall.sh
- **Specs**: `docs/superpowers/specs/` — design spec
- **Plans**: `docs/superpowers/plans/` — implementation plan

## Regole Obbligatorie

### Build & Install
1. **SEMPRE rebuild dopo ogni fix**: `cd gui && npx tauri build`
2. **SEMPRE rimuovere il .deb vecchio prima di installare**: `sudo dpkg -r proxi-flare`
3. **SEMPRE installare il nuovo**: `sudo dpkg -i gui/src-tauri/target/release/bundle/deb/ProxiFlare_*.deb`
4. **MAI far testare a Mich con una build vecchia**

### Sequenza di rilascio
```bash
# 1. Fix/modifica codice
# 2. Rebuild
cd gui && source ~/.cargo/env && npx tauri build
# 3. Rimuovi vecchio
sudo dpkg -r proxi-flare
# 4. Installa nuovo
sudo dpkg -i gui/src-tauri/target/release/bundle/deb/ProxiFlare_*.deb
# 5. Restart daemon se modificato
cd daemon/build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc)
sudo pkill proxiflare-daemon; sudo /usr/local/bin/proxiflare-daemon --foreground &
```

### Versioning (Semantic Versioning)
- Versione attuale: **0.1.0-alpha**
- NON saltare a 1.0.0 finché non è stabile e testato
- Incrementi ragionevoli: 0.1.0 → 0.1.1 (patch) → 0.2.0 (feature) → ...
- Aggiornare versione in: `gui/src-tauri/tauri.conf.json`, `gui/src-tauri/Cargo.toml`, `daemon/include/proxiflare.h`, `CHANGELOG.md`

### Daemon
- Gira come root: `sudo proxiflare-daemon --foreground`
- Systemd: `sudo systemctl start proxiflare-daemon`
- Socket: `/run/proxiflare/proxiflare.sock` (chmod 777 per accesso GUI)
- DB: `/var/lib/proxiflare/proxiflare.db`
- Log: `/var/log/proxiflare/proxiflare.log`
- Build: `cd daemon/build && cmake .. && make -j$(nproc)`
- Test: `./pf-test-config && ./pf-test-crypto && ./pf-test-rules && ./pf-test-sni`

### GUI
- Dev mode: `cd gui && npx tauri dev`
- Build prod: `cd gui && npx tauri build`
- .deb output: `gui/src-tauri/target/release/bundle/deb/ProxiFlare_*.deb`
- NO select nativi — usare dropdown custom (Linux WebKit li mostra bianchi)
- Tema dark: bg `#0f1117`, panels `#1a1d27`, accent `#6366f1`

### Codice
- Daemon C: `-Wall -Wextra`, zero warnings
- GUI: `npx tsc --noEmit` deve passare senza errori
- API responses: SEMPRE `Array.isArray()` check sui dati dal daemon
- useDaemon: una volta unlocked, resta unlocked per la sessione

## File Chiave

| File | Ruolo |
|------|-------|
| `daemon/include/proxiflare.h` | Tipi, costanti, versione |
| `daemon/src/main.c` | Entry point daemon, IPC handler, epoll loop |
| `daemon/src/config.c` | SQLite CRUD |
| `daemon/src/rules.c` | Rule engine pattern matching |
| `gui/src-tauri/src/ipc.rs` | Client Unix socket → daemon |
| `gui/src-tauri/src/commands.rs` | Tauri commands esposti a React |
| `gui/src/App.tsx` | Layout principale, tab navigation |
| `gui/src/hooks/useDaemon.ts` | Polling status daemon |
| `gui/src/lib/api.ts` | Wrapper API tipizzate |

## Proxy di Mich (6 residenziali)
Credenziali in `mem_creds("general")`. Paesi: FR, RS, BR, HR, CH, DE.

# Ruflo Integration (solo questo progetto)
Ruflo è installato in `.claude/` + `.claude-flow/` di questo progetto.
- MCP locali (in `.mcp.json`): claude-flow, ruv-swarm, flow-nexus — `autoStart: false`
- Avvio manuale: `npx claude-flow daemon start`, `memory init`, `swarm init`
- Per task multi-file/complessi: usa ToolSearch per trovare tool ruflo (memory_store, memory_search, hooks_route, swarm_init, agent_spawn)
- Osserva tag `[INTELLIGENCE]` nei system-reminder per suggerimenti pattern learning
- Provider principale: Ollama locale (GPU RTX 3070). Fallback: Claude
- Memoria swarm: locale in `.claude-flow/data/` — NON sostituisce MCP memory globale (quella resta primaria per decisioni/progressi)
