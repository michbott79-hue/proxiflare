use crate::ipc::DaemonClient;
use serde_json::{json, Value};
use tauri::State;

// ── Proxy ────────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn proxy_list(client: State<DaemonClient>) -> Result<Value, String> {
    client.send_request("proxy.list", json!({}))
}

#[tauri::command]
pub fn proxy_add(
    client: State<DaemonClient>,
    name: String,
    proxy_type: String,
    host: String,
    port: u16,
    username: String,
    password: String,
    check_interval: u32,
) -> Result<Value, String> {
    client.send_request(
        "proxy.add",
        json!({
            "name": name,
            "type": proxy_type,
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "check_interval": check_interval
        }),
    )
}

#[tauri::command]
pub fn proxy_edit(
    client: State<DaemonClient>,
    id: u32,
    name: String,
    proxy_type: String,
    host: String,
    port: u16,
    username: String,
    password: String,
    check_interval: u32,
    enabled: bool,
) -> Result<Value, String> {
    client.send_request(
        "proxy.edit",
        json!({
            "id": id,
            "name": name,
            "type": proxy_type,
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "check_interval": check_interval,
            "enabled": enabled
        }),
    )
}

#[tauri::command]
pub fn proxy_delete(client: State<DaemonClient>, id: u32) -> Result<Value, String> {
    client.send_request("proxy.delete", json!({ "id": id }))
}

#[tauri::command]
pub fn proxy_test(client: State<DaemonClient>, id: u32) -> Result<Value, String> {
    client.send_request("proxy.test", json!({ "id": id }))
}

// ── Rule ─────────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn rule_list(client: State<DaemonClient>) -> Result<Value, String> {
    client.send_request("rule.list", json!({}))
}

#[tauri::command]
pub fn rule_add(
    client: State<DaemonClient>,
    name: String,
    priority: u32,
    match_app: String,
    match_domain: String,
    match_ip: String,
    match_port: String,
    action: String,
    proxy_id: i32,
    chain_id: i32,
) -> Result<Value, String> {
    client.send_request(
        "rule.add",
        json!({
            "name": name,
            "priority": priority,
            "match_app": match_app,
            "match_domain": match_domain,
            "match_ip": match_ip,
            "match_port": match_port,
            "action": action,
            "proxy_id": proxy_id,
            "chain_id": chain_id
        }),
    )
}

#[tauri::command]
pub fn rule_edit(
    client: State<DaemonClient>,
    id: u32,
    name: String,
    enabled: bool,
    priority: u32,
    match_app: String,
    match_domain: String,
    match_ip: String,
    match_port: String,
    action: String,
    proxy_id: i32,
    chain_id: i32,
) -> Result<Value, String> {
    client.send_request(
        "rule.edit",
        json!({
            "id": id,
            "name": name,
            "enabled": enabled,
            "priority": priority,
            "match_app": match_app,
            "match_domain": match_domain,
            "match_ip": match_ip,
            "match_port": match_port,
            "action": action,
            "proxy_id": proxy_id,
            "chain_id": chain_id
        }),
    )
}

#[tauri::command]
pub fn rule_delete(client: State<DaemonClient>, id: u32) -> Result<Value, String> {
    client.send_request("rule.delete", json!({ "id": id }))
}

#[tauri::command]
pub fn rule_reorder(client: State<DaemonClient>, ids: Vec<u32>) -> Result<Value, String> {
    client.send_request("rule.reorder", json!({ "ids": ids }))
}

// ── Chain ────────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn chain_list(client: State<DaemonClient>) -> Result<Value, String> {
    client.send_request("chain.list", json!({}))
}

#[tauri::command]
pub fn chain_add(
    client: State<DaemonClient>,
    name: String,
    hop_proxy_ids: Vec<u32>,
) -> Result<Value, String> {
    client.send_request(
        "chain.add",
        json!({ "name": name, "hop_proxy_ids": hop_proxy_ids }),
    )
}

#[tauri::command]
pub fn chain_edit(
    client: State<DaemonClient>,
    id: u32,
    name: String,
    hop_proxy_ids: Vec<u32>,
) -> Result<Value, String> {
    client.send_request(
        "chain.edit",
        json!({ "id": id, "name": name, "hop_proxy_ids": hop_proxy_ids }),
    )
}

#[tauri::command]
pub fn chain_delete(client: State<DaemonClient>, id: u32) -> Result<Value, String> {
    client.send_request("chain.delete", json!({ "id": id }))
}

#[tauri::command]
pub fn chain_test(client: State<DaemonClient>, id: u32) -> Result<Value, String> {
    client.send_request("chain.test", json!({ "id": id }))
}

// ── Config ───────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn config_get(client: State<DaemonClient>, key: String) -> Result<Value, String> {
    client.send_request("config.get", json!({ "key": key }))
}

#[tauri::command]
pub fn config_set(
    client: State<DaemonClient>,
    key: String,
    value: String,
) -> Result<Value, String> {
    client.send_request("config.set", json!({ "key": key, "value": value }))
}

// ── Credentials ──────────────────────────────────────────────────────────────

#[tauri::command]
pub fn credentials_unlock(
    client: State<DaemonClient>,
    password: String,
) -> Result<Value, String> {
    client.send_request("credentials.unlock", json!({ "master_password": password }))
}

#[tauri::command]
pub fn credentials_lock(client: State<DaemonClient>) -> Result<Value, String> {
    client.send_request("credentials.lock", json!({}))
}

// ── System ───────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn system_status(client: State<DaemonClient>) -> Result<Value, String> {
    client.send_request("system.status", json!({}))
}

#[tauri::command]
pub fn system_version(client: State<DaemonClient>) -> Result<Value, String> {
    client.send_request("system.version", json!({}))
}

// ── DNS leak protection ──────────────────────────────────────────────────────

#[tauri::command]
pub fn dns_leak_enable(client: State<DaemonClient>, dns_server: String) -> Result<Value, String> {
    client.send_request("dns_leak.enable", json!({ "dns_server": dns_server }))
}

#[tauri::command]
pub fn dns_leak_disable(client: State<DaemonClient>) -> Result<Value, String> {
    client.send_request("dns_leak.disable", json!({}))
}

#[tauri::command]
pub fn dns_leak_status(client: State<DaemonClient>) -> Result<Value, String> {
    client.send_request("dns_leak.status", json!({}))
}

// ── Inspect (MITM) ──────────────────────────────────────────────────────────

#[tauri::command]
pub fn inspect_list(client: State<DaemonClient>, since_seq: u64) -> Result<Value, String> {
    client.send_request("inspect.list", json!({ "since_seq": since_seq }))
}

#[tauri::command]
pub fn inspect_enable(client: State<DaemonClient>) -> Result<Value, String> {
    client.send_request("inspect.enable", json!({}))
}

#[tauri::command]
pub fn inspect_disable(client: State<DaemonClient>) -> Result<Value, String> {
    client.send_request("inspect.disable", json!({}))
}

#[tauri::command]
pub fn inspect_status(client: State<DaemonClient>) -> Result<Value, String> {
    client.send_request("inspect.status", json!({}))
}

#[tauri::command]
pub fn inspect_generate_ca(client: State<DaemonClient>) -> Result<Value, String> {
    client.send_request("inspect.generate_ca", json!({}))
}

// ── Log polling ─────────────────────────────────────────────────────────────

#[tauri::command]
pub fn log_recent(client: State<DaemonClient>, since_seq: u64) -> Result<Value, String> {
    client.send_request("log.recent", json!({ "since_seq": since_seq }))
}

// ── System apps ─────────────────────────────────────────────────────────────

#[tauri::command]
pub fn list_system_apps() -> Result<Value, String> {
    use std::fs;
    use std::path::Path;

    let mut apps: Vec<Value> = Vec::new();
    let dirs = [
        "/usr/share/applications",
        "/var/lib/flatpak/exports/share/applications",
        "/var/lib/snapd/desktop/applications",
        "/snap/current/share/applications",
        &format!("{}/.local/share/applications", std::env::var("HOME").unwrap_or_default()),
    ];

    for dir in &dirs {
        let path = Path::new(dir);
        if !path.exists() { continue; }
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let fpath = entry.path();
                if fpath.extension().map_or(true, |e| e != "desktop") { continue; }
                if let Ok(content) = fs::read_to_string(&fpath) {
                    let mut name = String::new();
                    let mut exec = String::new();
                    let mut icon = String::new();
                    let mut nodisplay = false;
                    for line in content.lines() {
                        if line.starts_with("Name=") && name.is_empty() {
                            name = line[5..].to_string();
                        } else if line.starts_with("Exec=") && exec.is_empty() {
                            // Extract binary path, remove %u %F etc
                            exec = line[5..].split_whitespace().next().unwrap_or("").to_string();
                        } else if line.starts_with("Icon=") && icon.is_empty() {
                            icon = line[5..].to_string();
                        } else if line == "NoDisplay=true" {
                            nodisplay = true;
                        }
                    }
                    if !name.is_empty() && !exec.is_empty() && !nodisplay {
                        apps.push(json!({"name": name, "exec": exec, "icon": icon}));
                    }
                }
            }
        }
    }

    // Sort by name
    apps.sort_by(|a, b| {
        a["name"].as_str().unwrap_or("").to_lowercase()
            .cmp(&b["name"].as_str().unwrap_or("").to_lowercase())
    });

    // Deduplicate by exec
    apps.dedup_by(|a, b| a["exec"] == b["exec"]);

    Ok(Value::Array(apps))
}
