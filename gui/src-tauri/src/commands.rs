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
            "check_interval": check_interval
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
