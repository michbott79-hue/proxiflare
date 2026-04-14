#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod ipc;
mod providers;

use ipc::DaemonClient;
use serde_json::json;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use tauri::Manager;

static WE_STARTED_DAEMON: AtomicBool = AtomicBool::new(false);
const SOCKET_PATH: &str = "/run/proxiflare/proxiflare.sock";

fn systemctl(verb: &str) -> bool {
    Command::new("systemctl")
        .args([verb, "proxiflare-daemon"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn daemon_is_active() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "proxiflare-daemon"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn wait_for_socket(timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if Path::new(SOCKET_PATH).exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

fn ensure_daemon_running() {
    if daemon_is_active() {
        return;
    }
    if systemctl("start") {
        WE_STARTED_DAEMON.store(true, Ordering::SeqCst);
        wait_for_socket(Duration::from_secs(5));
    }
}

fn shutdown_daemon(client: &DaemonClient) {
    let _ = client.send_request("system.shutdown", json!({}));
    if WE_STARTED_DAEMON.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(300));
        let _ = systemctl("stop");
    }
}

fn main() {
    ensure_daemon_running();

    let client = DaemonClient::new();
    let _ = client.connect();

    let app = tauri::Builder::default()
        .manage(client)
        .invoke_handler(tauri::generate_handler![
            commands::proxy_list,
            commands::proxy_add,
            commands::proxy_edit,
            commands::proxy_delete,
            commands::proxy_test,
            commands::rule_list,
            commands::rule_add,
            commands::rule_edit,
            commands::rule_delete,
            commands::rule_reorder,
            commands::chain_list,
            commands::chain_add,
            commands::chain_edit,
            commands::chain_delete,
            commands::chain_test,
            commands::config_get,
            commands::config_set,
            commands::credentials_unlock,
            commands::credentials_lock,
            commands::system_status,
            commands::system_version,
            commands::dns_leak_enable,
            commands::dns_leak_disable,
            commands::dns_leak_status,
            commands::list_system_apps,
            commands::log_recent,
            commands::inspect_list,
            commands::inspect_get,
            commands::inspect_enable,
            commands::inspect_disable,
            commands::inspect_status,
            commands::inspect_generate_ca,
            commands::providers_list,
            commands::providers_import,
        ])
        .build(tauri::generate_context!())
        .expect("error running ProxiFlare");

    // Install SIGTERM/SIGINT handlers that trigger a clean shutdown of the
    // daemon (we can't rely solely on Tauri's window events for kill signals).
    {
        let handle = app.handle().clone();
        ctrlc_shutdown(handle);
    }

    app.run(|handle, event| match event {
        tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit => {
            if let Some(client) = handle.try_state::<DaemonClient>() {
                shutdown_daemon(&client);
            }
        }
        _ => {}
    });
}

fn ctrlc_shutdown(handle: tauri::AppHandle) {
    thread::spawn(move || {
        let mut signals = match signal_hook::iterator::Signals::new([
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGHUP,
        ]) {
            Ok(s) => s,
            Err(_) => return,
        };
        for _ in signals.forever() {
            if let Some(client) = handle.try_state::<DaemonClient>() {
                shutdown_daemon(&client);
            }
            handle.exit(0);
            break;
        }
    });
}
