#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod ipc;

use ipc::DaemonClient;

fn main() {
    let client = DaemonClient::new();
    // Try to connect at startup — GUI can work offline and retry per-request
    let _ = client.connect();

    tauri::Builder::default()
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
        ])
        .run(tauri::generate_context!())
        .expect("error running ProxiFlare");
}
