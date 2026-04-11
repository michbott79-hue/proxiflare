use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tauri::{AppHandle, Emitter};

const SOCKET_PATH: &str = "/run/proxiflare/proxiflare.sock";

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

pub struct DaemonClient {
    stream: Mutex<Option<UnixStream>>,
}

impl DaemonClient {
    pub fn new() -> Self {
        Self {
            stream: Mutex::new(None),
        }
    }

    pub fn connect(&self) -> Result<(), String> {
        let stream = UnixStream::connect(SOCKET_PATH)
            .map_err(|e| format!("Failed to connect to daemon: {}", e))?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();
        *self.stream.lock().unwrap() = Some(stream);
        Ok(())
    }

    pub fn send_request(&self, method: &str, params: Value) -> Result<Value, String> {
        let mut guard = self.stream.lock().unwrap();

        // Auto-reconnect if not connected
        if guard.is_none() {
            let stream = UnixStream::connect(SOCKET_PATH)
                .map_err(|e| format!("Daemon not reachable: {}", e))?;
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .ok();
            *guard = Some(stream);
        }

        let stream = guard.as_mut().ok_or("Not connected to daemon")?;

        let id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let request = json!({
            "id": id,
            "method": method,
            "params": params
        });

        let mut msg = serde_json::to_string(&request)
            .map_err(|e| format!("JSON serialize error: {}", e))?;
        msg.push('\n');

        stream
            .write_all(msg.as_bytes())
            .map_err(|e| format!("Write error: {}", e))?;

        // Read response byte-by-byte until '\n' to avoid BufReader ownership issues
        let mut response_bytes: Vec<u8> = Vec::with_capacity(4096);
        let mut buf = [0u8; 1];
        loop {
            use std::io::Read;
            match stream.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    if buf[0] == b'\n' {
                        break;
                    }
                    response_bytes.push(buf[0]);
                }
                Err(e) => {
                    // Connection broken — clear so next call reconnects
                    *guard = None;
                    return Err(format!("Read error: {}", e));
                }
            }
        }

        let response_line = String::from_utf8(response_bytes)
            .map_err(|e| format!("UTF-8 error: {}", e))?;

        if response_line.is_empty() {
            *guard = None;
            return Err("Daemon closed connection".to_string());
        }

        let response: Value = serde_json::from_str(&response_line)
            .map_err(|e| format!("JSON parse error: {}", e))?;

        if let Some(error) = response.get("error") {
            return Err(error["message"]
                .as_str()
                .unwrap_or("Unknown error")
                .to_string());
        }

        // Daemon double-wraps: {"id":N, "result": {"result": <data>}}
        // Unwrap both levels to return just <data>
        let outer = response.get("result").cloned().unwrap_or(Value::Null);
        if let Some(inner) = outer.get("result") {
            Ok(inner.clone())
        } else {
            Ok(outer)
        }
    }

    /// Starts a background thread that opens a SECOND, dedicated connection to the daemon,
    /// subscribes to log events, and emits them as Tauri events.
    /// This avoids any contention with the request/response stream.
    pub fn start_event_listener(&self, app: AppHandle) {
        // Open a dedicated connection just for push events
        let mut event_stream = match UnixStream::connect(SOCKET_PATH) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[proxiflare] event listener: cannot connect to daemon: {}", e);
                return;
            }
        };

        // Send log.subscribe on this dedicated connection
        let sub_req = json!({"id": 0, "method": "log.subscribe", "params": {}});
        let mut sub_msg = serde_json::to_string(&sub_req).unwrap_or_default();
        sub_msg.push('\n');
        if event_stream.write_all(sub_msg.as_bytes()).is_err() {
            eprintln!("[proxiflare] event listener: failed to send log.subscribe");
            return;
        }

        std::thread::spawn(move || {
            use std::io::Read;
            let mut buf: Vec<u8> = Vec::with_capacity(8192);
            let mut byte = [0u8; 1];

            loop {
                match event_stream.read(&mut byte) {
                    Ok(0) => {
                        eprintln!("[proxiflare] event listener: daemon closed connection");
                        break;
                    }
                    Ok(_) => {
                        if byte[0] == b'\n' {
                            if let Ok(line) = std::str::from_utf8(&buf) {
                                if let Ok(json_val) = serde_json::from_str::<Value>(line) {
                                    // Push events have an "event" field and no numeric id
                                    let is_push = json_val.get("event").is_some()
                                        && !json_val.get("id").and_then(|v| v.as_u64()).is_some();

                                    if is_push {
                                        let event_type = json_val["event"]
                                            .as_str()
                                            .unwrap_or("unknown");
                                        let data = json_val
                                            .get("data")
                                            .cloned()
                                            .unwrap_or(Value::Null);

                                        match event_type {
                                            "log.entry" => {
                                                let _ = app.emit("log-entry", &data);
                                            }
                                            "stats.update" => {
                                                let _ = app.emit("stats-update", &data);
                                            }
                                            "proxy.status" => {
                                                let _ = app.emit("proxy-status", &data);
                                            }
                                            _ => {}
                                        }
                                    }
                                    // else: it's the subscribe response (id=0) — discard
                                }
                            }
                            buf.clear();
                        } else {
                            buf.push(byte[0]);
                        }
                    }
                    Err(e) => {
                        eprintln!("[proxiflare] event listener: read error: {}", e);
                        break;
                    }
                }
            }
        });
    }
}
