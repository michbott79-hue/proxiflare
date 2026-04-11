use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

const SOCKET_PATH: &str = "/run/proxiflare.sock";

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

        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    }
}
