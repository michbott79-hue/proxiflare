//! Provider abstraction for importing proxies from external APIs.
//!
//! A provider is any service that sells or distributes proxies and exposes
//! an HTTP API to list the user's inventory. The abstraction lets us add
//! new providers (Bright Data, Oxylabs, IPRoyal, SmartProxy…) without
//! touching the rest of the code: implement `ProxyProvider::fetch` returning
//! a `Vec<ImportedProxy>`, register in `list_providers()`, done.
//!
//! Why here (Tauri/Rust) and not in the C daemon:
//!   - HTTP + TLS + JSON is a three-line job in Rust via reqwest+serde.
//!   - Keeping network I/O in the unprivileged user-side process means a
//!     provider API being slow or flaky doesn't stall the root daemon.
//!   - Credentials never leave the user's GUI process except to the daemon
//!     IPC (which already auths via Unix socket permissions).

pub mod dto;
pub mod proxy_cheap;

use async_trait::async_trait;
use dto::{ImportedProxy, ImportError};

/// Everything a provider needs to expose to the import pipeline.
#[async_trait]
pub trait ProxyProvider: Send + Sync {
    /// Short identifier used in the GUI dropdown ("proxy-cheap").
    fn id(&self) -> &'static str;

    /// Human-readable name shown in the GUI ("Proxy-Cheap").
    fn display_name(&self) -> &'static str;

    /// Fetch all proxies owned by the authenticated account. Implementations
    /// are expected to:
    ///   - time-out at a reasonable bound (we enforce 30s at the HTTP layer)
    ///   - filter out non-usable entries (expired, pending activation)
    ///   - never panic; return `ImportError` on any failure
    async fn fetch(&self, api_key: &str, api_secret: &str) -> Result<Vec<ImportedProxy>, ImportError>;
}

/// Returns a provider by its id, or None if unknown.
pub fn get_provider(id: &str) -> Option<Box<dyn ProxyProvider>> {
    match id {
        "proxy-cheap" => Some(Box::new(proxy_cheap::ProxyCheap::new())),
        _ => None,
    }
}

/// List of supported providers (for populating the GUI dropdown).
pub fn list_providers() -> Vec<(&'static str, &'static str)> {
    vec![("proxy-cheap", "Proxy-Cheap")]
}
