//! Provider-agnostic data types exchanged between providers and the
//! import pipeline. Keeping the shape minimal means `proxy_cheap.rs`
//! (and future providers) never leaks vendor-specific fields into the
//! rest of the codebase.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Proxy protocol as understood by the ProxiFlare daemon.
/// Mirrors the `type` column of the `proxies` table.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    Socks5,
    Socks4,
    Http,
    Ssh,
}

impl ProxyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProxyKind::Socks5 => "socks5",
            ProxyKind::Socks4 => "socks4",
            ProxyKind::Http => "http",
            ProxyKind::Ssh => "ssh",
        }
    }
}

/// One proxy normalized for insertion into the ProxiFlare DB.
/// We keep enough metadata (country, ISP, expiration) that the GUI
/// can render rich rows without re-querying the provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedProxy {
    pub provider: String,
    pub provider_id: String, /* stringified — providers use various int/uuid ids */
    pub name: String,        /* human-readable, e.g. "proxy-cheap DE #1913863" */
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub country_code: Option<String>,
    pub isp: Option<String>,
    pub expires_at: Option<String>, /* ISO-8601; informational only */
}

/// All the ways an import can fail, shaped so the GUI can display a
/// useful error instead of a generic "something went wrong".
#[derive(Debug, Error, Serialize)]
#[serde(tag = "type", content = "message")]
pub enum ImportError {
    #[error("network: {0}")]
    Network(String),
    #[error("authentication rejected by provider")]
    Auth,
    #[error("provider returned unexpected data: {0}")]
    Schema(String),
    #[error("{0}")]
    Other(String),
}

impl From<reqwest::Error> for ImportError {
    fn from(e: reqwest::Error) -> Self {
        if e.is_timeout() {
            ImportError::Network(format!("timeout: {e}"))
        } else if let Some(status) = e.status() {
            if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
                ImportError::Auth
            } else {
                ImportError::Network(format!("HTTP {status}"))
            }
        } else {
            ImportError::Network(e.to_string())
        }
    }
}

/// Summary returned to the GUI after an import run.
#[derive(Debug, Serialize)]
pub struct ImportResult {
    pub fetched: usize,  /* total proxies returned by the provider */
    pub added: usize,    /* newly inserted into the daemon */
    pub skipped: usize,  /* already present (deduped by host:port) */
    pub failed: usize,   /* daemon refused to insert */
    pub errors: Vec<String>,
}
