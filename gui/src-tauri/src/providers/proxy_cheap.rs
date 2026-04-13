//! Proxy-Cheap provider integration.
//!
//! API reference (observed 2026-04-13, docs at api.proxy-cheap.com):
//!   GET /proxies
//!   headers: X-Api-Key, X-Api-Secret
//!   response body: { "proxies": [ <Proxy>, ... ] }
//!
//! A single account mixes HTTP, HTTPS and SOCKS5 offerings — we expand each
//! response row into up to two `ImportedProxy` entries (HTTP + SOCKS5 when
//! both ports are populated; `httpsPort`/`socks5Port` are often null).
//!
//! Only proxies with `status == "ACTIVE"` are returned. Pending/expired
//! entries would just show up offline and confuse the user.

use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;

use super::dto::{ImportError, ImportedProxy, ProxyKind};
use super::ProxyProvider;

const API_BASE: &str = "https://api.proxy-cheap.com";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub struct ProxyCheap {
    client: reqwest::Client,
}

impl ProxyCheap {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("ProxiFlare/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client build must not fail with default config");
        Self { client }
    }
}

#[async_trait]
impl ProxyProvider for ProxyCheap {
    fn id(&self) -> &'static str { "proxy-cheap" }
    fn display_name(&self) -> &'static str { "Proxy-Cheap" }

    async fn fetch(&self, api_key: &str, api_secret: &str) -> Result<Vec<ImportedProxy>, ImportError> {
        let url = format!("{}/proxies", API_BASE);
        let resp = self.client
            .get(&url)
            .header("Accept", "application/json")
            .header("X-Api-Key", api_key)
            .header("X-Api-Secret", api_secret)
            .send()
            .await?;

        /* Map auth/other HTTP errors to typed variants BEFORE parsing the
         * body — a 401 page might not be valid JSON. */
        if !resp.status().is_success() {
            return Err(match resp.status() {
                reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => ImportError::Auth,
                s => ImportError::Network(format!("HTTP {s}")),
            });
        }

        let parsed: ApiResponse = resp.json().await
            .map_err(|e| ImportError::Schema(e.to_string()))?;

        let mut out = Vec::with_capacity(parsed.proxies.len());
        for p in parsed.proxies {
            if !matches!(p.status.as_deref(), Some("ACTIVE")) {
                continue;
            }
            let host = p.connection.connect_ip.clone()
                .or_else(|| p.connection.public_ip.clone())
                .unwrap_or_default();
            if host.is_empty() {
                continue; /* unusable row, skip silently */
            }

            let id_str = match &p.id {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                v => v.to_string(),
            };
            let user = p.authentication.username.clone().unwrap_or_default();
            let pass = p.authentication.password.clone().unwrap_or_default();
            let country = p.country_code.clone();
            let isp = p.metadata.as_ref().and_then(|m| m.isp_name.clone());
            let expires = p.expires_at.clone();

            if let Some(port) = p.connection.http_port {
                out.push(ImportedProxy {
                    provider: "proxy-cheap".to_string(),
                    provider_id: id_str.clone(),
                    name: format!("proxy-cheap {} HTTP #{}",
                                  country.as_deref().unwrap_or("?"), id_str),
                    kind: ProxyKind::Http,
                    host: host.clone(),
                    port,
                    username: user.clone(),
                    password: pass.clone(),
                    country_code: country.clone(),
                    isp: isp.clone(),
                    expires_at: expires.clone(),
                });
            }
            if let Some(port) = p.connection.socks5_port {
                out.push(ImportedProxy {
                    provider: "proxy-cheap".to_string(),
                    provider_id: id_str.clone(),
                    name: format!("proxy-cheap {} SOCKS5 #{}",
                                  country.as_deref().unwrap_or("?"), id_str),
                    kind: ProxyKind::Socks5,
                    host: host.clone(),
                    port,
                    username: user.clone(),
                    password: pass.clone(),
                    country_code: country.clone(),
                    isp: isp.clone(),
                    expires_at: expires.clone(),
                });
            }
        }
        Ok(out)
    }
}

/* ─── wire format (matches live API, not the partially-documented schema) ── */

#[derive(Deserialize)]
struct ApiResponse {
    proxies: Vec<ApiProxy>,
}

#[derive(Deserialize)]
struct ApiProxy {
    id: serde_json::Value, /* int in practice, string in docs — accept both */
    status: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    authentication: ApiAuth,
    connection: ApiConnection,
    #[serde(rename = "expiresAt")]
    expires_at: Option<String>,
    metadata: Option<ApiMetadata>,
}

#[derive(Deserialize)]
struct ApiAuth {
    username: Option<String>,
    password: Option<String>,
}

#[derive(Deserialize)]
struct ApiConnection {
    #[serde(rename = "publicIp")]
    public_ip: Option<String>,
    #[serde(rename = "connectIp")]
    connect_ip: Option<String>,
    #[serde(rename = "httpPort")]
    http_port: Option<u16>,
    #[serde(rename = "socks5Port")]
    socks5_port: Option<u16>,
}

#[derive(Deserialize)]
struct ApiMetadata {
    #[serde(rename = "ispName")]
    isp_name: Option<String>,
}
