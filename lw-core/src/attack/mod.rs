//! Attack engine — active scanning modules that send real HTTP requests.
//!
//! All modules consume a `reqwest::Client` created by the caller; use
//! `build_client` to construct one with optional TLS / proxy overrides.

pub mod idor;
pub mod race;
pub mod sequence;
pub mod severity;

use serde::{Deserialize, Serialize};

use crate::auth::Severity;

// ── Unified finding ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingSource {
    Idor,
    SequenceBreak,
    Race,
}

impl FindingSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Idor          => "IDOR",
            Self::SequenceBreak => "SEQUENCE_BREAK",
            Self::Race          => "RACE",
        }
    }
}

/// A finding emitted by any attack module, before final scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackFinding {
    pub source:      FindingSource,
    pub url_pattern: String,
    pub method:      String,
    pub request_id:  Option<i64>,
    pub severity:    Severity,
    /// Raw score from the emitting module (0–100).
    pub score:       f32,
    pub title:       String,
    pub details:     String,
    pub evidence:    Vec<String>,
}

// ── HTTP client factory ───────────────────────────────────────────────────────

/// Build a `reqwest::Client` with optional insecure-TLS and proxy settings.
///
/// * `insecure`  – when `true`, TLS certificate errors are ignored (useful
///   for targets with self-signed certs).
/// * `proxy_url` – optional HTTP/HTTPS proxy URL (e.g. `http://127.0.0.1:8080`
///   to route through Burp Suite).
pub fn build_client(
    insecure:  bool,
    proxy_url: Option<&str>,
) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(insecure);

    if let Some(p) = proxy_url {
        builder = builder.proxy(reqwest::Proxy::all(p)?);
    }

    Ok(builder.build()?)
}
