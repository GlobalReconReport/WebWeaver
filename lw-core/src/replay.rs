//! Request reconstructor — builds a `ReplayableRequest` from a captured DB row.
//!
//! Rules
//! -----
//! * Method, URL, and body are taken verbatim from the captured request.
//! * Host, Content-Type, Accept, and all custom app-level headers are kept.
//! * Proxy-added headers (Via, X-Forwarded-For, X-LW-Session, …) are stripped.
//! * Auth substitution: only Cookie, Authorization, and X-CSRF-Token are
//!   replaced — all other headers are left intact.
//! * Body / URL substitution: only the specific entity value being tested is
//!   replaced, using JSON-aware replacement when possible.

use std::collections::HashMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::models::Request;

// ── Header allow / deny lists ─────────────────────────────────────────────────

const PROXY_HEADERS: &[&str] = &[
    "x-lw-session",
    "via",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
    "forwarded",
    "proxy-authorization",
    "proxy-connection",
    "x-proxy-id",
    "x-bluecoat-via",
    "x-envoy-original-path",
    "x-envoy-decorator-operation",
];

const AUTH_HEADERS: &[&str] = &[
    "cookie",
    "authorization",
    "x-csrf-token",
    "x-xsrf-token",
];

// ── Public types ──────────────────────────────────────────────────────────────

/// An HTTP response captured after executing a `ReplayableRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers:     HashMap<String, String>,
    /// Raw body bytes (skipped in serialisation).
    #[serde(skip)]
    pub body:        Vec<u8>,
    /// Body as UTF-8 text, or hex-encoded when binary.
    pub body_text:   String,
    pub elapsed_ms:  u64,
}

/// A fully reconstructed HTTP request ready for replay.
#[derive(Debug, Clone)]
pub struct ReplayableRequest {
    /// Primary key of the source request in the main DB.
    pub original_request_id: i64,
    pub method:  String,
    pub url:     String,
    pub headers: HashMap<String, String>,
    pub body:    Option<Vec<u8>>,
}

// ── Reconstructor ─────────────────────────────────────────────────────────────

pub struct RequestReconstructor;

impl RequestReconstructor {
    /// Build from a captured request, stripping proxy-added headers.
    pub fn build(req: &Request) -> ReplayableRequest {
        let raw: HashMap<String, String> =
            serde_json::from_str(&req.headers_json).unwrap_or_default();

        let headers = raw
            .into_iter()
            .filter(|(k, _)| !is_proxy_header(k))
            .collect();

        ReplayableRequest {
            original_request_id: req.id,
            method:  req.method.clone(),
            url:     req.url.clone(),
            headers,
            body:    req.body_blob.clone(),
        }
    }

    /// Keep everything from the original request except Cookie / Authorization /
    /// X-CSRF-Token, which are replaced by `auth_headers`.
    pub fn build_with_auth_swap(
        req:          &Request,
        auth_headers: &HashMap<String, String>,
    ) -> ReplayableRequest {
        let mut replay = Self::build(req);
        replay.headers.retain(|k, _| !is_auth_header(k));
        for (k, v) in auth_headers {
            if is_auth_header(k) {
                replay.headers.insert(k.clone(), v.clone());
            }
        }
        replay
    }

    /// Replace every occurrence of `old_val` with `new_val` in the URL path /
    /// query string and in the JSON body (JSON-aware when possible).
    pub fn build_with_value_substitution(
        req:     &Request,
        old_val: &str,
        new_val: &str,
    ) -> ReplayableRequest {
        let mut replay = Self::build(req);
        replay.url  = replace_in_url(&replay.url, old_val, new_val);
        if let Some(ref body) = req.body_blob {
            replay.body = Some(substitute_in_body(body, old_val, new_val));
        }
        replay
    }
}

// ── HTTP execution ────────────────────────────────────────────────────────────

impl ReplayableRequest {
    /// Send this request with the provided `reqwest::Client`.
    pub async fn execute(
        &self,
        client: &reqwest::Client,
    ) -> anyhow::Result<HttpResponse> {
        let start  = Instant::now();
        let method = self.method.parse::<reqwest::Method>()
            .unwrap_or(reqwest::Method::GET);

        let mut builder = client.request(method, &self.url);
        for (k, v) in &self.headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        if let Some(ref body) = self.body {
            builder = builder.body(body.clone());
        }

        let resp        = builder.send().await?;
        let status_code = resp.status().as_u16();
        let headers: HashMap<String, String> = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.to_string(), s.to_owned())))
            .collect();

        let body      = resp.bytes().await?.to_vec();
        let body_text = String::from_utf8(body.clone())
            .unwrap_or_else(|_| hex::encode(&body));
        let elapsed_ms = start.elapsed().as_millis() as u64;

        Ok(HttpResponse { status_code, headers, body, body_text, elapsed_ms })
    }
}

// ── Auth context helpers ──────────────────────────────────────────────────────

/// Extract Cookie / Authorization / X-CSRF-Token from a JSON header map.
pub fn extract_auth_context(headers_json: &str) -> HashMap<String, String> {
    let raw: HashMap<String, String> =
        serde_json::from_str(headers_json).unwrap_or_default();
    raw.into_iter()
        .filter(|(k, _)| is_auth_header(k))
        .collect()
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn is_proxy_header(name: &str) -> bool {
    let l = name.to_lowercase();
    PROXY_HEADERS.contains(&l.as_str())
}

fn is_auth_header(name: &str) -> bool {
    let l = name.to_lowercase();
    AUTH_HEADERS.contains(&l.as_str())
}

/// Substitute `old_val` in the URL path and query string only, not in host/scheme.
fn replace_in_url(url: &str, old_val: &str, new_val: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            let new_path = parsed.path().replace(old_val, new_val);
            parsed.set_path(&new_path);
            if let Some(q) = parsed.query() {
                let nq = q.replace(old_val, new_val);
                parsed.set_query(if nq.is_empty() { None } else { Some(&nq) });
            }
            parsed.to_string()
        }
        Err(_) => url.replace(old_val, new_val),
    }
}

fn substitute_in_body(body: &[u8], old_val: &str, new_val: &str) -> Vec<u8> {
    // Try JSON-aware substitution first to preserve structure.
    if let Ok(mut val) = serde_json::from_slice::<serde_json::Value>(body) {
        substitute_json_value(&mut val, old_val, new_val);
        if let Ok(b) = serde_json::to_vec(&val) {
            return b;
        }
    }
    // Fall back to UTF-8 string replacement.
    if let Ok(s) = std::str::from_utf8(body) {
        return s.replace(old_val, new_val).into_bytes();
    }
    body.to_vec()
}

fn substitute_json_value(val: &mut serde_json::Value, old: &str, new: &str) {
    match val {
        serde_json::Value::String(s) if s == old => *s = new.to_owned(),
        serde_json::Value::Object(map) => {
            for v in map.values_mut() {
                substitute_json_value(v, old, new);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                substitute_json_value(v, old, new);
            }
        }
        _ => {}
    }
}
