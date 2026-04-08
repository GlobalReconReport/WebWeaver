//! Dependency tracker — finds value flows between responses and subsequent
//! requests within a session (Set-Cookie → Cookie, CSRF tokens, entity IDs, …).

use std::collections::HashMap;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::db::get_pairs_for_session;

/// Minimum byte length for a value to be tracked (avoids noisy short strings).
const MIN_VAL_LEN: usize = 8;

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DependencyEdgeType {
    Cookie,      // Set-Cookie → Cookie header
    CsrfToken,   // CSRF value in response → request header/body
    AuthToken,   // Bearer/JWT in response → Authorization header
    EntityId,    // UUID/numeric ID in response → URL/body of later request
    RedirectUrl, // Location header → next request URL
    WsPayload,   // Value extracted from a WebSocket message payload
    Generic,     // Catch-all for other value flows
}

impl DependencyEdgeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cookie      => "cookie",
            Self::CsrfToken   => "csrf_token",
            Self::AuthToken   => "auth_token",
            Self::EntityId    => "entity_id",
            Self::RedirectUrl => "redirect_url",
            Self::WsPayload   => "ws_payload",
            Self::Generic     => "generic",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "cookie"       => Self::Cookie,
            "csrf_token"   => Self::CsrfToken,
            "auth_token"   => Self::AuthToken,
            "entity_id"    => Self::EntityId,
            "redirect_url" => Self::RedirectUrl,
            "ws_payload"   => Self::WsPayload,
            _              => Self::Generic,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DependencySourceType {
    Response,
    WsMessage,
}

impl DependencySourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Response  => "response",
            Self::WsMessage => "ws_message",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "ws_message" => Self::WsMessage,
            _            => Self::Response,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub id:                Option<i64>,
    pub session_id:        i64,
    pub source_type:       DependencySourceType,
    /// responses.id  OR  requests.id (when source_type = WsMessage)
    pub source_id:         i64,
    pub target_request_id: i64,
    pub field_name:        String,
    pub value:             String,
    pub edge_type:         DependencyEdgeType,
}

// ── Tracker ───────────────────────────────────────────────────────────────────

pub struct DependencyTracker;

impl DependencyTracker {
    pub fn new() -> Self { Self }

    /// Walk every request-response pair in chronological order and emit edges
    /// wherever a value first seen in a response (or WS message payload) is
    /// later reused in a request.
    pub fn analyze_session(
        &self,
        conn: &Connection,
        session_id: i64,
    ) -> anyhow::Result<Vec<DependencyEdge>> {
        let pairs = get_pairs_for_session(conn, session_id)?;

        // value → (source_type, source_id, field_path, edge_type)
        let mut origins: HashMap<String, Origin> = HashMap::new();
        let mut edges: Vec<DependencyEdge> = Vec::new();

        for (req, maybe_resp) in &pairs {
            // ── Check request values against accumulated origins ──────────
            for (field_path, value) in extract_request_values(req) {
                if let Some(origin) = origins.get(&value) {
                    edges.push(DependencyEdge {
                        id:                None,
                        session_id,
                        source_type:       origin.source_type.clone(),
                        source_id:         origin.source_id,
                        target_request_id: req.id,
                        field_name:        field_path,
                        value:             value.clone(),
                        edge_type:         origin.edge_type.clone(),
                    });
                }
            }

            // ── Index this response's values for future requests ──────────
            if let Some(resp) = maybe_resp {
                for (field_path, value, etype) in extract_response_values(resp) {
                    origins.entry(value).or_insert(Origin {
                        source_type: DependencySourceType::Response,
                        source_id:   resp.id,
                        field_path,
                        edge_type:   etype,
                    });
                }
            }

            // ── WebSocket messages: treat payload as response-like ────────
            if req.is_websocket {
                if let Some(ref body) = req.body_blob {
                    for (field_path, value) in extract_body_values(body) {
                        origins.entry(value).or_insert(Origin {
                            source_type: DependencySourceType::WsMessage,
                            source_id:   req.id,
                            field_path,
                            edge_type:   DependencyEdgeType::WsPayload,
                        });
                    }
                }
            }
        }

        Ok(edges)
    }
}

impl Default for DependencyTracker {
    fn default() -> Self { Self::new() }
}

// ── Value extraction — responses (provide values) ────────────────────────────

fn extract_response_values(
    resp: &crate::models::Response,
) -> Vec<(String, String, DependencyEdgeType)> {
    let mut out: Vec<(String, String, DependencyEdgeType)> = Vec::new();

    // Headers
    if let Ok(Value::Object(hdrs)) = serde_json::from_str::<Value>(&resp.headers_json) {
        for (name, val) in &hdrs {
            let v = match val.as_str() { Some(s) => s, None => continue };
            let n = name.to_lowercase();
            match n.as_str() {
                "set-cookie" => {
                    // Extract the cookie value (before first ';')
                    if let Some(first) = v.split(';').next() {
                        if let Some((_, cv)) = first.split_once('=') {
                            let cv = cv.trim();
                            if cv.len() >= MIN_VAL_LEN {
                                out.push((
                                    "header:set-cookie".to_owned(),
                                    cv.to_owned(),
                                    DependencyEdgeType::Cookie,
                                ));
                            }
                        }
                    }
                }
                "location" => {
                    if v.len() >= MIN_VAL_LEN {
                        out.push((
                            "header:location".into(),
                            v.to_owned(),
                            DependencyEdgeType::RedirectUrl,
                        ));
                    }
                }
                n if n.contains("csrf") || n.contains("xsrf") => {
                    if v.len() >= MIN_VAL_LEN {
                        out.push((
                            format!("header:{name}"),
                            v.to_owned(),
                            DependencyEdgeType::CsrfToken,
                        ));
                    }
                }
                n if n.contains("token") || n.contains("auth") => {
                    if v.len() >= 16 {
                        out.push((
                            format!("header:{name}"),
                            v.to_owned(),
                            DependencyEdgeType::AuthToken,
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    // Body
    if let Some(ref body) = resp.body_blob {
        out.extend(extract_body_values(body).into_iter().map(|(f, v)| {
            // Classify by value shape
            let et = if is_jwt(&v) {
                DependencyEdgeType::AuthToken
            } else if is_uuid(&v) {
                DependencyEdgeType::EntityId
            } else {
                DependencyEdgeType::Generic
            };
            (f, v, et)
        }));
    }

    out
}

// ── Value extraction — requests (consume values) ─────────────────────────────

fn extract_request_values(req: &crate::models::Request) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();

    // Headers
    if let Ok(Value::Object(hdrs)) = serde_json::from_str::<Value>(&req.headers_json) {
        for (name, val) in &hdrs {
            let v = match val.as_str() { Some(s) => s, None => continue };
            let n = name.to_lowercase();
            match n.as_str() {
                "cookie" => {
                    for cookie in v.split(';') {
                        let cookie = cookie.trim();
                        if let Some((k, cv)) = cookie.split_once('=') {
                            let cv = cv.trim();
                            if cv.len() >= MIN_VAL_LEN {
                                out.push((format!("cookie:{}", k.trim()), cv.to_owned()));
                            }
                        }
                    }
                }
                "authorization" => {
                    let tok = v.strip_prefix("Bearer ")
                        .or_else(|| v.strip_prefix("JWT "))
                        .or_else(|| v.strip_prefix("Token "))
                        .unwrap_or(v);
                    if tok.len() >= MIN_VAL_LEN {
                        out.push(("header:authorization".into(), tok.to_owned()));
                    }
                }
                n if n.contains("csrf") || n.contains("xsrf") => {
                    if v.len() >= MIN_VAL_LEN {
                        out.push((format!("header:{name}"), v.to_owned()));
                    }
                }
                n if n.contains("token") || n.contains("api-key") || n.contains("api_key") => {
                    if v.len() >= MIN_VAL_LEN {
                        out.push((format!("header:{name}"), v.to_owned()));
                    }
                }
                _ => {}
            }
        }
    }

    // URL path segments (UUIDs or long numeric IDs)
    if let Ok(parsed) = url::Url::parse(&req.url) {
        if let Some(segs) = parsed.path_segments() {
            for seg in segs {
                if seg.len() >= MIN_VAL_LEN && (is_uuid(seg) || seg.chars().all(char::is_numeric)) {
                    out.push(("url:path_segment".into(), seg.to_owned()));
                }
            }
        }
        // Query params with ID-like values
        for (k, v) in parsed.query_pairs() {
            let v = v.as_ref();
            if v.len() >= MIN_VAL_LEN && (is_uuid(v) || is_numeric_id(v)) {
                out.push((format!("url:query:{}", k.as_ref()), v.to_owned()));
            }
        }
    }

    // Body (JSON)
    if let Some(ref body) = req.body_blob {
        out.extend(extract_body_values(body));
    }

    out
}

// ── Body / JSON value extraction (shared) ────────────────────────────────────

/// Returns (field_path, value) pairs from a JSON body.
pub fn extract_body_values(body: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Ok(val) = serde_json::from_slice::<Value>(body) {
        extract_json(val, "", 0, &mut out);
    }
    out
}

fn extract_json(val: Value, path: &str, depth: u8, out: &mut Vec<(String, String)>) {
    if depth > 12 { return; }
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                let child = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                if let Some(s) = v.as_str() {
                    if s.len() >= MIN_VAL_LEN {
                        out.push((child.clone(), s.to_owned()));
                    }
                } else if let Some(n) = v.as_i64() {
                    let s = n.to_string();
                    if s.len() >= 4 {
                        out.push((child.clone(), s));
                    }
                }
                extract_json(v, &child, depth + 1, out);
            }
        }
        Value::Array(arr) => {
            for (i, v) in arr.into_iter().enumerate() {
                extract_json(v, &format!("{path}[{i}]"), depth + 1, out);
            }
        }
        _ => {}
    }
}

// ── Value classifiers ─────────────────────────────────────────────────────────

fn is_uuid(s: &str) -> bool {
    s.len() == 36 && {
        let b = s.as_bytes();
        b[8] == b'-' && b[13] == b'-' && b[18] == b'-' && b[23] == b'-'
    }
}

fn is_jwt(s: &str) -> bool {
    let parts: Vec<&str> = s.splitn(4, '.').collect();
    parts.len() == 3 && parts.iter().all(|p| p.len() >= 4)
}

fn is_numeric_id(s: &str) -> bool {
    s.len() >= 4 && s.len() <= 18 && s.chars().all(char::is_numeric)
}

// ── Internal types ────────────────────────────────────────────────────────────

struct Origin {
    source_type: DependencySourceType,
    source_id:   i64,
    #[allow(dead_code)]
    field_path:  String,
    edge_type:   DependencyEdgeType,
}
