//! Flow differ — align two sessions by URL pattern + method and surface:
//!   * status-code deltas
//!   * JSON structural diffs
//!   * IDOR candidates (Session B sees Session A's entity values)

use std::collections::{HashMap, HashSet};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::db::{find_session_by_name, get_pairs_for_session};
use crate::graph::normalize_url;
use crate::models::{Request, Response, Session};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct DiffResult {
    pub session_a:      String,
    pub session_b:      String,
    pub aligned_count:  usize,
    /// URL patterns accessed only by session A.
    pub only_in_a:      Vec<String>,
    /// URL patterns accessed only by session B.
    pub only_in_b:      Vec<String>,
    pub aligned_pairs:  Vec<AlignedPair>,
    pub idor_candidates: Vec<IdorCandidate>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AlignedPair {
    pub url_pattern:  String,
    pub method:       String,
    pub request_id_a: i64,
    pub request_id_b: i64,
    pub status_a:     Option<i64>,
    pub status_b:     Option<i64>,
    pub status_match: bool,
    pub json_diff:    Option<JsonDiff>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonDiff {
    pub keys_only_in_a:  Vec<String>,
    pub keys_only_in_b:  Vec<String>,
    pub common_key_count: usize,
    pub changed_values:  Vec<JsonValueChange>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonValueChange {
    pub path:    String,
    pub value_a: String,
    pub value_b: String,
}

/// A request where Session B's response contains a value that was first seen
/// in Session A's responses — potential IDOR / broken object-level access control.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdorCandidate {
    pub url_pattern:   String,
    pub method:        String,
    pub request_id_b:  i64,
    /// The entity value from session A that appeared in session B's response.
    pub leaked_value:  String,
    /// Path inside the response body where the value was found (if JSON).
    pub field_path:    String,
    /// 0.0–1.0: higher when value is a UUID (more unique).
    pub confidence:    f32,
}

// ── FlowDiffer ────────────────────────────────────────────────────────────────

pub struct FlowDiffer;

impl FlowDiffer {
    pub fn new() -> Self { Self }

    /// Compare session `name_a` (privileged / reference) against `name_b`
    /// (target under test).
    pub fn diff(
        &self,
        conn:   &Connection,
        name_a: &str,
        name_b: &str,
    ) -> anyhow::Result<DiffResult> {
        let session_a = find_session_by_name(conn, name_a)?
            .ok_or_else(|| anyhow::anyhow!("Session '{name_a}' not found"))?;
        let session_b = find_session_by_name(conn, name_b)?
            .ok_or_else(|| anyhow::anyhow!("Session '{name_b}' not found"))?;

        let pairs_a = get_pairs_for_session(conn, session_a.id)?;
        let pairs_b = get_pairs_for_session(conn, session_b.id)?;

        // Build pattern→(request, response) maps
        let map_a = index_by_pattern(&pairs_a);
        let map_b = index_by_pattern(&pairs_b);

        // Compute set differences
        let keys_a: HashSet<&str> = map_a.keys().map(String::as_str).collect();
        let keys_b: HashSet<&str> = map_b.keys().map(String::as_str).collect();

        let only_in_a: Vec<String> = keys_a
            .difference(&keys_b)
            .map(|s| s.to_string())
            .collect();
        let only_in_b: Vec<String> = keys_b
            .difference(&keys_a)
            .map(|s| s.to_string())
            .collect();

        // Build response entity index for session A (UUIDs from response bodies).
        let a_entity_values = collect_response_uuids(conn, &session_a)?;

        let mut aligned_pairs: Vec<AlignedPair> = Vec::new();
        let mut idor_candidates: Vec<IdorCandidate> = Vec::new();

        for (pattern, (req_a, resp_a)) in &map_a {
            let Some((req_b, resp_b)) = map_b.get(pattern) else { continue };

            let status_a = resp_a.as_ref().map(|r| r.status_code);
            let status_b = resp_b.as_ref().map(|r| r.status_code);

            let json_diff = compute_json_diff(
                resp_a.as_ref().and_then(|r| r.body_blob.as_deref()),
                resp_b.as_ref().and_then(|r| r.body_blob.as_deref()),
            );

            aligned_pairs.push(AlignedPair {
                url_pattern:  pattern.clone(),
                method:       req_a.method.clone(),
                request_id_a: req_a.id,
                request_id_b: req_b.id,
                status_a,
                status_b,
                status_match: status_a == status_b,
                json_diff,
            });

            // IDOR check: does session B's response contain session A's UUIDs?
            if let Some(ref resp_b_inner) = resp_b {
                if let Some(ref body) = resp_b_inner.body_blob {
                    let body_str = String::from_utf8_lossy(body);
                    for uuid in &a_entity_values {
                        if body_str.contains(uuid.as_str()) {
                            let field_path =
                                find_json_path_for_value(body, uuid).unwrap_or_default();
                            idor_candidates.push(IdorCandidate {
                                url_pattern:  pattern.clone(),
                                method:       req_b.method.clone(),
                                request_id_b: req_b.id,
                                leaked_value: uuid.clone(),
                                field_path,
                                confidence:   0.9, // UUIDs are highly unique
                            });
                        }
                    }
                }
            }
        }

        let aligned_count = aligned_pairs.len();

        Ok(DiffResult {
            session_a: name_a.to_owned(),
            session_b: name_b.to_owned(),
            aligned_count,
            only_in_a,
            only_in_b,
            aligned_pairs,
            idor_candidates,
        })
    }
}

impl Default for FlowDiffer {
    fn default() -> Self { Self::new() }
}

// ── JSON structural diff ──────────────────────────────────────────────────────

fn compute_json_diff(body_a: Option<&[u8]>, body_b: Option<&[u8]>) -> Option<JsonDiff> {
    let val_a = body_a.and_then(|b| serde_json::from_slice::<Value>(b).ok())?;
    let val_b = body_b.and_then(|b| serde_json::from_slice::<Value>(b).ok())?;

    match (&val_a, &val_b) {
        (Value::Object(_), Value::Object(_)) => {}
        _ => return None, // only diff objects
    }

    let mut diff = JsonDiff {
        keys_only_in_a:   Vec::new(),
        keys_only_in_b:   Vec::new(),
        common_key_count: 0,
        changed_values:   Vec::new(),
    };

    diff_json_values(&val_a, &val_b, "", &mut diff);
    Some(diff)
}

fn diff_json_values(a: &Value, b: &Value, path: &str, diff: &mut JsonDiff) {
    match (a, b) {
        (Value::Object(ma), Value::Object(mb)) => {
            let keys_a: HashSet<&String> = ma.keys().collect();
            let keys_b: HashSet<&String> = mb.keys().collect();

            for k in keys_a.difference(&keys_b) {
                diff.keys_only_in_a
                    .push(if path.is_empty() { k.to_string() } else { format!("{path}.{k}") });
            }
            for k in keys_b.difference(&keys_a) {
                diff.keys_only_in_b
                    .push(if path.is_empty() { k.to_string() } else { format!("{path}.{k}") });
            }
            for k in keys_a.intersection(&keys_b) {
                diff.common_key_count += 1;
                let child = if path.is_empty() { k.to_string() } else { format!("{path}.{k}") };
                diff_json_values(&ma[*k], &mb[*k], &child, diff);
            }
        }
        (Value::Array(aa), Value::Array(ab)) => {
            for (i, (va, vb)) in aa.iter().zip(ab.iter()).enumerate() {
                diff_json_values(va, vb, &format!("{path}[{i}]"), diff);
            }
        }
        (va, vb) if va != vb => {
            // Leaf values differ — only record when at least one is a string
            // (avoid noisy numeric comparisons).
            let sa = value_to_display(va);
            let sb = value_to_display(vb);
            if !path.is_empty() {
                diff.changed_values.push(JsonValueChange {
                    path:    path.to_owned(),
                    value_a: sa,
                    value_b: sb,
                });
            }
        }
        _ => {}
    }
}

fn value_to_display(v: &Value) -> String {
    match v {
        Value::String(s)  => s.clone(),
        Value::Number(n)  => n.to_string(),
        Value::Bool(b)    => b.to_string(),
        Value::Null       => "null".into(),
        Value::Array(_)   => "[…]".into(),
        Value::Object(_)  => "{…}".into(),
    }
}

// ── IDOR helpers ──────────────────────────────────────────────────────────────

/// Collect all UUID-shaped values from session A's response bodies.
fn collect_response_uuids(
    conn:    &Connection,
    session: &Session,
) -> anyhow::Result<Vec<String>> {
    let pairs = get_pairs_for_session(conn, session.id)?;
    let mut uuids = HashSet::new();
    for (_, resp) in pairs {
        if let Some(resp) = resp {
            if let Some(body) = resp.body_blob {
                collect_uuids_from_body(&body, &mut uuids);
            }
        }
    }
    Ok(uuids.into_iter().collect())
}

fn collect_uuids_from_body(body: &[u8], out: &mut HashSet<String>) {
    if let Ok(val) = serde_json::from_slice::<Value>(body) {
        collect_uuids_from_value(&val, out);
    }
}

fn collect_uuids_from_value(val: &Value, out: &mut HashSet<String>) {
    match val {
        Value::String(s) if is_uuid(s) => { out.insert(s.clone()); }
        Value::Object(map) => map.values().for_each(|v| collect_uuids_from_value(v, out)),
        Value::Array(arr)  => arr.iter().for_each(|v| collect_uuids_from_value(v, out)),
        _ => {}
    }
}

fn is_uuid(s: &str) -> bool {
    s.len() == 36 && {
        let b = s.as_bytes();
        b[8] == b'-' && b[13] == b'-' && b[18] == b'-' && b[23] == b'-'
    }
}

/// Try to find the JSON path where `needle` appears in `body`.
fn find_json_path_for_value(body: &[u8], needle: &str) -> Option<String> {
    let val = serde_json::from_slice::<Value>(body).ok()?;
    find_in_json(&val, needle, "")
}

fn find_in_json(val: &Value, needle: &str, path: &str) -> Option<String> {
    match val {
        Value::String(s) if s == needle => Some(path.to_owned()),
        Value::Object(map) => {
            for (k, v) in map {
                let p = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                if let Some(found) = find_in_json(v, needle, &p) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                if let Some(found) = find_in_json(v, needle, &format!("{path}[{i}]")) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

// ── Index helpers ─────────────────────────────────────────────────────────────

type PairMap = HashMap<String, (Request, Option<Response>)>;

/// Group request-response pairs by `(method, url_pattern)` key.
/// If multiple requests share the same pattern (e.g., multiple GETs to the
/// same resource), we keep the last one (most representative).
fn index_by_pattern(pairs: &[(Request, Option<Response>)]) -> PairMap {
    let mut map: PairMap = HashMap::new();
    for (req, resp) in pairs {
        if req.is_websocket { continue; }
        let key = format!("{}:{}", req.method.to_uppercase(), normalize_url(&req.url));
        map.insert(key, (req.clone(), resp.clone()));
    }
    map
}
