use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;

use crate::models::{EntityLocation, EntityType};

// ── Compiled patterns ─────────────────────────────────────────────────────────

static UUID_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    .unwrap()
});

/// Numeric path segment — up to 18 digits, avoids matching timestamps or very
/// large numbers that are unlikely to be IDs.
static NUMERIC_ID_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\d{1,18}$").unwrap());

/// JWT: three base64url segments each ≥ 20 chars.
static JWT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$").unwrap()
});

/// Slug: lowercase alphanumeric words joined by hyphens, at least two words.
static SLUG_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-z0-9]+-[a-z0-9]+(?:-[a-z0-9]+)*$").unwrap());

// ── Public API ────────────────────────────────────────────────────────────────

/// A single entity extracted from a request, ready for DB insertion
/// (request_id must be filled in by the caller).
#[derive(Debug, Clone)]
pub struct ExtractedEntity {
    pub entity_type: EntityType,
    pub field_name: String,
    pub value: String,
    pub location: EntityLocation,
}

pub struct EntityExtractor;

impl EntityExtractor {
    pub fn new() -> Self {
        Self
    }

    /// Extract all notable entities from a request.
    pub fn extract(
        &self,
        url: &str,
        headers_json: &str,
        body: Option<&[u8]>,
    ) -> Vec<ExtractedEntity> {
        let mut out = Vec::new();
        extract_from_url(url, &mut out);
        extract_from_headers(headers_json, &mut out);
        if let Some(b) = body {
            extract_from_body(b, &mut out);
        }
        // Deduplicate exact (type, field, value, location) triples.
        out.sort_by(|a, b| {
            a.entity_type
                .as_str()
                .cmp(b.entity_type.as_str())
                .then(a.field_name.cmp(&b.field_name))
                .then(a.value.cmp(&b.value))
        });
        out.dedup_by(|a, b| {
            a.entity_type == b.entity_type
                && a.field_name == b.field_name
                && a.value == b.value
                && a.location == b.location
        });
        out
    }

    /// Extract entities contributed by GraphQL variables (called separately
    /// in the sync path where gql_info is already available).
    pub fn extract_gql_variables(
        vars: &std::collections::HashMap<String, Value>,
        out: &mut Vec<ExtractedEntity>,
    ) {
        for (name, val) in vars {
            let s = match val {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => continue,
            };
            out.push(ExtractedEntity {
                entity_type: EntityType::GraphqlVariable,
                field_name: name.clone(),
                value: s,
                location: EntityLocation::Body,
            });
        }
    }
}

impl Default for EntityExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// ── URL extraction ────────────────────────────────────────────────────────────

fn extract_from_url(url: &str, out: &mut Vec<ExtractedEntity>) {
    let parsed = match url::Url::parse(url) {
        Ok(p) => p,
        Err(_) => return,
    };

    // Path segments — UUID/numeric/slug characters are never percent-encoded,
    // so we can match directly against the raw (still-encoded) segment.
    if let Some(segs) = parsed.path_segments() {
        for seg in segs {
            if seg.is_empty() {
                continue;
            }

            if UUID_RE.is_match(seg) {
                push(out, EntityType::Uuid, "path_segment", seg, EntityLocation::Url);
            } else if NUMERIC_ID_RE.is_match(seg) {
                // Only treat pure-digit path segments as IDs (e.g. /users/42)
                push(out, EntityType::NumericId, "path_segment", seg, EntityLocation::Url);
            } else if is_slug(seg) {
                push(out, EntityType::Slug, "path_segment", seg, EntityLocation::Url);
            }
        }
    }

    // Query parameters
    for (key, val) in parsed.query_pairs() {
        let k = key.as_ref();
        let v = val.as_ref();
        let k_low = k.to_lowercase();

        if let Some(et) = classify_key(&k_low) {
            push(out, et, k, v, EntityLocation::Url);
        } else if UUID_RE.is_match(v) {
            push(out, EntityType::Uuid, k, v, EntityLocation::Url);
        } else if NUMERIC_ID_RE.is_match(v) && v.len() <= 10 {
            push(out, EntityType::NumericId, k, v, EntityLocation::Url);
        } else if JWT_RE.is_match(v) {
            push(out, EntityType::JwtToken, k, v, EntityLocation::Url);
        }
    }
}

// ── Header extraction ─────────────────────────────────────────────────────────

fn extract_from_headers(headers_json: &str, out: &mut Vec<ExtractedEntity>) {
    let headers: Value = match serde_json::from_str(headers_json) {
        Ok(v) => v,
        Err(_) => return,
    };
    let obj = match headers.as_object() {
        Some(o) => o,
        None => return,
    };

    for (name, val) in obj {
        let v = match val.as_str() {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };
        let n_low = name.to_lowercase();

        match n_low.as_str() {
            "authorization" => {
                let token = strip_prefix(v, "Bearer ")
                    .or_else(|| strip_prefix(v, "JWT "))
                    .or_else(|| strip_prefix(v, "Token "))
                    .unwrap_or(v);
                let et = if JWT_RE.is_match(token) {
                    EntityType::JwtToken
                } else {
                    EntityType::AuthToken
                };
                push(out, et, name, token, EntityLocation::Header);
            }
            "cookie" => {
                for cookie in v.split(';') {
                    let cookie = cookie.trim();
                    if let Some((k, cv)) = cookie.split_once('=') {
                        let k = k.trim();
                        let cv = cv.trim();
                        let k_low = k.to_lowercase();
                        if k_low.contains("session")
                            || k_low.contains("token")
                            || k_low.contains("auth")
                            || k_low.contains("jwt")
                        {
                            let et = if JWT_RE.is_match(cv) {
                                EntityType::JwtToken
                            } else {
                                EntityType::AuthToken
                            };
                            push(out, et, k, cv, EntityLocation::Cookie);
                        }
                    }
                }
            }
            n if n.contains("csrf") || n.contains("xsrf") => {
                push(out, EntityType::CsrfToken, name, v, EntityLocation::Header);
            }
            n if n.contains("api-key")
                || n.contains("api_key")
                || n.contains("apikey")
                || n == "x-auth-token"
                || n == "x-access-token"
                || n == "x-id-token" =>
            {
                let et = if JWT_RE.is_match(v) {
                    EntityType::JwtToken
                } else {
                    EntityType::AuthToken
                };
                push(out, et, name, v, EntityLocation::Header);
            }
            _ => {}
        }
    }
}

// ── Body extraction ───────────────────────────────────────────────────────────

fn extract_from_body(body: &[u8], out: &mut Vec<ExtractedEntity>) {
    if body.is_empty() {
        return;
    }
    if let Ok(val) = serde_json::from_slice::<Value>(body) {
        extract_json_value(&val, "", 0, out);
    }
}

fn extract_json_value(val: &Value, path: &str, depth: u8, out: &mut Vec<ExtractedEntity>) {
    if depth > 12 {
        return;
    }
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                let child_path = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                let k_low = k.to_lowercase();

                if let Some(s) = v.as_str() {
                    if let Some(et) = classify_key(&k_low) {
                        push(out, et, &child_path, s, EntityLocation::Body);
                        continue; // don't also recurse — value is a leaf
                    }
                    if UUID_RE.is_match(s) {
                        push(out, EntityType::Uuid, &child_path, s, EntityLocation::Body);
                        continue;
                    }
                    if JWT_RE.is_match(s) {
                        push(out, EntityType::JwtToken, &child_path, s, EntityLocation::Body);
                        continue;
                    }
                } else if let Some(n) = v.as_i64() {
                    if k_low == "id"
                        || k_low.ends_with("_id")
                        || k_low.ends_with("id")
                        || k_low == "uid"
                    {
                        push(
                            out,
                            EntityType::NumericId,
                            &child_path,
                            &n.to_string(),
                            EntityLocation::Body,
                        );
                    }
                }
                extract_json_value(v, &child_path, depth + 1, out);
            }
        }
        Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let child_path = format!("{path}[{i}]");
                extract_json_value(v, &child_path, depth + 1, out);
            }
        }
        _ => {}
    }
}

// ── Classification helpers ────────────────────────────────────────────────────

/// Maps a lower-cased key name to a semantic entity type, or None if unknown.
fn classify_key(k: &str) -> Option<EntityType> {
    // CSRF
    if k.contains("csrf") || k.contains("xsrf") || k == "_token" || k == "__requestverificationtoken" {
        return Some(EntityType::CsrfToken);
    }
    // Tokens / auth
    if k == "token"
        || k.ends_with("_token")
        || k.ends_with("token")
        || k == "access_token"
        || k == "refresh_token"
        || k == "id_token"
        || k.contains("api_key")
        || k.contains("apikey")
        || k == "secret"
        || k.contains("access_key")
    {
        return Some(EntityType::AuthToken);
    }
    // Tenant / org
    if k.contains("tenant_id")
        || k.contains("org_id")
        || k.contains("organization_id")
        || k.contains("workspace_id")
        || k.contains("team_id")
        || k.contains("company_id")
        || k.contains("account_id")
        || k == "tenantid"
    {
        return Some(EntityType::TenantIdentifier);
    }
    // User
    if k == "user_id"
        || k == "userid"
        || k == "uid"
        || k == "sub"
        || k == "profile_id"
        || k == "member_id"
        || k.starts_with("user_")
        || k.ends_with("_user_id")
    {
        return Some(EntityType::UserIdentifier);
    }
    None
}

/// Returns true if the segment looks like a content slug (kebab-case, ≥2 words,
/// > 6 chars, all lowercase).
fn is_slug(s: &str) -> bool {
    s.len() > 6 && s.len() < 120 && s == s.to_lowercase() && SLUG_RE.is_match(s)
}

fn strip_prefix<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    s.strip_prefix(prefix)
}

fn push(
    out: &mut Vec<ExtractedEntity>,
    entity_type: EntityType,
    field_name: &str,
    value: &str,
    location: EntityLocation,
) {
    if value.is_empty() {
        return;
    }
    out.push(ExtractedEntity {
        entity_type,
        field_name: field_name.to_owned(),
        value: value.to_owned(),
        location,
    });
}
