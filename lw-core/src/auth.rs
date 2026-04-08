//! Auth boundary detector — flags requests where authorization controls look
//! weak, missing, or inconsistent across sessions.
//!
//! **Detection only** — this module never sends network traffic.

use std::collections::HashMap;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::db::{find_session_by_name, get_pairs_for_session, list_sessions};
use crate::graph::normalize_url;

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info     => "info",
            Self::Low      => "low",
            Self::Medium   => "medium",
            Self::High     => "high",
            Self::Critical => "critical",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "critical" => Self::Critical,
            "high"     => Self::High,
            "medium"   => Self::Medium,
            "low"      => Self::Low,
            _          => Self::Info,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthFindingType {
    /// A request succeeded (2xx) with no recognisable auth header.
    UnauthorizedSuccess,
    /// Two sessions with DIFFERENT role labels both got 2xx for the same resource.
    CrossRoleAccess,
    /// A URL pattern matching /admin, /internal, etc. was accessed by a
    /// non-admin role and returned 2xx.
    SensitiveEndpointExposed,
    /// A session obtained a 2xx response but the request had no session cookie
    /// either.
    MissingSessionBinding,
}

impl AuthFindingType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnauthorizedSuccess    => "unauthorized_success",
            Self::CrossRoleAccess        => "cross_role_access",
            Self::SensitiveEndpointExposed => "sensitive_endpoint_exposed",
            Self::MissingSessionBinding  => "missing_session_binding",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "cross_role_access"          => Self::CrossRoleAccess,
            "sensitive_endpoint_exposed" => Self::SensitiveEndpointExposed,
            "missing_session_binding"    => Self::MissingSessionBinding,
            _                            => Self::UnauthorizedSuccess,
        }
    }
}

/// One piece of evidence supporting a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEvidence {
    pub request_id:      i64,
    pub session_name:    String,
    pub role:            String,
    pub status_code:     i64,
    pub has_auth_header: bool,
    pub has_session_cookie: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFinding {
    pub session_a:    String,
    pub session_b:    Option<String>,
    pub url_pattern:  String,
    pub method:       String,
    pub finding_type: AuthFindingType,
    pub severity:     Severity,
    pub details:      String,
    pub evidence:     Vec<AuthEvidence>,
}

// ── Detector ──────────────────────────────────────────────────────────────────

pub struct AuthBoundaryDetector;

impl AuthBoundaryDetector {
    pub fn new() -> Self { Self }

    /// Analyze a single session for internal auth anomalies (e.g., 2xx without
    /// any auth header).
    pub fn analyze_session(
        &self,
        conn:         &Connection,
        session_name: &str,
    ) -> anyhow::Result<Vec<AuthFinding>> {
        let session = find_session_by_name(conn, session_name)?
            .ok_or_else(|| anyhow::anyhow!("Session '{session_name}' not found"))?;

        let pairs = get_pairs_for_session(conn, session.id)?;
        let mut findings: Vec<AuthFinding> = Vec::new();

        for (req, resp) in &pairs {
            if req.is_websocket { continue; }
            let Some(resp) = resp else { continue };
            if !is_success(resp.status_code) { continue; }

            let headers = parse_headers(&req.headers_json);
            let has_auth       = has_auth_header(&headers);
            let has_cookie     = has_session_cookie_header(&headers);
            let url_pat        = normalize_url(&req.url);
            let is_sensitive   = url_looks_sensitive(&url_pat);

            let evidence = vec![AuthEvidence {
                request_id:         req.id,
                session_name:       session_name.to_owned(),
                role:               session.user_role.clone(),
                status_code:        resp.status_code,
                has_auth_header:    has_auth,
                has_session_cookie: has_cookie,
            }];

            // No auth header AND no session cookie → suspicious
            if !has_auth && !has_cookie {
                findings.push(AuthFinding {
                    session_a:    session_name.to_owned(),
                    session_b:    None,
                    url_pattern:  url_pat.clone(),
                    method:       req.method.clone(),
                    finding_type: AuthFindingType::UnauthorizedSuccess,
                    severity:     if is_sensitive { Severity::High } else { Severity::Medium },
                    details: format!(
                        "{} {} returned {} with no auth header or session cookie",
                        req.method, url_pat, resp.status_code
                    ),
                    evidence: evidence.clone(),
                });
            }

            // Sensitive endpoint accessible
            if is_sensitive && (has_auth || has_cookie) {
                // Check if this session's role is non-admin.
                let role_lower = session.user_role.to_lowercase();
                if !role_is_admin(&role_lower) {
                    findings.push(AuthFinding {
                        session_a:    session_name.to_owned(),
                        session_b:    None,
                        url_pattern:  url_pat.clone(),
                        method:       req.method.clone(),
                        finding_type: AuthFindingType::SensitiveEndpointExposed,
                        severity:     Severity::Critical,
                        details: format!(
                            "Sensitive endpoint {} {} returned {} for role '{}'",
                            req.method, url_pat, resp.status_code, session.user_role
                        ),
                        evidence,
                    });
                }
            }
        }

        Ok(findings)
    }

    /// Cross-session analysis: for every URL pattern accessed by multiple
    /// sessions with DIFFERENT roles, flag where all get 2xx.
    pub fn analyze_all_sessions(
        &self,
        conn: &Connection,
    ) -> anyhow::Result<Vec<AuthFinding>> {
        let sessions = list_sessions(conn)?;
        let mut all_findings: Vec<AuthFinding> = Vec::new();

        // Single-session checks.
        for s in &sessions {
            let findings = self.analyze_session(conn, &s.name)?;
            all_findings.extend(findings);
        }

        // Cross-session checks.
        // Build: url_pattern → Vec<(session_name, role, request_id, status, has_auth)>
        let mut pattern_map: PatternMap = HashMap::new();
        for s in &sessions {
            let pairs = get_pairs_for_session(conn, s.id)?;
            for (req, resp) in pairs {
                if req.is_websocket { continue; }
                let Some(resp) = resp else { continue };
                let pat = format!("{}:{}", req.method, normalize_url(&req.url));
                let headers    = parse_headers(&req.headers_json);
                let has_auth   = has_auth_header(&headers);
                let has_cookie = has_session_cookie_header(&headers);
                pattern_map.entry(pat).or_default().push(PatternEntry {
                    request_id:         req.id,
                    session_name:       s.name.clone(),
                    role:               s.user_role.clone(),
                    status_code:        resp.status_code,
                    has_auth_header:    has_auth,
                    has_session_cookie: has_cookie,
                });
            }
        }

        for (pat, entries) in &pattern_map {
            let successful: Vec<&PatternEntry> =
                entries.iter().filter(|e| is_success(e.status_code)).collect();

            if successful.len() < 2 { continue; }

            // Check if multiple distinct roles all succeeded.
            let distinct_roles: std::collections::HashSet<&str> =
                successful.iter().map(|e| e.role.as_str()).collect();

            if distinct_roles.len() < 2 { continue; }

            let (method, url_pat) = split_method_pattern(pat);
            let is_sensitive = url_looks_sensitive(&url_pat);

            let evidence: Vec<AuthEvidence> = successful
                .iter()
                .map(|e| AuthEvidence {
                    request_id:         e.request_id,
                    session_name:       e.session_name.clone(),
                    role:               e.role.clone(),
                    status_code:        e.status_code,
                    has_auth_header:    e.has_auth_header,
                    has_session_cookie: e.has_session_cookie,
                })
                .collect();

            let roles_str: Vec<&str> = distinct_roles.iter().copied().collect();
            let sev = if is_sensitive { Severity::Critical } else { Severity::High };

            all_findings.push(AuthFinding {
                session_a:    successful[0].session_name.clone(),
                session_b:    Some(successful[1].session_name.clone()),
                url_pattern:  url_pat.clone(),
                method:       method.to_owned(),
                finding_type: AuthFindingType::CrossRoleAccess,
                severity:     sev,
                details: format!(
                    "{} {} succeeded for multiple roles: {}",
                    method, url_pat,
                    roles_str.join(", ")
                ),
                evidence,
            });
        }

        // Deduplicate and sort by severity.
        all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        Ok(all_findings)
    }
}

impl Default for AuthBoundaryDetector {
    fn default() -> Self { Self::new() }
}

// ── Heuristics ────────────────────────────────────────────────────────────────

const SENSITIVE_PATTERNS: &[&str] = &[
    "/admin",
    "/internal",
    "/debug",
    "/config",
    "/management",
    "/superuser",
    "/system",
    "/settings",
    "/users/",       // accessing another user's resource
    "/_internal",
    "/__admin",
    "/api/admin",
    "/api/internal",
    "/ops/",
    "/staff/",
    "/backoffice",
    "/console",
    "/dashboard/admin",
];

fn url_looks_sensitive(pattern: &str) -> bool {
    let lower = pattern.to_lowercase();
    SENSITIVE_PATTERNS.iter().any(|p| lower.contains(p))
}

fn role_is_admin(role_lower: &str) -> bool {
    matches!(
        role_lower,
        "admin" | "administrator" | "superuser" | "root" | "staff" | "superadmin"
    )
}

fn is_success(code: i64) -> bool {
    (200..300).contains(&code)
}

fn has_auth_header(headers: &HashMap<String, String>) -> bool {
    headers.keys().any(|k| {
        let kl = k.to_lowercase();
        kl == "authorization"
            || kl.contains("api-key")
            || kl.contains("api_key")
            || kl.contains("apikey")
            || kl == "x-auth-token"
            || kl == "x-access-token"
            || kl == "x-id-token"
    })
}

fn has_session_cookie_header(headers: &HashMap<String, String>) -> bool {
    if let Some(cookie_hdr) = headers.get("cookie").or_else(|| headers.get("Cookie")) {
        let lower = cookie_hdr.to_lowercase();
        return lower.contains("session")
            || lower.contains("token")
            || lower.contains("auth")
            || lower.contains("jwt")
            || lower.contains("access");
    }
    false
}

fn parse_headers(json: &str) -> HashMap<String, String> {
    serde_json::from_str::<Value>(json)
        .ok()
        .and_then(|v| v.into_object())
        .map(|obj| {
            obj.into_iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

fn split_method_pattern(s: &str) -> (&str, String) {
    if let Some((method, pat)) = s.split_once(':') {
        (method, pat.to_owned())
    } else {
        ("GET", s.to_owned())
    }
}

// ── Internal types ────────────────────────────────────────────────────────────

struct PatternEntry {
    request_id:         i64,
    session_name:       String,
    role:               String,
    status_code:        i64,
    has_auth_header:    bool,
    has_session_cookie: bool,
}

type PatternMap = HashMap<String, Vec<PatternEntry>>;

// ── serde_json helper (into_object) ──────────────────────────────────────────

trait IntoObject {
    fn into_object(self) -> Option<serde_json::Map<String, Value>>;
}
impl IntoObject for Value {
    fn into_object(self) -> Option<serde_json::Map<String, Value>> {
        if let Value::Object(m) = self { Some(m) } else { None }
    }
}
