//! Report generator.
//!
//! Consumes a ranked `Vec<ScoredFinding>`, enriches each entry with:
//! - a redacted `curl` reproduction command built from the original DB request
//! - a pre-written impact statement derived from finding type
//! - a vulnerability classification string
//!
//! Then renders everything through one of three embedded Tera templates.

use std::collections::HashMap;

use rusqlite::Connection;

use crate::attack::{AttackFinding, FindingSource};
use crate::attack::severity::ScoredFinding;
use crate::db::get_request_by_id;
use crate::models::Request;

use super::{
    redact::{redact_auth_value, RedactEngine},
    ReportFinding, ReportFormat, ScoreItem,
};

// ── Embedded Tera templates ───────────────────────────────────────────────────

const TPL_GENERIC:    &str = include_str!("templates/generic.md.tera");
const TPL_HACKERONE:  &str = include_str!("templates/hackerone.md.tera");
const TPL_BUGCROWD:   &str = include_str!("templates/bugcrowd.md.tera");

// ── Proxy / internal headers to omit from curl commands ──────────────────────

const SKIP_HEADERS: &[&str] = &[
    "x-lw-session", "via", "x-forwarded-for", "x-forwarded-host",
    "x-forwarded-proto", "x-forwarded-port", "x-real-ip", "forwarded",
    "proxy-authorization", "proxy-connection", "x-proxy-id",
    "x-bluecoat-via", "x-envoy-original-path", "x-envoy-decorator-operation",
    "host",                   // curl derives host from URL
    "content-length",         // curl sets this automatically
    "transfer-encoding",
];

// ── Public API ────────────────────────────────────────────────────────────────

pub struct ReportGenerator;

impl ReportGenerator {
    /// Produce a one-line-per-finding draft summary for the analyst checkpoint.
    /// The returned string is ready to print to stdout.
    pub fn draft_summary(findings: &[ScoredFinding]) -> String {
        let divider = "─".repeat(80);
        let mut out = String::new();
        out.push_str("=== DRAFT FINDINGS SUMMARY ===\n");
        out.push_str(&divider);
        out.push('\n');

        if findings.is_empty() {
            out.push_str("  (no findings)\n");
        }

        for (i, sf) in findings.iter().enumerate() {
            let f = &sf.finding;
            out.push_str(&format!(
                "  #{:<3} [{score:>5.1}] {sev:<8} [{src}] {title}\n       {detail}\n",
                i + 1,
                score = sf.final_score,
                sev   = f.severity.as_str().to_uppercase(),
                src   = f.source.as_str(),
                title = f.title,
                detail = truncate(&f.details, 100),
            ));
        }

        out.push_str(&divider);
        out
    }

    /// Enrich scored findings with redacted evidence, curl repro, and impact
    /// statements, ready for template rendering.
    pub fn build_report_findings(
        conn:    &Connection,
        scored:  &[ScoredFinding],
        redact:  &RedactEngine,
    ) -> anyhow::Result<Vec<ReportFinding>> {
        let mut out = Vec::with_capacity(scored.len());
        for (i, sf) in scored.iter().enumerate() {
            let f = &sf.finding;

            let curl_repro = build_curl_repro(conn, f, redact);
            let redacted_evidence = f.evidence
                .iter()
                .map(|e| redact.redact(e))
                .collect();

            out.push(ReportFinding {
                index:             i + 1,
                title:             f.title.clone(),
                severity:          f.severity.as_str().to_owned(),
                score:             sf.final_score,
                source:            f.source.as_str().to_owned(),
                method:            f.method.clone(),
                url_pattern:       f.url_pattern.clone(),
                vuln_type:         vuln_type(f),
                details:           redact.redact(&f.details),
                curl_repro,
                redacted_evidence,
                impact:            impact_statement(f),
                score_breakdown:   sf.score_breakdown.iter().map(|s| ScoreItem {
                    name:  s.name.clone(),
                    delta: s.delta,
                    notes: s.notes.clone(),
                }).collect(),
            });
        }
        Ok(out)
    }

    /// Render the given `ReportFinding` list through the selected template.
    /// Returns the rendered report as a `String`.
    pub fn render(
        findings: &[ReportFinding],
        format:   &ReportFormat,
        date:     &str,
    ) -> anyhow::Result<String> {
        let mut tera = tera::Tera::default();
        tera.add_raw_template("generic.md",   TPL_GENERIC)
            .map_err(|e| anyhow::anyhow!("Template parse error (generic): {e}"))?;
        tera.add_raw_template("hackerone.md", TPL_HACKERONE)
            .map_err(|e| anyhow::anyhow!("Template parse error (hackerone): {e}"))?;
        tera.add_raw_template("bugcrowd.md",  TPL_BUGCROWD)
            .map_err(|e| anyhow::anyhow!("Template parse error (bugcrowd): {e}"))?;

        // Build severity count map.
        let mut severity_counts: HashMap<String, usize> = HashMap::new();
        for f in findings {
            *severity_counts.entry(capitalize(&f.severity)).or_insert(0) += 1;
        }

        let ctx_val = serde_json::json!({
            "date":             date,
            "total_findings":   findings.len(),
            "severity_counts":  severity_counts,
            "findings":         findings,
        });

        let ctx = tera::Context::from_value(ctx_val)
            .map_err(|e| anyhow::anyhow!("Tera context error: {e}"))?;

        tera.render(format.template_name(), &ctx)
            .map_err(|e| anyhow::anyhow!("Tera render error: {e}"))
    }
}

// ── Curl repro builder ────────────────────────────────────────────────────────

fn build_curl_repro(
    conn:   &Connection,
    finding: &AttackFinding,
    redact: &RedactEngine,
) -> String {
    // Attempt to fetch the original request from the database.
    let req_opt = finding.request_id
        .and_then(|id| get_request_by_id(conn, id).ok().flatten());

    if let Some(req) = req_opt {
        format_curl(&req, redact)
    } else {
        // Fallback when no DB request is available (e.g. sequence-break steps).
        format!(
            "curl -s -X '{}' \\\n  '{}' \\\n  -H 'Authorization: $AUTH_TOKEN_A' \\\n  -H 'Cookie: $SESSION_COOKIE_A'",
            finding.method,
            finding.url_pattern,
        )
    }
}

fn format_curl(req: &Request, redact: &RedactEngine) -> String {
    let mut args: Vec<String> = Vec::new();

    args.push(format!("curl -s -X '{}'", req.method));
    args.push(format!("'{}'", req.url));

    // Headers
    if let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&req.headers_json) {
        for (name, val) in &map {
            let name_lower = name.to_lowercase();
            if SKIP_HEADERS.contains(&name_lower.as_str()) { continue; }
            let raw = val.as_str().unwrap_or_default();
            let display = curl_header_value(&name_lower, raw);
            args.push(format!("-H '{}: {}'", name, display));
        }
    }

    // Body
    if let Some(ref blob) = req.body_blob {
        if let Ok(body) = std::str::from_utf8(blob) {
            let redacted = redact.redact(body);
            // Escape single quotes for shell safety.
            let escaped = redacted.replace('\'', "'\\''");
            args.push(format!("--data-raw '{}'", escaped));
        }
    }

    args.join(" \\\n  ")
}

/// Return a safe placeholder for sensitive header values, or the raw value for
/// non-sensitive headers.
fn curl_header_value(name_lower: &str, raw: &str) -> String {
    match name_lower {
        "authorization"             => "$AUTH_TOKEN_A".to_owned(),
        "cookie"                    => "$SESSION_COOKIE_A".to_owned(),
        "x-csrf-token" | "x-xsrf-token" => "$CSRF_TOKEN_A".to_owned(),
        n if n.contains("token") || n.contains("apikey") || n.contains("api-key") => {
            format!("$TOKEN_{}", name_lower.to_uppercase().replace('-', "_"))
        }
        _ => {
            // Still redact any embedded auth-looking values.
            if raw.len() > 60 && (raw.starts_with("ey") || raw.starts_with("Bearer")) {
                redact_auth_value(raw)
            } else {
                raw.to_owned()
            }
        }
    }
}

// ── Impact + vuln-type generators ─────────────────────────────────────────────

fn vuln_type(f: &AttackFinding) -> String {
    match f.source {
        FindingSource::Idor => "Insecure Direct Object Reference (IDOR / BOLA)".to_owned(),
        FindingSource::Race => "Race Condition / Time-of-Check Time-of-Use (TOCTOU)".to_owned(),
        FindingSource::SequenceBreak => {
            if f.title.contains("replay_step") {
                "Missing Idempotency / Replay Protection".to_owned()
            } else {
                "Broken Workflow Enforcement / Business Logic Bypass".to_owned()
            }
        }
    }
}

fn impact_statement(f: &AttackFinding) -> String {
    match f.source {
        FindingSource::Idor => {
            "An attacker using valid credentials for their own account can access or \
             modify resources belonging to other users. Depending on the data exposed \
             this could lead to unauthorized information disclosure, account takeover, \
             financial loss, or regulatory exposure (GDPR, PCI-DSS, HIPAA)."
                .to_owned()
        }
        FindingSource::Race => {
            "A race condition allows multiple concurrent requests to bypass single-use \
             restrictions before the server can record the first operation. This enables \
             double-spend attacks, coupon or voucher reuse, inventory manipulation, \
             duplicate order creation, and other state-corruption scenarios."
                .to_owned()
        }
        FindingSource::SequenceBreak => {
            if f.title.contains("replay_step") {
                "Non-idempotent write requests can be replayed without restriction, \
                 potentially causing double charges, duplicate record creation, repeated \
                 privilege escalation, or other unintended state changes."
                    .to_owned()
            } else {
                "Mandatory prerequisite steps in the application workflow can be skipped \
                 or reordered, potentially bypassing identity verification, payment gates, \
                 terms-of-service acceptance, or multi-factor authentication."
                    .to_owned()
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max { return s; }
    // Walk back to a char boundary.
    let mut idx = max;
    while !s.is_char_boundary(idx) { idx -= 1; }
    &s[..idx]
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None    => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}
