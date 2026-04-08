//! Report generation module.
//!
//! Converts a ranked `Vec<ScoredFinding>` into a publishable bug-bounty report.
//! Three output formats are supported: generic Markdown, HackerOne, Bugcrowd.
//!
//! # Redaction
//! Before any evidence string reaches a template the [`RedactEngine`] strips:
//! - `Authorization` header values (first 8 chars kept, rest → `...REDACTED`)
//! - Cookie values (name preserved, value → `[REDACTED]`)
//! - E-mail addresses, phone numbers, SSN and card numbers in body text
//! - Any custom regex patterns from an optional `redact.toml` file
//!
//! Curl reproduction commands use `$AUTH_TOKEN_A`, `$SESSION_COOKIE_A`, etc.
//! as placeholders instead of live credentials.

pub mod generator;
pub mod redact;

pub use generator::ReportGenerator;
pub use redact::{RedactConfig, RedactEngine};

use serde::Serialize;

// ── Output format ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportFormat {
    Markdown,
    HackerOne,
    Bugcrowd,
}

impl ReportFormat {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "hackerone" | "h1" => Self::HackerOne,
            "bugcrowd"  | "bc" => Self::Bugcrowd,
            _                  => Self::Markdown,
        }
    }

    pub fn template_name(&self) -> &'static str {
        match self {
            Self::HackerOne => "hackerone.md",
            Self::Bugcrowd  => "bugcrowd.md",
            Self::Markdown  => "generic.md",
        }
    }
}

// ── Template-facing finding ───────────────────────────────────────────────────

/// An enriched, fully-redacted finding ready for Tera template rendering.
#[derive(Debug, Clone, Serialize)]
pub struct ReportFinding {
    /// 1-based rank index.
    pub index:             usize,
    pub title:             String,
    pub severity:          String,
    pub score:             f32,
    pub source:            String,
    pub method:            String,
    pub url_pattern:       String,
    /// Human-readable vulnerability classification (e.g. "IDOR / BOLA").
    pub vuln_type:         String,
    pub details:           String,
    /// Multi-line curl command using `$AUTH_TOKEN_A` / `$SESSION_COOKIE_A` placeholders.
    pub curl_repro:        String,
    /// Evidence lines after redaction.
    pub redacted_evidence: Vec<String>,
    /// Pre-generated impact statement.
    pub impact:            String,
    pub score_breakdown:   Vec<ScoreItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScoreItem {
    pub name:  String,
    pub delta: f32,
    pub notes: String,
}
