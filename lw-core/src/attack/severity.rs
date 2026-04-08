//! Severity heuristic — scores and ranks `AttackFinding` values across five
//! dimensions:
//!
//! 1. **Base severity** — from the emitting module's own severity label.
//! 2. **HTTP method** — write methods (POST/PUT/PATCH/DELETE) score higher.
//! 3. **Sensitive field exposure** — email, phone, SSN, card number patterns
//!    found in evidence strings.
//! 4. **Foreign object access** — IDOR findings receive an additional bonus.
//! 5. **Response delta magnitude** — more evidence items → larger impact.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::auth::Severity;

use super::{AttackFinding, FindingSource};

// ── Compiled PII patterns ─────────────────────────────────────────────────────

static EMAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}").unwrap()
});

static PHONE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b").unwrap()
});

/// US Social Security Number pattern.
static SSN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b").unwrap()
});

/// Major card number patterns (Visa, Mastercard, Amex, Discover).
static CARD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    )
    .unwrap()
});

// ── Public types ──────────────────────────────────────────────────────────────

/// An `AttackFinding` after scoring, with a full breakdown for transparency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredFinding {
    #[serde(flatten)]
    pub finding:         AttackFinding,
    /// Final score 0–100 (higher = more urgent).
    pub final_score:     f32,
    pub score_breakdown: Vec<ScoreComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreComponent {
    pub name:  String,
    pub delta: f32,
    pub notes: String,
}

// ── Scorer ────────────────────────────────────────────────────────────────────

pub struct SeverityScorer;

impl SeverityScorer {
    pub fn new() -> Self { Self }

    /// Score every finding and return them sorted by `final_score` descending.
    pub fn rank(&self, findings: Vec<AttackFinding>) -> Vec<ScoredFinding> {
        let mut scored: Vec<ScoredFinding> =
            findings.into_iter().map(|f| self.score_one(f)).collect();
        scored.sort_by(|a, b| {
            b.final_score
                .partial_cmp(&a.final_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        scored
    }

    #[allow(clippy::unused_self)]
    fn score_one(&self, finding: AttackFinding) -> ScoredFinding {
        let mut score      = 0.0_f32;
        let mut components = Vec::<ScoreComponent>::new();

        // 1. Base severity.
        let base = base_score(&finding.severity);
        score += base;
        components.push(ScoreComponent {
            name:  "base_severity".into(),
            delta: base,
            notes: finding.severity.as_str().to_owned(),
        });

        // 2. HTTP method weight.
        let md = method_delta(&finding.method);
        if md != 0.0 {
            score += md;
            components.push(ScoreComponent {
                name:  "method_weight".into(),
                delta: md,
                notes: format!("{} endpoint", finding.method),
            });
        }

        // 3. Sensitive field exposure.
        let sd = sensitive_delta(&finding);
        if sd > 0.0 {
            score += sd;
            components.push(ScoreComponent {
                name:  "sensitive_field_exposure".into(),
                delta: sd,
                notes: "PII patterns detected in response".into(),
            });
        }

        // 4. Foreign object access bonus for IDOR.
        if finding.source == FindingSource::Idor {
            score += 15.0;
            components.push(ScoreComponent {
                name:  "foreign_object_access".into(),
                delta: 15.0,
                notes: "Cross-user object access".into(),
            });
        }

        // 5. Race condition bonus (potential double-spend / state corruption).
        if finding.source == FindingSource::Race {
            score += 10.0;
            components.push(ScoreComponent {
                name:  "race_condition".into(),
                delta: 10.0,
                notes: "Concurrent execution anomaly".into(),
            });
        }

        // 6. Privilege tier: compare role labels if present in details.
        if finding.details.contains("role") || finding.details.contains("admin") {
            score += 8.0;
            components.push(ScoreComponent {
                name:  "privilege_tier".into(),
                delta: 8.0,
                notes: "Privilege tier crossed".into(),
            });
        }

        // 7. Response delta magnitude.
        let ev_count = finding.evidence.len();
        if ev_count >= 5 {
            let d = ((ev_count - 4) as f32).min(10.0) * 1.5;
            score += d;
            components.push(ScoreComponent {
                name:  "response_delta_magnitude".into(),
                delta: d,
                notes: format!("{ev_count} evidence items"),
            });
        }

        score = score.clamp(0.0, 100.0);
        ScoredFinding { finding, final_score: score, score_breakdown: components }
    }
}

impl Default for SeverityScorer {
    fn default() -> Self { Self::new() }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn base_score(sev: &Severity) -> f32 {
    match sev {
        Severity::Critical => 80.0,
        Severity::High     => 65.0,
        Severity::Medium   => 45.0,
        Severity::Low      => 25.0,
        Severity::Info     => 10.0,
    }
}

fn method_delta(method: &str) -> f32 {
    match method.to_uppercase().as_str() {
        "DELETE"         => 15.0,
        "POST" | "PUT" | "PATCH" => 10.0,
        _                => 0.0,
    }
}

fn sensitive_delta(finding: &AttackFinding) -> f32 {
    let text = format!("{} {}", finding.details, finding.evidence.join(" "));
    let mut d = 0.0_f32;
    if EMAIL_RE.is_match(&text) { d += 10.0; }
    if PHONE_RE.is_match(&text) { d += 10.0; }
    if SSN_RE.is_match(&text)   { d += 20.0; }
    if CARD_RE.is_match(&text)  { d += 25.0; }
    d
}
