//! Race condition tester.
//!
//! Fires a single request `concurrency` times simultaneously (default 10) using
//! `tokio::spawn`.  After all tasks complete the responses are analysed for:
//!
//! * **Status divergence** — some responses succeed and others fail.  For write
//!   methods this indicates one request "won" the race.
//! * **Numeric value divergence** — JSON numeric fields differ across responses
//!   (e.g. balance or counter incremented only once when it should have been N
//!   times, or incremented N times when it should have been once).
//! * **Duplicate-processing signals** — keywords like "already processed",
//!   "duplicate", "already redeemed" found in a subset of responses.

use std::sync::Arc;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::auth::Severity;
use crate::db::{find_session_by_name, get_pairs_for_session};
use crate::replay::RequestReconstructor;

use super::{AttackFinding, FindingSource};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaceConfig {
    /// Number of concurrent requests to fire (default 10).
    pub concurrency: usize,
    /// Per-request timeout in milliseconds (default 10 000).
    pub timeout_ms:  u64,
}

impl Default for RaceConfig {
    fn default() -> Self { Self { concurrency: 10, timeout_ms: 10_000 } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaceResponse {
    pub attempt_index: usize,
    pub status_code:   u16,
    pub body_text:     String,
    pub elapsed_ms:    u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaceFinding {
    pub anomaly_type:    String,
    pub details:         String,
    pub severity:        Severity,
    /// Indices into `RaceResult::responses` that were anomalous.
    pub affected_indices: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaceResult {
    pub request_id:  i64,
    pub method:      String,
    pub url:         String,
    pub concurrency: usize,
    pub responses:   Vec<RaceResponse>,
    pub findings:    Vec<RaceFinding>,
}

pub struct RaceTester {
    client: reqwest::Client,
}

impl RaceTester {
    pub fn new(client: reqwest::Client) -> Self { Self { client } }

    /// Race `request_id` from `session_name` with `config.concurrency` tasks.
    pub async fn test(
        &self,
        conn:         &Connection,
        session_name: &str,
        request_id:   i64,
        config:       &RaceConfig,
    ) -> anyhow::Result<RaceResult> {
        let session = find_session_by_name(conn, session_name)?
            .ok_or_else(|| anyhow::anyhow!("Session '{session_name}' not found"))?;

        let pairs = get_pairs_for_session(conn, session.id)?;
        let (req, _) = pairs
            .into_iter()
            .find(|(r, _)| r.id == request_id)
            .ok_or_else(|| anyhow::anyhow!(
                "Request {request_id} not found in session '{session_name}'"
            ))?;

        let replay    = Arc::new(RequestReconstructor::build(&req));
        let client    = self.client.clone();
        let n         = config.concurrency;
        let timeout_ms = config.timeout_ms;

        // Spawn all tasks and collect JoinHandles.
        let mut handles = Vec::with_capacity(n);
        for i in 0..n {
            let client  = client.clone();
            let replay  = (*replay).clone();
            handles.push(tokio::spawn(async move {
                let result = tokio::time::timeout(
                    std::time::Duration::from_millis(timeout_ms),
                    replay.execute(&client),
                )
                .await
                .unwrap_or_else(|_| Err(anyhow::anyhow!("timeout")));
                (i, result)
            }));
        }

        let mut responses = Vec::with_capacity(n);
        for handle in handles {
            match handle.await {
                Ok((idx, Ok(resp))) => responses.push(RaceResponse {
                    attempt_index: idx,
                    status_code:   resp.status_code,
                    body_text:     resp.body_text,
                    elapsed_ms:    resp.elapsed_ms,
                }),
                Ok((idx, Err(e))) => eprintln!("[race] attempt {idx} failed: {e}"),
                Err(e)            => eprintln!("[race] task panicked: {e}"),
            }
        }

        responses.sort_by_key(|r| r.attempt_index);
        let findings = analyse_race(&responses, &req.method);

        Ok(RaceResult {
            request_id:  req.id,
            method:      req.method.clone(),
            url:         req.url.clone(),
            concurrency: n,
            responses,
            findings,
        })
    }

    /// Return request IDs of write-method requests in the session that are
    /// good candidates for race testing.
    pub fn suggest_targets(
        conn:         &Connection,
        session_name: &str,
    ) -> anyhow::Result<Vec<i64>> {
        let session = find_session_by_name(conn, session_name)?
            .ok_or_else(|| anyhow::anyhow!("Session '{session_name}' not found"))?;
        let pairs = get_pairs_for_session(conn, session.id)?;
        Ok(pairs
            .into_iter()
            .filter(|(req, _)| {
                !req.is_websocket
                    && matches!(
                        req.method.to_uppercase().as_str(),
                        "POST" | "PUT" | "PATCH" | "DELETE"
                    )
            })
            .map(|(req, _)| req.id)
            .collect())
    }
}

// ── Conversion ────────────────────────────────────────────────────────────────

pub fn result_to_findings(result: &RaceResult) -> Vec<AttackFinding> {
    result.findings.iter().map(|f| {
        AttackFinding {
            source:      FindingSource::Race,
            url_pattern: result.url.clone(),
            method:      result.method.clone(),
            request_id:  Some(result.request_id),
            severity:    f.severity.clone(),
            score:       sev_to_score(&f.severity),
            title:       format!("Race condition: {} {}", result.method, result.url),
            details:     f.details.clone(),
            evidence:    result.responses.iter()
                .map(|r| format!(
                    "[{}] HTTP {} — {}ms",
                    r.attempt_index, r.status_code, r.elapsed_ms
                ))
                .collect(),
        }
    }).collect()
}

// ── Response analysis ─────────────────────────────────────────────────────────

fn analyse_race(responses: &[RaceResponse], method: &str) -> Vec<RaceFinding> {
    let mut findings = Vec::new();
    if responses.is_empty() { return findings; }

    // 1. Status code divergence.
    let codes: Vec<u16> = responses.iter().map(|r| r.status_code).collect();
    let base_code = codes[0];
    let divergent: Vec<usize> = codes
        .iter()
        .enumerate()
        .filter(|(_, &c)| c != base_code)
        .map(|(i, _)| i)
        .collect();

    if !divergent.is_empty() {
        let ok  = codes.iter().filter(|&&c| (200..300).contains(&i64::from(c))).count();
        let err = codes.len() - ok;
        if ok > 0 && err > 0 {
            let is_write = matches!(method.to_uppercase().as_str(), "POST" | "PUT" | "PATCH" | "DELETE");
            findings.push(RaceFinding {
                anomaly_type: "status_divergence".into(),
                details: format!(
                    "{ok}/{} requests succeeded and {err}/{} returned errors — \
                     possible race condition on {} {}",
                    responses.len(), responses.len(), method, responses[0].body_text.get(..40).unwrap_or("")
                ),
                severity:        if is_write { Severity::High } else { Severity::Medium },
                affected_indices: divergent,
            });
        }
    }

    // 2. Numeric value divergence in JSON bodies.
    let num_anomalies = numeric_divergence(responses);
    if !num_anomalies.is_empty() {
        findings.push(RaceFinding {
            anomaly_type:    "numeric_divergence".into(),
            details:         format!(
                "Differing numeric values across concurrent responses: {}",
                num_anomalies.join("; ")
            ),
            severity:        Severity::High,
            affected_indices: (0..responses.len()).collect(),
        });
    }

    // 3. Duplicate-processing keywords.
    let dup_signals = duplicate_signals(responses);
    if !dup_signals.is_empty() {
        findings.push(RaceFinding {
            anomaly_type:    "duplicate_processing".into(),
            details:         format!(
                "Duplicate-processing indicators in responses: {}",
                dup_signals.join(", ")
            ),
            severity:        Severity::Critical,
            affected_indices: (0..responses.len()).collect(),
        });
    }

    findings
}

fn numeric_divergence(responses: &[RaceResponse]) -> Vec<String> {
    use serde_json::Value;

    let parsed: Vec<Option<Value>> = responses
        .iter()
        .map(|r| serde_json::from_str(&r.body_text).ok())
        .collect();

    let valid: Vec<&Value> = parsed.iter().filter_map(|o| o.as_ref()).collect();
    if valid.len() < 2 { return Vec::new(); }

    let mut out = Vec::new();
    collect_num_diffs(valid[0], &valid[1..], "", &mut out);
    out
}

fn collect_num_diffs(
    base: &serde_json::Value,
    rest: &[&serde_json::Value],
    path: &str,
    out:  &mut Vec<String>,
) {
    use serde_json::Value;
    match base {
        Value::Number(n) => {
            // `rest` has already been recursed to the parallel child values,
            // so we compare directly — NOT via `.get(path)` on a root object.
            if let Some(bv) = n.as_f64() {
                for other in rest {
                    if let Some(ov) = other.as_f64() {
                        if (bv - ov).abs() > f64::EPSILON {
                            out.push(format!("'{path}': {bv} vs {ov}"));
                        }
                    }
                }
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                let child = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                // Descend into the same key in each sibling response.
                let rest_children: Vec<&Value> = rest
                    .iter()
                    .filter_map(|o| o.get(k.as_str()))
                    .collect();
                collect_num_diffs(v, &rest_children, &child, out);
            }
        }
        _ => {}
    }
}

fn duplicate_signals(responses: &[RaceResponse]) -> Vec<String> {
    const KEYWORDS: &[&str] = &[
        "already processed",
        "already exists",
        "duplicate",
        "already redeemed",
        "already used",
        "double charge",
        "idempotency",
        "concurrent modification",
    ];
    let mut found = Vec::new();
    for r in responses {
        let lower = r.body_text.to_lowercase();
        for kw in KEYWORDS {
            if lower.contains(kw) && !found.contains(&kw.to_string()) {
                found.push(kw.to_string());
            }
        }
    }
    found
}

fn sev_to_score(sev: &Severity) -> f32 {
    match sev {
        Severity::Critical => 95.0,
        Severity::High     => 75.0,
        Severity::Medium   => 55.0,
        Severity::Low      => 35.0,
        Severity::Info     => 10.0,
    }
}
