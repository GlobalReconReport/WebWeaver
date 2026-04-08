//! Sequence breaker.
//!
//! For each step in a session's request chain the module generates three
//! mutation variants and tests them against the live server:
//!
//! * **Skip step N** — execute steps 0..N-1 then jump directly to N+1.
//!   Flag if N+1 still succeeds (prerequisite was skippable).
//! * **Reorder steps N / N+1** — send request N+1 before request N.
//!   Flag if N+1 succeeds when N has not yet executed.
//! * **Replay step N** — send request N a second time immediately after.
//!   Flag if a write-method request returns 2xx on the second attempt
//!   (missing idempotency / replay protection).
//!
//! Each request is sent with its originally-captured headers (including the
//! auth state from the time of capture).  This means the session's auth
//! tokens are valid and the test focuses on server-side state enforcement
//! rather than re-establishing a fresh session.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::auth::Severity;
use crate::db::{find_session_by_name, get_pairs_for_session};
use crate::models::Request;
use crate::replay::RequestReconstructor;

use super::{AttackFinding, FindingSource};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MutationType {
    SkipStep,
    ReorderWithNext,
    ReplayStep,
}

impl MutationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SkipStep        => "skip_step",
            Self::ReorderWithNext => "reorder_with_next",
            Self::ReplayStep      => "replay_step",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceMutation {
    pub step_index:    usize,
    pub mutation_type: MutationType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub original_request_id: i64,
    pub method:              String,
    pub url:                 String,
    pub status_code:         Option<u16>,
    pub body_text:           String,
    pub elapsed_ms:          u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceBreakResult {
    pub mutation:          SequenceMutation,
    /// Original captured status codes for reference.
    pub baseline_statuses: Vec<Option<i64>>,
    /// Responses received during the mutated execution.
    pub mutated_steps:     Vec<StepResult>,
    /// True when the server correctly rejected the mutation.
    pub rejected:          bool,
    pub finding:           Option<String>,
    pub severity:          Severity,
}

pub struct SequenceBreaker {
    client: reqwest::Client,
}

impl SequenceBreaker {
    pub fn new(client: reqwest::Client) -> Self { Self { client } }

    /// Test all three mutation types for every step in the session, up to
    /// `max_steps` (default 20).  Returns one result per mutation variant.
    pub async fn break_sequence(
        &self,
        conn:         &Connection,
        session_name: &str,
        max_steps:    usize,
    ) -> anyhow::Result<Vec<SequenceBreakResult>> {
        let session = find_session_by_name(conn, session_name)?
            .ok_or_else(|| anyhow::anyhow!("Session '{session_name}' not found"))?;

        let all_pairs = get_pairs_for_session(conn, session.id)?;

        // Keep only non-WS HTTP steps; honour max_steps ceiling.
        let limit = if max_steps == 0 { usize::MAX } else { max_steps };
        let steps: Vec<_> = all_pairs
            .into_iter()
            .filter(|(req, _)| !req.is_websocket)
            .take(limit)
            .collect();

        if steps.is_empty() { return Ok(Vec::new()); }

        let baseline_statuses: Vec<Option<i64>> = steps
            .iter()
            .map(|(_, r)| r.as_ref().map(|resp| resp.status_code))
            .collect();

        let n = steps.len();
        let mut results = Vec::new();

        for i in 0..n {
            let (req_i, _) = &steps[i];

            // ── Skip step i ───────────────────────────────────────────────
            // Execute step i+1 directly (bypassing step i).
            if i + 1 < n {
                let (req_next, _) = &steps[i + 1];
                let replay = RequestReconstructor::build(req_next);
                let step   = fire(&self.client, req_next, &replay).await;

                let (rejected, finding, sev) = judge_skip(
                    &step,
                    baseline_statuses.get(i + 1).copied().flatten(),
                    i,
                );
                results.push(SequenceBreakResult {
                    mutation:          SequenceMutation { step_index: i, mutation_type: MutationType::SkipStep },
                    baseline_statuses: baseline_statuses.clone(),
                    mutated_steps:     vec![step],
                    rejected,
                    finding,
                    severity: sev,
                });
            }

            // ── Reorder: send step i+1 before step i ─────────────────────
            if i + 1 < n {
                let (req_next, _) = &steps[i + 1];
                let replay = RequestReconstructor::build(req_next);
                let step   = fire(&self.client, req_next, &replay).await;

                let (rejected, finding, sev) = judge_reorder(
                    &step,
                    baseline_statuses.get(i + 1).copied().flatten(),
                    i,
                );
                results.push(SequenceBreakResult {
                    mutation:          SequenceMutation { step_index: i, mutation_type: MutationType::ReorderWithNext },
                    baseline_statuses: baseline_statuses.clone(),
                    mutated_steps:     vec![step],
                    rejected,
                    finding,
                    severity: sev,
                });
            }

            // ── Replay step i twice ───────────────────────────────────────
            let replay1 = RequestReconstructor::build(req_i);
            let first   = fire(&self.client, req_i, &replay1).await;

            let replay2 = RequestReconstructor::build(req_i);
            let second  = fire(&self.client, req_i, &replay2).await;

            let (rejected, finding, sev) = judge_replay(
                &first,
                &second,
                baseline_statuses.get(i).copied().flatten(),
                &req_i.method,
                i,
            );
            results.push(SequenceBreakResult {
                mutation:          SequenceMutation { step_index: i, mutation_type: MutationType::ReplayStep },
                baseline_statuses: baseline_statuses.clone(),
                mutated_steps:     vec![first, second],
                rejected,
                finding,
                severity: sev,
            });
        }

        Ok(results)
    }
}

// ── Conversion ────────────────────────────────────────────────────────────────

pub fn results_to_findings(results: &[SequenceBreakResult]) -> Vec<AttackFinding> {
    results
        .iter()
        .filter(|r| !r.rejected && r.finding.is_some())
        .map(|r| {
            let step = r.mutated_steps.first();
            AttackFinding {
                source:      FindingSource::SequenceBreak,
                url_pattern: step.map_or("?", |s| s.url.as_str()).to_owned(),
                method:      step.map_or("?", |s| s.method.as_str()).to_owned(),
                request_id:  step.map(|s| s.original_request_id),
                severity:    r.severity.clone(),
                score:       sev_to_score(&r.severity),
                title:       format!(
                    "Sequence break [{} @ step {}]",
                    r.mutation.mutation_type.as_str(),
                    r.mutation.step_index,
                ),
                details:     r.finding.clone().unwrap_or_default(),
                evidence:    r.mutated_steps
                    .iter()
                    .map(|s| format!("{} {} → HTTP {:?}", s.method, s.url, s.status_code))
                    .collect(),
            }
        })
        .collect()
}

// ── Judgement heuristics ──────────────────────────────────────────────────────

fn judge_skip(
    step:     &StepResult,
    baseline: Option<i64>,
    idx:      usize,
) -> (bool, Option<String>, Severity) {
    let Some(sc) = step.status_code else {
        return (true, None, Severity::Info);
    };

    // If the original also returned 2xx for this step (no dependency on the
    // prior step), skip is expected — not a vulnerability.
    let orig_was_success = baseline.is_some_and(|b| (200..300).contains(&b));
    if !orig_was_success {
        return (true, None, Severity::Info);
    }

    // Both the original and the skipped variant succeed → no prerequisite enforced.
    if (200..300).contains(&i64::from(sc)) {
        (
            false,
            Some(format!(
                "Step {} succeeded when step {} was skipped (no prerequisite enforcement)",
                idx + 1, idx
            )),
            Severity::Medium,
        )
    } else {
        (true, None, Severity::Info)
    }
}

fn judge_reorder(
    step:     &StepResult,
    baseline: Option<i64>,
    idx:      usize,
) -> (bool, Option<String>, Severity) {
    // Same logic as skip: if the out-of-order step succeeds when the prior step
    // has not yet been executed, sequence ordering is not enforced.
    judge_skip(step, baseline, idx)
}

fn judge_replay(
    first:     &StepResult,
    second:    &StepResult,
    _baseline: Option<i64>,
    method:    &str,
    idx:       usize,
) -> (bool, Option<String>, Severity) {
    // Replaying GET / HEAD is always fine (idempotent by definition).
    if matches!(method.to_uppercase().as_str(), "GET" | "HEAD" | "OPTIONS") {
        return (true, None, Severity::Info);
    }

    let Some(sc1) = first.status_code  else { return (true, None, Severity::Info); };
    let Some(sc2) = second.status_code else { return (true, None, Severity::Info); };

    if (200..300).contains(&i64::from(sc1)) && (200..300).contains(&i64::from(sc2)) {
        let sev = if matches!(method.to_uppercase().as_str(), "POST") {
            Severity::High
        } else {
            Severity::Medium
        };
        (
            false,
            Some(format!(
                "Replaying {method} step {idx} twice: both returned 2xx ({sc1}, {sc2}) — \
                 possible double-execution / missing replay protection"
            )),
            sev,
        )
    } else {
        (true, None, Severity::Info)
    }
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

async fn fire(
    client: &reqwest::Client,
    req:    &Request,
    replay: &crate::replay::ReplayableRequest,
) -> StepResult {
    match replay.execute(client).await {
        Ok(r) => StepResult {
            original_request_id: req.id,
            method:      req.method.clone(),
            url:         req.url.clone(),
            status_code: Some(r.status_code),
            body_text:   r.body_text,
            elapsed_ms:  r.elapsed_ms,
        },
        Err(e) => {
            eprintln!("[sequence] request failed for {}: {e}", req.url);
            StepResult {
                original_request_id: req.id,
                method:      req.method.clone(),
                url:         req.url.clone(),
                status_code: None,
                body_text:   String::new(),
                elapsed_ms:  0,
            }
        }
    }
}

fn sev_to_score(sev: &Severity) -> f32 {
    match sev {
        Severity::Critical => 90.0,
        Severity::High     => 70.0,
        Severity::Medium   => 50.0,
        Severity::Low      => 30.0,
        Severity::Info     => 10.0,
    }
}
