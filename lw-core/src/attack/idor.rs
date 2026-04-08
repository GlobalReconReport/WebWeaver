//! IDOR scanner.
//!
//! For every entity of type UUID or NumericId in session A's requests, find
//! session B's matching entity at the same URL pattern + field name.  Send
//! session A's request with B's entity ID (keeping A's auth intact) and
//! analyse the response to determine whether B's data was exposed.

use std::collections::HashMap;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::auth::Severity;
use crate::db::{find_session_by_name, get_entities_for_request, get_pairs_for_session};
use crate::graph::normalize_url;
use crate::models::{EntityLocation, EntityType, Request, Response};
use crate::replay::{HttpResponse, RequestReconstructor};

use super::{AttackFinding, FindingSource};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdorAttempt {
    pub url_pattern:     String,
    pub method:          String,
    pub field_name:      String,
    pub value_a:         String,
    pub value_b:         String,
    pub request_id_a:    i64,
    pub status_original: Option<i64>,
    pub status_test:     Option<u16>,
    pub is_idor:         bool,
    pub confidence:      f32,
    pub details:         String,
}

/// Configuration for an IDOR scan.
pub struct IdorScanConfig {
    /// When `true`, build and log every test request but do not send it.
    pub dry_run:   bool,
    /// Stop after this many HTTP tests (0 = unlimited).
    pub max_tests: usize,
}

impl Default for IdorScanConfig {
    fn default() -> Self {
        Self { dry_run: false, max_tests: 100 }
    }
}

pub struct IdorScanner {
    client: reqwest::Client,
}

impl IdorScanner {
    pub fn new(client: reqwest::Client) -> Self { Self { client } }

    pub async fn scan(
        &self,
        conn:     &Connection,
        session_a: &str,
        session_b: &str,
        config:   &IdorScanConfig,
    ) -> anyhow::Result<Vec<IdorAttempt>> {
        let sa = find_session_by_name(conn, session_a)?
            .ok_or_else(|| anyhow::anyhow!("Session '{session_a}' not found"))?;
        let sb = find_session_by_name(conn, session_b)?
            .ok_or_else(|| anyhow::anyhow!("Session '{session_b}' not found"))?;

        let pairs_a = get_pairs_for_session(conn, sa.id)?;
        let pairs_b = get_pairs_for_session(conn, sb.id)?;

        // Build an index of session B: (url_pattern, METHOD, field_name) → (value, response)
        let b_index = build_entity_index(conn, &pairs_b)?;

        let mut attempts: Vec<IdorAttempt> = Vec::new();
        let mut test_count = 0usize;

        'outer: for (req_a, resp_a) in &pairs_a {
            if req_a.is_websocket { continue; }

            let entities = get_entities_for_request(conn, req_a.id)?;

            for entity in &entities {
                // Only URL-path or body object identifiers — not headers/cookies.
                if matches!(entity.location, EntityLocation::Header | EntityLocation::Cookie) {
                    continue;
                }
                if !matches!(entity.entity_type, EntityType::Uuid | EntityType::NumericId) {
                    continue;
                }

                let pat = normalize_url(&req_a.url);
                let key = (pat.clone(), req_a.method.to_uppercase(), entity.field_name.clone());

                let Some((val_b, _req_b_id, resp_b)) = b_index.get(&key) else {
                    continue;
                };
                if val_b == &entity.value { continue; } // same object in both sessions

                let status_original = resp_a.as_ref().map(|r| r.status_code);

                if config.dry_run {
                    attempts.push(IdorAttempt {
                        url_pattern: pat,
                        method:      req_a.method.clone(),
                        field_name:  entity.field_name.clone(),
                        value_a:     entity.value.clone(),
                        value_b:     val_b.clone(),
                        request_id_a: req_a.id,
                        status_original,
                        status_test:  None,
                        is_idor:      false,
                        confidence:   0.0,
                        details:      "dry-run — not executed".to_owned(),
                    });
                    continue;
                }

                // Build the test request: A's auth + B's entity ID.
                let replay = RequestReconstructor::build_with_value_substitution(
                    req_a,
                    &entity.value,
                    val_b,
                );

                match replay.execute(&self.client).await {
                    Ok(http_resp) => {
                        let (is_idor, confidence, details) = analyse_idor_response(
                            &http_resp,
                            resp_b.as_ref(),
                            val_b,
                            status_original,
                        );
                        attempts.push(IdorAttempt {
                            url_pattern:     pat,
                            method:          req_a.method.clone(),
                            field_name:      entity.field_name.clone(),
                            value_a:         entity.value.clone(),
                            value_b:         val_b.clone(),
                            request_id_a:    req_a.id,
                            status_original,
                            status_test:     Some(http_resp.status_code),
                            is_idor,
                            confidence,
                            details,
                        });
                    }
                    Err(e) => {
                        eprintln!("[idor] request failed for {}: {e}", req_a.url);
                    }
                }

                test_count += 1;
                if config.max_tests > 0 && test_count >= config.max_tests {
                    break 'outer;
                }
            }
        }

        Ok(attempts)
    }
}

// ── Conversion ────────────────────────────────────────────────────────────────

pub fn attempts_to_findings(attempts: &[IdorAttempt]) -> Vec<AttackFinding> {
    attempts
        .iter()
        .filter(|a| a.is_idor)
        .map(|a| {
            let sev = if a.confidence >= 0.8 { Severity::High } else { Severity::Medium };
            let score = a.confidence * 75.0;
            AttackFinding {
                source:      FindingSource::Idor,
                url_pattern: a.url_pattern.clone(),
                method:      a.method.clone(),
                request_id:  Some(a.request_id_a),
                severity:    sev,
                score,
                title:       format!("IDOR: {} {}", a.method, a.url_pattern),
                details:     a.details.clone(),
                evidence:    vec![
                    format!("Substituted '{}' → '{}'", a.value_a, a.value_b),
                    format!("Test response HTTP {}", a.status_test.map_or("?".into(), |s| s.to_string())),
                ],
            }
        })
        .collect()
}

// ── IDOR response analysis ────────────────────────────────────────────────────

fn analyse_idor_response(
    test_resp:   &HttpResponse,
    baseline_b:  Option<&Response>,
    val_b:       &str,
    status_orig: Option<i64>,
) -> (bool, f32, String) {
    let sc = test_resp.status_code;

    if !(200..300).contains(&i64::from(sc)) {
        return (false, 0.0, format!("HTTP {sc} — access denied"));
    }

    let mut confidence = 0.4_f32;
    let mut reasons    = vec![format!("HTTP {sc} (success)")];

    // If the original session A request also failed, the 2xx is even more suspicious.
    if let Some(orig) = status_orig {
        if !(200..300).contains(&(orig)) {
            confidence += 0.15;
            reasons.push("Session A's own request was non-2xx".into());
        }
    }

    // Does the response contain session B's entity value?
    if test_resp.body_text.contains(val_b) {
        confidence += 0.25;
        reasons.push(format!("Response body contains B's value '{val_b}'"));
    }

    // Does the response structurally resemble session B's baseline?
    if let Some(bl) = baseline_b {
        if let Some(ref bl_body) = bl.body_blob {
            let sim = jaccard_similarity(&test_resp.body_text, &String::from_utf8_lossy(bl_body));
            if sim > 0.55 {
                confidence += 0.20;
                reasons.push(format!("Response {:.0}% structurally similar to B's baseline", sim * 100.0));
            }
        }
    }

    confidence = confidence.min(1.0);
    (confidence >= 0.5, confidence, reasons.join("; "))
}

/// Jaccard similarity over whitespace tokens — lightweight body similarity check.
fn jaccard_similarity(a: &str, b: &str) -> f32 {
    let sa: std::collections::HashSet<&str> = a.split_whitespace().collect();
    let sb: std::collections::HashSet<&str> = b.split_whitespace().collect();
    if sa.is_empty() && sb.is_empty() { return 1.0; }
    if sa.is_empty() || sb.is_empty() { return 0.0; }
    let inter = sa.intersection(&sb).count() as f32;
    let union = sa.union(&sb).count() as f32;
    inter / union
}

// ── Entity index ──────────────────────────────────────────────────────────────

type EntityIndex = HashMap<(String, String, String), (String, i64, Option<Response>)>;

fn build_entity_index(
    conn:  &Connection,
    pairs: &[(Request, Option<Response>)],
) -> anyhow::Result<EntityIndex> {
    let mut map = EntityIndex::new();
    for (req, resp) in pairs {
        if req.is_websocket { continue; }
        let pat      = normalize_url(&req.url);
        let entities = get_entities_for_request(conn, req.id)?;
        for e in entities {
            if matches!(e.location, EntityLocation::Header | EntityLocation::Cookie) { continue; }
            if !matches!(e.entity_type, EntityType::Uuid | EntityType::NumericId) { continue; }
            let key = (pat.clone(), req.method.to_uppercase(), e.field_name.clone());
            map.entry(key).or_insert_with(|| (e.value.clone(), req.id, resp.clone()));
        }
    }
    Ok(map)
}
