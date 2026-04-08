use rusqlite::{params, Connection, OptionalExtension};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::Duration,
};

use crate::{
    db::{
        find_main_id_for_staging, find_or_create_session, get_last_synced_rowid,
        insert_correlation, insert_entity, insert_request, insert_response,
        open_main_db, open_staging_db, set_last_synced_rowid,
    },
    entities::EntityExtractor,
    graphql::GraphqlDetector,
    models::PendingRequest,
    normalize::Normalizer,
};

const POLL_INTERVAL_MS: u64 = 500;
const BATCH_LIMIT: i64 = 500;

// ── Public API ────────────────────────────────────────────────────────────────

pub struct Syncer {
    staging_path: PathBuf,
    main_path:    PathBuf,
    normalizer:   Arc<Normalizer>,
    extractor:    EntityExtractor,
    detector:     GraphqlDetector,
}

impl Syncer {
    pub fn new<P: AsRef<Path>>(
        staging_path: P,
        main_path:    P,
        normalizer:   Arc<Normalizer>,
    ) -> Self {
        Self {
            staging_path: staging_path.as_ref().to_owned(),
            main_path:    main_path.as_ref().to_owned(),
            normalizer,
            extractor:    EntityExtractor::new(),
            detector:     GraphqlDetector::new(),
        }
    }

    /// Run one merge cycle.  Returns the number of requests processed.
    pub fn sync_once(&self) -> anyhow::Result<usize> {
        if !self.staging_path.exists() {
            return Ok(0);
        }

        let staging = open_staging_db(&self.staging_path)?;
        let main    = open_main_db(&self.main_path)?;

        let last_rowid = get_last_synced_rowid(&main)?;
        let pending    = fetch_pending_requests(&staging, last_rowid)?;

        if pending.is_empty() {
            return Ok(0);
        }

        let mut new_last_rowid = last_rowid;
        let mut count = 0usize;

        for pr in &pending {
            if !self.normalizer.should_pass(&pr.url, &pr.method) {
                new_last_rowid = pr.staging_id;
                continue;
            }

            // ── GraphQL detection ─────────────────────────────────────────
            let gql_info = self.detector.detect(
                &pr.url,
                &pr.headers_json,
                pr.body_blob.as_deref(),
            );

            let operation_name: Option<&str> = pr
                .operation_name
                .as_deref()
                .or_else(|| gql_info.as_ref().and_then(|g| g.operation_name.as_deref()));

            let effective_url: String =
                if let Some(op) = operation_name {
                    if Normalizer::is_graphql_candidate(&pr.url) {
                        format!("graphql:{op}")
                    } else {
                        pr.url.clone()
                    }
                } else {
                    pr.url.clone()
                };

            // ── Resolve WS parent request ID ──────────────────────────────
            let parent_request_id: Option<i64> = if pr.is_websocket {
                pr.parent_staging_id
                    .and_then(|pid| find_main_id_for_staging(&main, pid).ok().flatten())
            } else {
                None
            };

            let session_id = find_or_create_session(&main, &pr.session_name)?;

            let req_id = insert_request(
                &main,
                session_id,
                &pr.method,
                &effective_url,
                &pr.headers_json,
                pr.body_blob.as_deref(),
                &pr.timestamp,
                operation_name,
                pr.is_websocket,
                parent_request_id,
                Some(pr.staging_id),
            )?;

            // ── Entity extraction ─────────────────────────────────────────
            let mut entities = self.extractor.extract(
                &pr.url,
                &pr.headers_json,
                pr.body_blob.as_deref(),
            );
            if let Some(ref gql) = gql_info {
                EntityExtractor::extract_gql_variables(&gql.variables, &mut entities);
            }
            for e in &entities {
                insert_entity(
                    &main,
                    req_id,
                    e.entity_type.as_str(),
                    &e.field_name,
                    &e.value,
                    e.location.as_str(),
                )?;
            }

            // ── Correlation ───────────────────────────────────────────────
            if let Some(ref cid) = pr.correlation_id {
                let src = pr.correlation_source.as_deref().unwrap_or("hash");
                insert_correlation(&main, req_id, cid, src)?;
            }

            // ── Response (if already in staging) ─────────────────────────
            if let Some(resp) = fetch_pending_response(&staging, pr.staging_id)? {
                insert_response(
                    &main,
                    req_id,
                    resp.0,
                    &resp.1,
                    resp.2.as_deref(),
                )?;
            }

            new_last_rowid = pr.staging_id;
            count += 1;
        }

        if new_last_rowid > last_rowid {
            set_last_synced_rowid(&main, new_last_rowid)?;
        }

        Ok(count)
    }

    /// Spawn a background thread that calls `sync_once` every 500 ms.
    pub fn run_background(self) -> thread::JoinHandle<()> {
        thread::spawn(move || loop {
            match self.sync_once() {
                Ok(n) if n > 0 => eprintln!("[lw-sync] merged {n} request(s)"),
                Err(e)         => eprintln!("[lw-sync] error: {e}"),
                _              => {}
            }
            thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
        })
    }

    pub fn run_background_arc(self: Arc<Self>) -> thread::JoinHandle<()> {
        thread::spawn(move || loop {
            match self.sync_once() {
                Ok(n) if n > 0 => eprintln!("[lw-sync] merged {n} request(s)"),
                Err(e)         => eprintln!("[lw-sync] error: {e}"),
                _              => {}
            }
            thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
        })
    }
}

unsafe impl Send for Syncer {}
unsafe impl Sync for Syncer {}

// ── Staging query helpers ─────────────────────────────────────────────────────

fn fetch_pending_requests(
    conn:       &Connection,
    after_rowid: i64,
) -> anyhow::Result<Vec<PendingRequest>> {
    let mut stmt = conn.prepare(
        "SELECT id, session_name, method, url, headers_json, body_blob,
                timestamp, correlation_id, correlation_source,
                is_websocket, ws_opcode, operation_name, parent_staging_id
         FROM pending_requests
         WHERE id > ?1
         ORDER BY id ASC
         LIMIT ?2",
    )?;

    let rows = stmt
        .query_map(params![after_rowid, BATCH_LIMIT], |row| {
            Ok(PendingRequest {
                staging_id:         row.get(0)?,
                session_name:       row.get(1)?,
                method:             row.get(2)?,
                url:                row.get(3)?,
                headers_json:       row.get(4)?,
                body_blob:          row.get(5)?,
                timestamp:          row.get(6)?,
                correlation_id:     row.get(7)?,
                correlation_source: row.get(8)?,
                is_websocket:       row.get::<_, i64>(9)? != 0,
                ws_opcode:          row.get(10)?,
                operation_name:     row.get(11)?,
                parent_staging_id:  row.get(12)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();

    Ok(rows)
}

type PendingResponseRow = (i64, String, Option<Vec<u8>>);

/// Returns (status_code, headers_json, body_blob) or None.
fn fetch_pending_response(
    conn:           &Connection,
    staging_req_id: i64,
) -> anyhow::Result<Option<PendingResponseRow>> {
    conn.query_row(
        "SELECT status_code, headers_json, body_blob
         FROM pending_responses WHERE request_staging_id = ?1 LIMIT 1",
        params![staging_req_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .optional()
    .map_err(Into::into)
}
