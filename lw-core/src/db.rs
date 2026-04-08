use anyhow::Context;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

use crate::models::*;

// ── Database initialisation ───────────────────────────────────────────────────

pub fn open_main_db<P: AsRef<Path>>(path: P) -> anyhow::Result<Connection> {
    let conn = Connection::open(path).context("Failed to open main database")?;
    enable_wal(&conn)?;
    run_schema_migrations(&conn)?;
    Ok(conn)
}

pub fn open_staging_db<P: AsRef<Path>>(path: P) -> anyhow::Result<Connection> {
    let conn = Connection::open(path).context("Failed to open staging database")?;
    enable_wal(&conn)?;
    init_staging_schema(&conn)?;
    Ok(conn)
}

fn enable_wal(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;",
    )?;
    Ok(())
}

/// Run all pending schema migrations idempotently.
fn run_schema_migrations(conn: &Connection) -> anyhow::Result<()> {
    // Base tables (safe to call on any DB — uses IF NOT EXISTS).
    create_base_tables(conn)?;
    // Phase 2: add new columns to existing tables.
    apply_v2_columns(conn)?;
    // Phase 2: new tables for flow-engine.
    create_v2_tables(conn)?;
    Ok(())
}

fn create_base_tables(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL UNIQUE,
            user_role   TEXT    NOT NULL DEFAULT 'default',
            created_at  TEXT    NOT NULL
        );

        -- is_websocket / parent_request_id / staging_src_id may not be present
        -- on Phase-1 databases; apply_v2_columns handles adding them.
        CREATE TABLE IF NOT EXISTS requests (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      INTEGER NOT NULL,
            method          TEXT    NOT NULL,
            url             TEXT    NOT NULL,
            headers_json    TEXT    NOT NULL DEFAULT '{}',
            body_blob       BLOB,
            timestamp       TEXT    NOT NULL,
            operation_name  TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        CREATE TABLE IF NOT EXISTS responses (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id      INTEGER NOT NULL UNIQUE,
            status_code     INTEGER NOT NULL,
            headers_json    TEXT    NOT NULL DEFAULT '{}',
            body_blob       BLOB,
            FOREIGN KEY (request_id) REFERENCES requests(id)
        );

        CREATE TABLE IF NOT EXISTS correlations (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id      INTEGER NOT NULL,
            correlation_id  TEXT    NOT NULL,
            source          TEXT    NOT NULL CHECK (source IN ('header','timestamp','hash')),
            FOREIGN KEY (request_id) REFERENCES requests(id)
        );

        CREATE TABLE IF NOT EXISTS entities (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id      INTEGER NOT NULL,
            entity_type     TEXT    NOT NULL,
            field_name      TEXT    NOT NULL,
            value           TEXT    NOT NULL,
            location        TEXT    NOT NULL CHECK (location IN ('url','header','body','cookie')),
            FOREIGN KEY (request_id) REFERENCES requests(id)
        );

        CREATE TABLE IF NOT EXISTS sync_meta (
            key     TEXT PRIMARY KEY,
            value   TEXT NOT NULL
        );
        INSERT OR IGNORE INTO sync_meta (key, value)
            VALUES ('last_synced_request_rowid', '0');

        CREATE INDEX IF NOT EXISTS idx_requests_session  ON requests(session_id);
        CREATE INDEX IF NOT EXISTS idx_requests_url      ON requests(url);
        CREATE INDEX IF NOT EXISTS idx_requests_method   ON requests(method);
        CREATE INDEX IF NOT EXISTS idx_entities_request  ON entities(request_id);
        CREATE INDEX IF NOT EXISTS idx_entities_type     ON entities(entity_type);
        CREATE INDEX IF NOT EXISTS idx_correlations_cid  ON correlations(correlation_id);
        CREATE INDEX IF NOT EXISTS idx_correlations_req  ON correlations(request_id);
        "#,
    )?;
    Ok(())
}

/// Add Phase-2 columns to the requests table if they do not already exist.
fn apply_v2_columns(conn: &Connection) -> anyhow::Result<()> {
    let additions: &[(&str, &str)] = &[
        ("is_websocket",      "INTEGER NOT NULL DEFAULT 0"),
        ("parent_request_id", "INTEGER"),
        ("staging_src_id",    "INTEGER"),
    ];
    for (col, def) in additions {
        if !column_exists(conn, "requests", col)? {
            conn.execute_batch(&format!(
                "ALTER TABLE requests ADD COLUMN {col} {def};"
            ))?;
        }
    }
    Ok(())
}

fn create_v2_tables(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        r#"
        -- Value-flow edges between a response (or WS message) and a subsequent request.
        CREATE TABLE IF NOT EXISTS dependency_edges (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id          INTEGER NOT NULL,
            source_type         TEXT    NOT NULL
                CHECK (source_type IN ('response','ws_message')),
            source_id           INTEGER NOT NULL,
            target_request_id   INTEGER NOT NULL,
            field_name          TEXT    NOT NULL,
            value               TEXT    NOT NULL,
            edge_type           TEXT    NOT NULL,
            FOREIGN KEY (session_id)          REFERENCES sessions(id),
            FOREIGN KEY (target_request_id)   REFERENCES requests(id)
        );

        -- Auth-boundary analysis findings.
        CREATE TABLE IF NOT EXISTS auth_findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_a       TEXT    NOT NULL,
            session_b       TEXT,
            url_pattern     TEXT    NOT NULL,
            method          TEXT    NOT NULL,
            finding_type    TEXT    NOT NULL,
            severity        TEXT    NOT NULL,
            details         TEXT    NOT NULL,
            evidence_json   TEXT    NOT NULL DEFAULT '[]',
            created_at      TEXT    NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_dep_session  ON dependency_edges(session_id);
        CREATE INDEX IF NOT EXISTS idx_dep_source   ON dependency_edges(source_id, source_type);
        CREATE INDEX IF NOT EXISTS idx_dep_target   ON dependency_edges(target_request_id);
        CREATE INDEX IF NOT EXISTS idx_req_ws_parent ON requests(parent_request_id);
        CREATE INDEX IF NOT EXISTS idx_req_staging   ON requests(staging_src_id);
        "#,
    )?;
    Ok(())
}

fn init_staging_schema(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS pending_requests (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            session_name        TEXT    NOT NULL DEFAULT 'default',
            method              TEXT    NOT NULL,
            url                 TEXT    NOT NULL,
            headers_json        TEXT    NOT NULL DEFAULT '{}',
            body_blob           BLOB,
            timestamp           TEXT    NOT NULL,
            correlation_id      TEXT,
            correlation_source  TEXT,
            is_websocket        INTEGER NOT NULL DEFAULT 0,
            ws_opcode           INTEGER,
            operation_name      TEXT,
            parent_staging_id   INTEGER
        );

        CREATE TABLE IF NOT EXISTS pending_responses (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            request_staging_id  INTEGER NOT NULL,
            status_code         INTEGER NOT NULL,
            headers_json        TEXT    NOT NULL DEFAULT '{}',
            body_blob           BLOB
        );

        CREATE TABLE IF NOT EXISTS sync_meta (
            key     TEXT PRIMARY KEY,
            value   TEXT NOT NULL
        );
        INSERT OR IGNORE INTO sync_meta (key, value) VALUES ('last_request_rowid',  '0');
        INSERT OR IGNORE INTO sync_meta (key, value) VALUES ('last_response_rowid', '0');
        "#,
    )?;
    // Phase-2 upgrade for older staging DBs created without parent_staging_id.
    if !column_exists(conn, "pending_requests", "parent_staging_id")? {
        conn.execute_batch(
            "ALTER TABLE pending_requests ADD COLUMN parent_staging_id INTEGER;",
        )?;
    }
    Ok(())
}

// ── Schema helpers ────────────────────────────────────────────────────────────

fn column_exists(conn: &Connection, table: &str, col: &str) -> anyhow::Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let found = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(|r| r.ok())
        .any(|name| name == col);
    Ok(found)
}

// ── Session operations ────────────────────────────────────────────────────────

pub fn create_session(
    conn: &Connection,
    name: &str,
    user_role: &str,
) -> anyhow::Result<Session> {
    let now = Utc::now();
    conn.execute(
        "INSERT INTO sessions (name, user_role, created_at) VALUES (?1, ?2, ?3)",
        params![name, user_role, now.to_rfc3339()],
    )
    .context("Failed to insert session")?;
    Ok(Session {
        id:         conn.last_insert_rowid(),
        name:       name.to_owned(),
        user_role:  user_role.to_owned(),
        created_at: now,
    })
}

pub fn list_sessions(conn: &Connection) -> anyhow::Result<Vec<Session>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, user_role, created_at FROM sessions ORDER BY created_at DESC",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .filter_map(|r| r.ok())
        .map(|(id, name, user_role, ts)| Session {
            id,
            name,
            user_role,
            created_at: parse_dt(&ts),
        })
        .collect();
    Ok(rows)
}

pub fn find_session_by_name(
    conn: &Connection,
    name: &str,
) -> anyhow::Result<Option<Session>> {
    let res = conn
        .query_row(
            "SELECT id, name, user_role, created_at FROM sessions WHERE name = ?1",
            params![name],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()
        .context("query session")?;
    Ok(res.map(|(id, name, user_role, ts)| Session {
        id,
        name,
        user_role,
        created_at: parse_dt(&ts),
    }))
}

pub fn find_or_create_session(conn: &Connection, name: &str) -> anyhow::Result<i64> {
    if let Some(s) = find_session_by_name(conn, name)? {
        return Ok(s.id);
    }
    Ok(create_session(conn, name, "default")?.id)
}

pub fn get_session_stats(
    conn: &Connection,
    name: &str,
) -> anyhow::Result<Option<SessionStats>> {
    let session = match find_session_by_name(conn, name)? {
        Some(s) => s,
        None    => return Ok(None),
    };

    let request_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM requests WHERE session_id = ?1",
        params![session.id],
        |r| r.get(0),
    )?;
    let response_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM responses r
         JOIN requests req ON r.request_id = req.id
         WHERE req.session_id = ?1",
        params![session.id],
        |r| r.get(0),
    )?;
    let entity_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM entities e
         JOIN requests req ON e.request_id = req.id
         WHERE req.session_id = ?1",
        params![session.id],
        |r| r.get(0),
    )?;

    Ok(Some(SessionStats { session, request_count, response_count, entity_count }))
}

// ── Request / response write operations ──────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub fn insert_request(
    conn: &Connection,
    session_id:        i64,
    method:            &str,
    url:               &str,
    headers_json:      &str,
    body_blob:         Option<&[u8]>,
    timestamp:         &str,
    operation_name:    Option<&str>,
    is_websocket:      bool,
    parent_request_id: Option<i64>,
    staging_src_id:    Option<i64>,
) -> anyhow::Result<i64> {
    conn.execute(
        "INSERT INTO requests
         (session_id, method, url, headers_json, body_blob, timestamp,
          operation_name, is_websocket, parent_request_id, staging_src_id)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            session_id, method, url, headers_json, body_blob, timestamp,
            operation_name, is_websocket as i64, parent_request_id, staging_src_id
        ],
    )
    .context("insert request")?;
    Ok(conn.last_insert_rowid())
}

pub fn insert_response(
    conn: &Connection,
    request_id:  i64,
    status_code: i64,
    headers_json: &str,
    body_blob:   Option<&[u8]>,
) -> anyhow::Result<i64> {
    conn.execute(
        "INSERT OR IGNORE INTO responses (request_id, status_code, headers_json, body_blob)
         VALUES (?1, ?2, ?3, ?4)",
        params![request_id, status_code, headers_json, body_blob],
    )
    .context("insert response")?;
    Ok(conn.last_insert_rowid())
}

pub fn insert_correlation(
    conn:           &Connection,
    request_id:     i64,
    correlation_id: &str,
    source:         &str,
) -> anyhow::Result<i64> {
    conn.execute(
        "INSERT INTO correlations (request_id, correlation_id, source)
         VALUES (?1, ?2, ?3)",
        params![request_id, correlation_id, source],
    )
    .context("insert correlation")?;
    Ok(conn.last_insert_rowid())
}

pub fn insert_entity(
    conn:        &Connection,
    request_id:  i64,
    entity_type: &str,
    field_name:  &str,
    value:       &str,
    location:    &str,
) -> anyhow::Result<i64> {
    conn.execute(
        "INSERT INTO entities (request_id, entity_type, field_name, value, location)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![request_id, entity_type, field_name, value, location],
    )
    .context("insert entity")?;
    Ok(conn.last_insert_rowid())
}

/// Fetch a single request by its primary key.
pub fn get_request_by_id(
    conn: &Connection,
    id:   i64,
) -> anyhow::Result<Option<Request>> {
    conn.query_row(
        "SELECT id, session_id, method, url, headers_json, body_blob,
                timestamp, operation_name, is_websocket, parent_request_id
         FROM requests WHERE id = ?1",
        params![id],
        map_request_row,
    )
    .optional()
    .map_err(Into::into)
}

/// Look up the main-DB request.id that was synced from a particular staging rowid.
pub fn find_main_id_for_staging(
    conn:       &Connection,
    staging_id: i64,
) -> anyhow::Result<Option<i64>> {
    conn.query_row(
        "SELECT id FROM requests WHERE staging_src_id = ?1 LIMIT 1",
        params![staging_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

// ── sync_meta helpers ─────────────────────────────────────────────────────────

pub fn get_last_synced_rowid(conn: &Connection) -> anyhow::Result<i64> {
    let val: String = conn.query_row(
        "SELECT value FROM sync_meta WHERE key = 'last_synced_request_rowid'",
        [],
        |row| row.get(0),
    )?;
    Ok(val.parse().unwrap_or(0))
}

pub fn set_last_synced_rowid(conn: &Connection, rowid: i64) -> anyhow::Result<()> {
    conn.execute(
        "UPDATE sync_meta SET value = ?1 WHERE key = 'last_synced_request_rowid'",
        params![rowid.to_string()],
    )?;
    Ok(())
}

// ── Dependency edge operations ────────────────────────────────────────────────

pub fn save_dependency_edges(
    conn:       &Connection,
    session_id: i64,
    edges:      &[crate::deps::DependencyEdge],
) -> anyhow::Result<usize> {
    let mut count = 0usize;
    for e in edges {
        conn.execute(
            "INSERT INTO dependency_edges
             (session_id, source_type, source_id, target_request_id,
              field_name, value, edge_type)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                session_id,
                e.source_type.as_str(),
                e.source_id,
                e.target_request_id,
                e.field_name,
                e.value,
                e.edge_type.as_str(),
            ],
        )?;
        count += 1;
    }
    Ok(count)
}

pub fn load_dependency_edges(
    conn:       &Connection,
    session_id: i64,
) -> anyhow::Result<Vec<crate::deps::DependencyEdge>> {
    let mut stmt = conn.prepare(
        "SELECT id, source_type, source_id, target_request_id, field_name, value, edge_type
         FROM dependency_edges WHERE session_id = ?1 ORDER BY id ASC",
    )?;
    let rows = stmt
        .query_map(params![session_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?
        .filter_map(|r| r.ok())
        .map(|(id, src_type, src_id, tgt, field, val, etype)| {
            crate::deps::DependencyEdge {
                id: Some(id),
                session_id,
                source_type: crate::deps::DependencySourceType::from_str(&src_type),
                source_id: src_id,
                target_request_id: tgt,
                field_name: field,
                value: val,
                edge_type: crate::deps::DependencyEdgeType::from_str(&etype),
            }
        })
        .collect();
    Ok(rows)
}

// ── Auth finding operations ───────────────────────────────────────────────────

pub fn save_auth_findings(
    conn:     &Connection,
    findings: &[crate::auth::AuthFinding],
) -> anyhow::Result<usize> {
    let now = Utc::now().to_rfc3339();
    let mut count = 0usize;
    for f in findings {
        let evidence_json = serde_json::to_string(&f.evidence).unwrap_or_default();
        conn.execute(
            "INSERT INTO auth_findings
             (session_a, session_b, url_pattern, method, finding_type, severity,
              details, evidence_json, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                f.session_a,
                f.session_b,
                f.url_pattern,
                f.method,
                f.finding_type.as_str(),
                f.severity.as_str(),
                f.details,
                evidence_json,
                now,
            ],
        )?;
        count += 1;
    }
    Ok(count)
}

pub fn load_auth_findings(conn: &Connection) -> anyhow::Result<Vec<crate::auth::AuthFinding>> {
    let mut stmt = conn.prepare(
        "SELECT session_a, session_b, url_pattern, method, finding_type, severity,
                details, evidence_json
         FROM auth_findings ORDER BY id ASC",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })?
        .filter_map(|r| r.ok())
        .map(|(sa, sb, url_pat, method, ftype, sev, details, ev_json)| {
            let evidence = serde_json::from_str(&ev_json).unwrap_or_default();
            crate::auth::AuthFinding {
                session_a:    sa,
                session_b:    sb,
                url_pattern:  url_pat,
                method,
                finding_type: crate::auth::AuthFindingType::from_str(&ftype),
                severity:     crate::auth::Severity::from_str(&sev),
                details,
                evidence,
            }
        })
        .collect();
    Ok(rows)
}

// ── Session export ────────────────────────────────────────────────────────────

pub fn export_session(conn: &Connection, name: &str) -> anyhow::Result<SessionExport> {
    let session = find_session_by_name(conn, name)?
        .ok_or_else(|| anyhow::anyhow!("Session '{name}' not found"))?;

    let requests = get_requests_for_session(conn, session.id)?;
    let total_requests = requests.len();
    let mut total_responses = 0usize;
    let mut exports = Vec::with_capacity(total_requests);

    for req in requests {
        let req_id   = req.id;
        let response = get_response_for_request(conn, req_id)?;
        if response.is_some() { total_responses += 1; }
        exports.push(RequestExport {
            request:      RequestSummary::from_request(req),
            response:     response.map(ResponseSummary::from_response),
            entities:     get_entities_for_request(conn, req_id)?,
            correlations: get_correlations_for_request(conn, req_id)?,
        });
    }

    Ok(SessionExport { session, total_requests, total_responses, requests: exports })
}

// ── Internal read helpers ─────────────────────────────────────────────────────

/// Full request row including Phase-2 columns.
pub fn get_requests_for_session(
    conn:       &Connection,
    session_id: i64,
) -> anyhow::Result<Vec<Request>> {
    let mut stmt = conn.prepare(
        "SELECT id, session_id, method, url, headers_json, body_blob,
                timestamp, operation_name, is_websocket, parent_request_id
         FROM requests WHERE session_id = ?1 ORDER BY id ASC",
    )?;
    let rows = stmt
        .query_map(params![session_id], map_request_row)?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

pub fn get_response_for_request(
    conn:       &Connection,
    request_id: i64,
) -> anyhow::Result<Option<Response>> {
    conn.query_row(
        "SELECT id, request_id, status_code, headers_json, body_blob
         FROM responses WHERE request_id = ?1",
        params![request_id],
        |row| {
            Ok(Response {
                id:           row.get(0)?,
                request_id:   row.get(1)?,
                status_code:  row.get(2)?,
                headers_json: row.get(3)?,
                body_blob:    row.get(4)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

pub fn get_entities_for_request(
    conn:       &Connection,
    request_id: i64,
) -> anyhow::Result<Vec<Entity>> {
    let mut stmt = conn.prepare(
        "SELECT id, request_id, entity_type, field_name, value, location
         FROM entities WHERE request_id = ?1 ORDER BY id ASC",
    )?;
    let rows = stmt
        .query_map(params![request_id], |row| {
            Ok(Entity {
                id:          Some(row.get(0)?),
                request_id:  row.get(1)?,
                entity_type: parse_entity_type(row.get::<_, String>(2)?.as_str()),
                field_name:  row.get(3)?,
                value:       row.get(4)?,
                location:    parse_entity_location(row.get::<_, String>(5)?.as_str()),
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

pub fn get_correlations_for_request(
    conn:       &Connection,
    request_id: i64,
) -> anyhow::Result<Vec<Correlation>> {
    let mut stmt = conn.prepare(
        "SELECT id, request_id, correlation_id, source
         FROM correlations WHERE request_id = ?1",
    )?;
    let rows = stmt
        .query_map(params![request_id], |row| {
            let src: String = row.get(3)?;
            Ok(Correlation {
                id:             row.get(0)?,
                request_id:     row.get(1)?,
                correlation_id: row.get(2)?,
                source:         src.parse().unwrap_or(CorrelationSource::Hash),
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

/// Load all (request, response) pairs for a session in insertion order.
/// Used by the flow-engine modules (deps, graph, differ).
pub fn get_pairs_for_session(
    conn:       &Connection,
    session_id: i64,
) -> anyhow::Result<Vec<(Request, Option<Response>)>> {
    let reqs = get_requests_for_session(conn, session_id)?;
    let mut pairs = Vec::with_capacity(reqs.len());
    for req in reqs {
        let resp = get_response_for_request(conn, req.id)?;
        pairs.push((req, resp));
    }
    Ok(pairs)
}

// ── Row mappers ───────────────────────────────────────────────────────────────

fn map_request_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Request> {
    let ts: String = row.get(6)?;
    Ok(Request {
        id:                row.get(0)?,
        session_id:        row.get(1)?,
        method:            row.get(2)?,
        url:               row.get(3)?,
        headers_json:      row.get(4)?,
        body_blob:         row.get(5)?,
        timestamp:         parse_dt_rusqlite(&ts),
        operation_name:    row.get(7)?,
        is_websocket:      row.get::<_, i64>(8).unwrap_or(0) != 0,
        parent_request_id: row.get(9).unwrap_or(None),
    })
}

fn parse_dt_rusqlite(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn parse_dt(s: &str) -> DateTime<Utc> {
    parse_dt_rusqlite(s)
}

fn parse_entity_type(s: &str) -> EntityType {
    match s {
        "uuid"              => EntityType::Uuid,
        "numeric_id"        => EntityType::NumericId,
        "slug"              => EntityType::Slug,
        "user_identifier"   => EntityType::UserIdentifier,
        "tenant_identifier" => EntityType::TenantIdentifier,
        "auth_token"        => EntityType::AuthToken,
        "jwt_token"         => EntityType::JwtToken,
        "csrf_token"        => EntityType::CsrfToken,
        "graphql_variable"  => EntityType::GraphqlVariable,
        _                   => EntityType::Unknown,
    }
}

fn parse_entity_location(s: &str) -> EntityLocation {
    match s {
        "url"    => EntityLocation::Url,
        "header" => EntityLocation::Header,
        "body"   => EntityLocation::Body,
        "cookie" => EntityLocation::Cookie,
        _        => EntityLocation::Url,
    }
}
