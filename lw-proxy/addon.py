"""
WebWeaver mitmproxy addon  (lw-proxy)
======================================
Captures all HTTP/S and WebSocket traffic into a staging SQLite database that
lw-core polls and merges into the main database every 500 ms.

Usage
-----
    mitmproxy -s addon.py \\
        --set ww_session=admin-flow \\
        --set ww_db=/path/to/webweaver_staging.db \\
        --set ww_graphql_introspect=true

    mitmdump -s addon.py --set ww_session=guest-flow -p 8080

Options
-------
ww_session           Session name tag written to every captured request.
                     (default: "default")
ww_db                Path to the staging SQLite file.
                     (default: "webweaver_staging.db")
ww_graphql_introspect
                     If true, log a WARNING for every GraphQL introspection
                     query detected.  (default: false)
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Optional

from mitmproxy import ctx, http
from mitmproxy.addonmanager import Loader

log = logging.getLogger(__name__)

# ── Schema for the staging database ──────────────────────────────────────────

_STAGING_SCHEMA = """\
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

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
    -- Phase 2: rowid of the HTTP upgrade request that opened this WS connection.
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
"""

# ── GraphQL helpers ───────────────────────────────────────────────────────────

_OP_RE = re.compile(
    r"^\s*(query|mutation|subscription)\s*(\w+)?", re.IGNORECASE
)


def _detect_graphql(
    url: str,
    headers: dict[str, str],
    body: Optional[bytes],
) -> tuple[Optional[str], Optional[str]]:
    """
    Returns ``(operation_name, operation_type)`` when the request looks like a
    GraphQL operation, or ``(None, None)`` otherwise.
    """
    if not body:
        return None, None

    ct = headers.get("content-type", "").lower()
    url_lower = url.lower()
    is_gql_url = (
        "/graphql" in url_lower
        or "/graph/" in url_lower
        or url_lower.endswith("/gql")
    )
    is_json = "application/json" in ct or "application/graphql" in ct

    if not (is_gql_url or is_json):
        return None, None

    try:
        data = json.loads(body.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, AttributeError):
        return None, None

    if not isinstance(data, dict):
        return None, None

    query = data.get("query") or data.get("mutation")
    if not query or not isinstance(query, str):
        return None, None

    # Operation name from envelope field
    op_name: Optional[str] = data.get("operationName") or None

    # Parse from the query string
    m = _OP_RE.match(query)
    op_type = m.group(1).lower() if m else "query"
    if not op_name and m and m.group(2):
        op_name = m.group(2)

    return op_name, op_type


def _is_introspection(body: Optional[bytes]) -> bool:
    if not body:
        return False
    text = body.decode("utf-8", errors="replace")
    return (
        "__schema" in text
        or "IntrospectionQuery" in text
        or "__type" in text
    )


# ── Correlation helpers ───────────────────────────────────────────────────────

def _body_hash(method: str, url: str, body: Optional[bytes]) -> str:
    h = hashlib.sha256()
    h.update(method.encode())
    h.update(url.encode())
    if body:
        h.update(body)
    return h.hexdigest()[:24]


def _headers_dict(headers) -> dict[str, str]:
    """Convert mitmproxy Headers (multi-dict) to a plain str→str dict."""
    out: dict[str, str] = {}
    for name, value in headers.items():
        # Last value wins for duplicate names — sufficient for our purposes.
        out[name] = value
    return out


# ── Addon class ───────────────────────────────────────────────────────────────

class WebWeaverAddon:
    """
    mitmproxy addon that writes all traffic to a staging SQLite database.
    lw-core (Rust) polls this DB every 500 ms and merges it into the main DB.
    """

    def __init__(self) -> None:
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()
        # Maps flow.id (str) → staging pending_requests.id (int)
        self._flow_rowid: dict[str, int] = {}

    # ── mitmproxy lifecycle ───────────────────────────────────────────────────

    def load(self, loader: Loader) -> None:
        loader.add_option(
            name="ww_session",
            typespec=str,
            default="default",
            help="WebWeaver session name tag",
        )
        loader.add_option(
            name="ww_db",
            typespec=str,
            default="webweaver_staging.db",
            help="Path to the staging SQLite database",
        )
        loader.add_option(
            name="ww_graphql_introspect",
            typespec=bool,
            default=False,
            help="Warn on GraphQL introspection queries",
        )

    def configure(self, updates) -> None:
        if "ww_db" in updates:
            self._connect(ctx.options.ww_db)

    def running(self) -> None:
        # Called after all options are applied; safe to open DB now.
        if self._conn is None:
            self._connect(ctx.options.ww_db)

    # ── Traffic hooks ─────────────────────────────────────────────────────────

    def request(self, flow: http.HTTPFlow) -> None:
        self._save_request(flow)

    def response(self, flow: http.HTTPFlow) -> None:
        self._save_response(flow)

    def websocket_message(self, flow: http.HTTPFlow) -> None:  # type: ignore[override]
        self._save_ws_message(flow)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _connect(self, db_path: str) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None
            try:
                conn = sqlite3.connect(db_path, check_same_thread=False)
                conn.executescript(_STAGING_SCHEMA)
                # Phase-2 migration: add parent_staging_id if an older DB lacks it.
                try:
                    conn.execute(
                        "ALTER TABLE pending_requests ADD COLUMN parent_staging_id INTEGER"
                    )
                    conn.commit()
                except Exception:
                    pass  # Column already exists — that is fine.
                conn.commit()
                self._conn = conn
                log.info("[WebWeaver] staging DB ready: %s", db_path)
            except Exception as exc:
                log.error("[WebWeaver] cannot open staging DB %s: %s", db_path, exc)

    def _save_request(self, flow: http.HTTPFlow) -> None:
        if self._conn is None:
            return

        session  = ctx.options.ww_session
        url      = flow.request.pretty_url
        method   = flow.request.method
        headers  = _headers_dict(flow.request.headers)
        body     = flow.request.content or None
        now      = datetime.now(timezone.utc).isoformat()

        # Correlation: prefer explicit session header, else hash
        corr_id  = headers.get("X-LW-Session") or headers.get("x-lw-session")
        corr_src = "header" if corr_id else None
        if not corr_id:
            corr_id  = _body_hash(method, url, body)
            corr_src = "hash"

        # GraphQL
        op_name, _op_type = _detect_graphql(url, headers, body)

        if ctx.options.ww_graphql_introspect and _is_introspection(body):
            log.warning("[WebWeaver] GraphQL introspection detected: %s", url)

        headers_json = json.dumps(headers)

        try:
            with self._lock:
                cur = self._conn.execute(
                    """
                    INSERT INTO pending_requests
                        (session_name, method, url, headers_json, body_blob,
                         timestamp, correlation_id, correlation_source,
                         is_websocket, operation_name)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                    """,
                    (session, method, url, headers_json, body,
                     now, corr_id, corr_src, op_name),
                )
                self._conn.commit()
                self._flow_rowid[flow.id] = cur.lastrowid
        except Exception as exc:
            log.error("[WebWeaver] failed to write request: %s", exc)

    def _save_response(self, flow: http.HTTPFlow) -> None:
        if self._conn is None or flow.response is None:
            return

        staging_req_id = self._flow_rowid.get(flow.id)
        if staging_req_id is None:
            return

        status       = flow.response.status_code
        headers      = _headers_dict(flow.response.headers)
        body         = flow.response.content or None
        headers_json = json.dumps(headers)

        try:
            with self._lock:
                self._conn.execute(
                    """
                    INSERT INTO pending_responses
                        (request_staging_id, status_code, headers_json, body_blob)
                    VALUES (?, ?, ?, ?)
                    """,
                    (staging_req_id, status, headers_json, body),
                )
                self._conn.commit()
        except Exception as exc:
            log.error("[WebWeaver] failed to write response: %s", exc)
        finally:
            self._flow_rowid.pop(flow.id, None)

    def _save_ws_message(self, flow: http.HTTPFlow) -> None:
        """Capture individual WebSocket frames as pseudo-requests.

        The ``parent_staging_id`` is set to the staging rowid of the HTTP
        upgrade request that opened this connection, enabling lw-core to
        reconstruct the WebSocket connection node in the state graph.
        """
        if self._conn is None:
            return
        if not hasattr(flow, "websocket") or flow.websocket is None:
            return
        if not flow.websocket.messages:
            return

        msg     = flow.websocket.messages[-1]
        content = msg.content if isinstance(msg.content, bytes) else (msg.content or b"").encode()
        # mitmproxy message types: 1 = TEXT, 2 = BINARY
        opcode  = getattr(msg, "type", 1)
        if hasattr(opcode, "value"):
            opcode = opcode.value

        session      = ctx.options.ww_session
        url          = flow.request.pretty_url
        now          = datetime.now(timezone.utc).isoformat()
        corr_id      = _body_hash("WEBSOCKET", url, content)
        headers_json = json.dumps(_headers_dict(flow.request.headers))

        # The HTTP upgrade request for this flow was stored in _flow_rowid when
        # request() was called.  That rowid becomes the parent_staging_id for
        # every WS frame on this connection.
        upgrade_staging_id: Optional[int] = self._flow_rowid.get(flow.id)

        try:
            with self._lock:
                self._conn.execute(
                    """
                    INSERT INTO pending_requests
                        (session_name, method, url, headers_json, body_blob,
                         timestamp, correlation_id, correlation_source,
                         is_websocket, ws_opcode, parent_staging_id)
                    VALUES (?, 'WEBSOCKET', ?, ?, ?, ?, ?, 'hash', 1, ?, ?)
                    """,
                    (session, url, headers_json, content,
                     now, corr_id, opcode, upgrade_staging_id),
                )
                self._conn.commit()
        except Exception as exc:
            log.error("[WebWeaver] failed to write WebSocket message: %s", exc)


# mitmproxy looks for this module-level list at load time.
addons = [WebWeaverAddon()]
