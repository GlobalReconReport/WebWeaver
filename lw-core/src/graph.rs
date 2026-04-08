//! State graph builder — produces a petgraph DiGraph where nodes are requests
//! and edges are dependency flows.  WebSocket connections are first-class nodes
//! with child message nodes.

use std::collections::{HashMap, HashSet};

use once_cell::sync::Lazy;
use petgraph::graph::{DiGraph, NodeIndex};
use regex::Regex;
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;

use crate::db::{get_pairs_for_session, load_dependency_edges};
use crate::deps::DependencyTracker;

// ── URL normalisation ─────────────────────────────────────────────────────────

static UUID_PAT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    .unwrap()
});
static NUM_PAT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\d{1,18}$").unwrap());

/// Replace UUID and numeric path segments with `:uuid` / `:id`.
/// Query strings are stripped — normalization is for grouping, not display.
pub fn normalize_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(parsed) => {
            let norm_path: String = parsed
                .path()
                .split('/')
                .map(|seg| {
                    if seg.is_empty()         { seg }
                    else if UUID_PAT.is_match(seg) { ":uuid" }
                    else if NUM_PAT.is_match(seg)  { ":id" }
                    else                      { seg }
                })
                .collect::<Vec<_>>()
                .join("/");

            let host = parsed.host_str().unwrap_or("");
            format!("{host}{norm_path}")
        }
        Err(_) => url.to_owned(),
    }
}

// ── Graph node / edge types ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    /// Plain HTTP request/response.
    Http,
    /// HTTP 101 upgrade request that opened a WebSocket connection.
    WsUpgrade,
    /// An individual WebSocket frame (child of a WsUpgrade node).
    WsMessage,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowNode {
    pub request_id:     i64,
    pub kind:           NodeKind,
    pub method:         String,
    pub url_pattern:    String,
    pub url_raw:        String,
    pub status_code:    Option<i64>,
    pub operation_name: Option<String>,
    pub entity_types:   Vec<String>,
    pub timestamp:      String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowEdge {
    pub field_name:  String,
    /// Truncated value hint for display (max 32 chars + …).
    pub value_hint:  String,
    pub edge_type:   String,
    /// True for sequential WebSocket frame ordering edges.
    pub is_ws_seq:   bool,
}

// ── FlowGraph ─────────────────────────────────────────────────────────────────

pub struct FlowGraph {
    inner:    DiGraph<FlowNode, FlowEdge>,
    #[allow(dead_code)]
    node_map: HashMap<i64, NodeIndex>,
}

impl FlowGraph {
    /// Build the graph for `session_id`.
    ///
    /// Dependency edges are loaded from the DB if already computed; otherwise
    /// they are computed on-the-fly (but not saved — call `analyze_deps` to
    /// persist them first).
    pub fn build(conn: &Connection, session_id: i64) -> anyhow::Result<Self> {
        let pairs = get_pairs_for_session(conn, session_id)?;

        // Load or compute dependency edges.
        let dep_edges = {
            let stored = load_dependency_edges(conn, session_id)?;
            if !stored.is_empty() {
                stored
            } else {
                DependencyTracker::new().analyze_session(conn, session_id)?
            }
        };

        // Identify which requests are WS upgrades (have WS message children).
        let ws_upgrade_ids: HashSet<i64> = pairs
            .iter()
            .filter_map(|(req, _)| req.parent_request_id)
            .collect();

        let mut graph  = DiGraph::new();
        let mut node_map: HashMap<i64, NodeIndex> = HashMap::new();

        // ── Add nodes ────────────────────────────────────────────────────
        for (req, resp) in &pairs {
            let kind = if req.is_websocket {
                NodeKind::WsMessage
            } else if ws_upgrade_ids.contains(&req.id) {
                NodeKind::WsUpgrade
            } else {
                NodeKind::Http
            };

            let status_code = resp.as_ref().map(|r| r.status_code);
            let url_pattern = if req.is_websocket {
                format!("ws_msg:{}", &req.url)
            } else {
                normalize_url(&req.url)
            };

            let node = FlowNode {
                request_id:     req.id,
                kind,
                method:         req.method.clone(),
                url_pattern:    url_pattern.clone(),
                url_raw:        req.url.clone(),
                status_code,
                operation_name: req.operation_name.clone(),
                entity_types:   Vec::new(), // populated below
                timestamp:      req.timestamp.to_rfc3339(),
            };

            let idx = graph.add_node(node);
            node_map.insert(req.id, idx);
        }

        // ── WS message sequential edges ──────────────────────────────────
        // Group WS messages by their parent upgrade request, then chain them.
        let mut ws_children: HashMap<i64, Vec<i64>> = HashMap::new();
        for (req, _) in &pairs {
            if req.is_websocket {
                if let Some(parent_id) = req.parent_request_id {
                    ws_children.entry(parent_id).or_default().push(req.id);
                }
            }
        }
        for (parent_id, mut children) in ws_children {
            // Sort by request id (proxy for insertion order / timestamp).
            children.sort_unstable();

            // Edge: upgrade → first child
            if let (Some(&parent_idx), Some(&first_idx)) = (
                node_map.get(&parent_id),
                children.first().and_then(|id| node_map.get(id)),
            ) {
                graph.add_edge(
                    parent_idx,
                    first_idx,
                    FlowEdge {
                        field_name: "ws:open".into(),
                        value_hint: String::new(),
                        edge_type:  "ws_open".into(),
                        is_ws_seq:  true,
                    },
                );
            }

            // Sequential edges between consecutive messages.
            for win in children.windows(2) {
                if let (Some(&a), Some(&b)) =
                    (node_map.get(&win[0]), node_map.get(&win[1]))
                {
                    graph.add_edge(
                        a,
                        b,
                        FlowEdge {
                            field_name: "ws:next".into(),
                            value_hint: String::new(),
                            edge_type:  "ws_sequence".into(),
                            is_ws_seq:  true,
                        },
                    );
                }
            }
        }

        // ── Dependency edges ─────────────────────────────────────────────
        for dep in &dep_edges {
            // Find the node that "provided" the value (source response's request).
            // We need to find the request that produced the source response.
            let src_request_idx = find_source_node(conn, dep, &node_map)?;

            if let (Some(src_idx), Some(&tgt_idx)) =
                (src_request_idx, node_map.get(&dep.target_request_id))
            {
                if src_idx != tgt_idx {
                    let hint = if dep.value.len() > 32 {
                        format!("{}…", &dep.value[..32])
                    } else {
                        dep.value.clone()
                    };
                    graph.add_edge(
                        src_idx,
                        tgt_idx,
                        FlowEdge {
                            field_name: dep.field_name.clone(),
                            value_hint: hint,
                            edge_type:  dep.edge_type.as_str().to_owned(),
                            is_ws_seq:  false,
                        },
                    );
                }
            }
        }

        Ok(FlowGraph { inner: graph, node_map })
    }

    pub fn node_count(&self) -> usize { self.inner.node_count() }
    pub fn edge_count(&self) -> usize { self.inner.edge_count() }

    // ── Serialisation ─────────────────────────────────────────────────────

    /// Emit a Graphviz DOT representation.
    pub fn to_dot(&self) -> String {
        let mut out = String::from(
            "digraph webweaver {\n    rankdir=LR;\n    node [fontsize=10 fontname=monospace];\n\n",
        );

        for idx in self.inner.node_indices() {
            let n = &self.inner[idx];
            let (shape, color) = node_style(&n.kind);
            let status = n.status_code.map_or(String::new(), |s| format!(" [{s}]"));
            let op = n.operation_name.as_deref().map_or(String::new(), |o| format!("\\n({o})"));
            let label = format!(
                "{} {}{}{}",
                n.method, n.url_pattern, status, op
            );
            out.push_str(&format!(
                "    n{} [label=\"{label}\" shape={shape} style=filled fillcolor={color}];\n",
                idx.index()
            ));
        }

        out.push('\n');

        for eidx in self.inner.edge_indices() {
            let (src, dst) = self.inner.edge_endpoints(eidx).unwrap();
            let e = &self.inner[eidx];
            let (style, color) = edge_style(e);
            let label = if e.is_ws_seq {
                e.field_name.clone()
            } else {
                format!("{}: {}", e.edge_type, e.field_name)
            };
            out.push_str(&format!(
                "    n{} -> n{} [label=\"{label}\" style={style} color={color}];\n",
                src.index(),
                dst.index()
            ));
        }

        out.push('}');
        out
    }

    /// Emit a JSON representation suitable for further tooling.
    pub fn to_json(&self) -> anyhow::Result<String> {
        let nodes: Vec<_> = self
            .inner
            .node_indices()
            .map(|idx| {
                let n = &self.inner[idx];
                serde_json::json!({
                    "index":          idx.index(),
                    "request_id":     n.request_id,
                    "kind":           format!("{:?}", n.kind).to_lowercase(),
                    "method":         n.method,
                    "url_pattern":    n.url_pattern,
                    "url_raw":        n.url_raw,
                    "status_code":    n.status_code,
                    "operation_name": n.operation_name,
                    "timestamp":      n.timestamp,
                })
            })
            .collect();

        let edges: Vec<_> = self
            .inner
            .edge_indices()
            .map(|eidx| {
                let (src, dst) = self.inner.edge_endpoints(eidx).unwrap();
                let e = &self.inner[eidx];
                serde_json::json!({
                    "source":     src.index(),
                    "target":     dst.index(),
                    "field_name": e.field_name,
                    "value_hint": e.value_hint,
                    "edge_type":  e.edge_type,
                    "is_ws_seq":  e.is_ws_seq,
                })
            })
            .collect();

        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "node_count": nodes.len(),
            "edge_count": edges.len(),
            "nodes":      nodes,
            "edges":      edges,
        }))?)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Given a dependency edge, find the NodeIndex of the request that PRODUCED
/// the source value.  For a Response source, that is the request whose response
/// has id == dep.source_id.  For a WsMessage source, the message IS the request.
fn find_source_node(
    conn:     &Connection,
    dep:      &crate::deps::DependencyEdge,
    node_map: &HashMap<i64, NodeIndex>,
) -> anyhow::Result<Option<NodeIndex>> {
    use crate::deps::DependencySourceType;
    match dep.source_type {
        DependencySourceType::WsMessage => {
            Ok(node_map.get(&dep.source_id).copied())
        }
        DependencySourceType::Response => {
            // Find the request_id for this response.
            let req_id: Option<i64> = conn
                .query_row(
                    "SELECT request_id FROM responses WHERE id = ?1",
                    rusqlite::params![dep.source_id],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(req_id.and_then(|rid| node_map.get(&rid).copied()))
        }
    }
}

fn node_style(kind: &NodeKind) -> (&'static str, &'static str) {
    match kind {
        NodeKind::Http      => ("box",      "lightblue"),
        NodeKind::WsUpgrade => ("cylinder", "lightgreen"),
        NodeKind::WsMessage => ("note",     "honeydew"),
    }
}

fn edge_style(e: &FlowEdge) -> (&'static str, &'static str) {
    if e.is_ws_seq {
        return ("dotted", "darkgreen");
    }
    match e.edge_type.as_str() {
        "cookie"       => ("solid",  "blue"),
        "auth_token"   => ("solid",  "red"),
        "csrf_token"   => ("solid",  "orange"),
        "entity_id"    => ("dashed", "purple"),
        "redirect_url" => ("dashed", "gray"),
        _              => ("dashed", "black"),
    }
}
