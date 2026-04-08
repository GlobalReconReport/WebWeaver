use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

// ── Core DB models ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: i64,
    pub name: String,
    pub user_role: String,
    pub created_at: DateTime<Utc>,
}

/// A captured HTTP request or WebSocket message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: i64,
    pub session_id: i64,
    pub method: String,
    pub url: String,
    pub headers_json: String,
    #[serde(skip)]
    pub body_blob: Option<Vec<u8>>,
    pub timestamp: DateTime<Utc>,
    pub operation_name: Option<String>,
    /// True for WebSocket frames captured via mitmproxy's websocket_message hook.
    pub is_websocket: bool,
    /// For WebSocket messages: the request ID of the HTTP upgrade request.
    pub parent_request_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub id: i64,
    pub request_id: i64,
    pub status_code: i64,
    pub headers_json: String,
    #[serde(skip)]
    pub body_blob: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Correlation {
    pub id: i64,
    pub request_id: i64,
    pub correlation_id: String,
    pub source: CorrelationSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CorrelationSource {
    Header,
    Timestamp,
    Hash,
}

impl CorrelationSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Header    => "header",
            Self::Timestamp => "timestamp",
            Self::Hash      => "hash",
        }
    }
}

impl fmt::Display for CorrelationSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for CorrelationSource {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "header"    => Ok(Self::Header),
            "timestamp" => Ok(Self::Timestamp),
            "hash"      => Ok(Self::Hash),
            _           => Err(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    pub id: Option<i64>,
    pub request_id: i64,
    pub entity_type: EntityType,
    pub field_name: String,
    pub value: String,
    pub location: EntityLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Uuid,
    NumericId,
    Slug,
    UserIdentifier,
    TenantIdentifier,
    AuthToken,
    JwtToken,
    CsrfToken,
    GraphqlVariable,
    Unknown,
}

impl EntityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Uuid             => "uuid",
            Self::NumericId        => "numeric_id",
            Self::Slug             => "slug",
            Self::UserIdentifier   => "user_identifier",
            Self::TenantIdentifier => "tenant_identifier",
            Self::AuthToken        => "auth_token",
            Self::JwtToken         => "jwt_token",
            Self::CsrfToken        => "csrf_token",
            Self::GraphqlVariable  => "graphql_variable",
            Self::Unknown          => "unknown",
        }
    }
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EntityLocation {
    Url,
    Header,
    Body,
    Cookie,
}

impl EntityLocation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Url    => "url",
            Self::Header => "header",
            Self::Body   => "body",
            Self::Cookie => "cookie",
        }
    }
}

impl fmt::Display for EntityLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Staging DB models ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub staging_id:        i64,
    pub session_name:      String,
    pub method:            String,
    pub url:               String,
    pub headers_json:      String,
    pub body_blob:         Option<Vec<u8>>,
    pub timestamp:         String,
    pub correlation_id:    Option<String>,
    pub correlation_source:Option<String>,
    pub is_websocket:      bool,
    pub ws_opcode:         Option<i64>,
    pub operation_name:    Option<String>,
    /// staging.id of the HTTP upgrade request that opened this WS connection.
    pub parent_staging_id: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct PendingResponse {
    pub staging_id:         i64,
    pub request_staging_id: i64,
    pub status_code:        i64,
    pub headers_json:       String,
    pub body_blob:          Option<Vec<u8>>,
}

// ── Export / report models ────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionExport {
    pub session:         Session,
    pub total_requests:  usize,
    pub total_responses: usize,
    pub requests:        Vec<RequestExport>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequestExport {
    pub request:      RequestSummary,
    pub response:     Option<ResponseSummary>,
    pub entities:     Vec<Entity>,
    pub correlations: Vec<Correlation>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequestSummary {
    pub id:             i64,
    pub session_id:     i64,
    pub method:         String,
    pub url:            String,
    pub headers_json:   String,
    pub body:           Option<String>,
    pub timestamp:      DateTime<Utc>,
    pub operation_name: Option<String>,
    pub is_websocket:   bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseSummary {
    pub id:           i64,
    pub request_id:   i64,
    pub status_code:  i64,
    pub headers_json: String,
    pub body:         Option<String>,
}

impl RequestSummary {
    pub fn from_request(r: Request) -> Self {
        let body = r.body_blob.map(|b| {
            String::from_utf8(b.clone()).unwrap_or_else(|_| hex::encode(&b))
        });
        Self {
            id: r.id,
            session_id: r.session_id,
            method: r.method,
            url: r.url,
            headers_json: r.headers_json,
            body,
            timestamp: r.timestamp,
            operation_name: r.operation_name,
            is_websocket: r.is_websocket,
        }
    }
}

impl ResponseSummary {
    pub fn from_response(r: Response) -> Self {
        let body = r.body_blob.map(|b| {
            String::from_utf8(b.clone()).unwrap_or_else(|_| hex::encode(&b))
        });
        Self {
            id: r.id,
            request_id: r.request_id,
            status_code: r.status_code,
            headers_json: r.headers_json,
            body,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionStats {
    pub session:        Session,
    pub request_count:  i64,
    pub response_count: i64,
    pub entity_count:   i64,
}
