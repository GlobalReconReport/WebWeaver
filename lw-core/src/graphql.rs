use std::collections::HashMap;

/// Result of GraphQL detection on a single request.
#[derive(Debug, Clone)]
pub struct GraphqlInfo {
    /// Value of `operationName` field, or parsed from the query string.
    pub operation_name: Option<String>,
    /// "query" | "mutation" | "subscription"
    pub operation_type: String,
    /// The full `variables` object, if present.
    pub variables: HashMap<String, serde_json::Value>,
    /// True when the body contains `__schema` / `IntrospectionQuery` / `__type`.
    pub is_introspection: bool,
}

pub struct GraphqlDetector;

impl GraphqlDetector {
    pub fn new() -> Self {
        Self
    }

    /// Returns `Some(GraphqlInfo)` when the request looks like a GraphQL
    /// operation, `None` otherwise.
    pub fn detect(
        &self,
        url: &str,
        headers_json: &str,
        body: Option<&[u8]>,
    ) -> Option<GraphqlInfo> {
        let content_type = extract_content_type(headers_json);
        let url_lower = url.to_lowercase();

        let is_gql_url = url_lower.contains("/graphql")
            || url_lower.contains("/graph/")
            || url_lower.ends_with("/gql")
            || url_lower.contains("graphql");

        let is_json_ct = content_type
            .as_deref()
            .map(|ct| ct.contains("application/json") || ct.contains("application/graphql"))
            .unwrap_or(false);

        let body_bytes = body?;

        // Only attempt JSON parse if URL or content-type hints at GraphQL.
        if !is_gql_url && !is_json_ct {
            return None;
        }

        let data: serde_json::Value =
            serde_json::from_slice(body_bytes).ok()?;
        let obj = data.as_object()?;

        // Must have a `query` key with a non-empty string
        let query_str = obj
            .get("query")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())?;

        let is_introspection = query_str.contains("__schema")
            || query_str.contains("IntrospectionQuery")
            || query_str.contains("__type");

        // Extract operation name from the envelope or by parsing the query string
        let op_name_from_field = obj
            .get("operationName")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned);

        let (operation_name, operation_type) =
            parse_operation(query_str, op_name_from_field);

        // Collect variables (flat map: top-level keys → values)
        let variables = obj
            .get("variables")
            .and_then(|v| v.as_object())
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default();

        Some(GraphqlInfo {
            operation_name,
            operation_type,
            variables,
            is_introspection,
        })
    }
}

impl Default for GraphqlDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract the Content-Type value from a JSON-encoded headers object.
fn extract_content_type(headers_json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(headers_json).ok()?;
    let obj = v.as_object()?;
    // Header names may be any case
    for (k, val) in obj {
        if k.eq_ignore_ascii_case("content-type") {
            return val.as_str().map(str::to_lowercase);
        }
    }
    None
}

/// Given the raw query string and an optional envelope operation name, return
/// `(operation_name, operation_type)`.
fn parse_operation(
    query: &str,
    envelope_name: Option<String>,
) -> (Option<String>, String) {
    // Quick regex-free parse of the opening tokens:
    // Examples:
    //   query GetUser { ... }
    //   mutation { ... }
    //   subscription OnMessage($id: ID!) { ... }
    let trimmed = query.trim();
    let mut tokens = trimmed.split_whitespace();

    let op_type = match tokens.next() {
        Some(kw) if kw.eq_ignore_ascii_case("mutation") => "mutation",
        Some(kw) if kw.eq_ignore_ascii_case("subscription") => "subscription",
        _ => "query",
    }
    .to_owned();

    // The next token, if present and not `{`, is the operation name.
    let parsed_name = tokens
        .next()
        .filter(|t| !t.starts_with('{') && !t.starts_with('('))
        .map(|t| {
            // Strip variable list `(` if joined: `GetUser(`
            t.split('(').next().unwrap_or(t).to_owned()
        });

    let op_name = envelope_name.or(parsed_name);
    (op_name, op_type)
}
