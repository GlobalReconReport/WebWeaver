//! Redaction engine.
//!
//! Applies a layered set of redaction rules to any text before it is written
//! into a report, ensuring that live credentials, PII, and other sensitive data
//! are stripped or masked.
//!
//! Built-in rules (applied in order):
//! 1. Authorization header values -- keep first 8 chars, append "...REDACTED"
//! 2. Cookie header values -- preserve cookie name, replace value with [REDACTED]
//! 3. Email addresses -- keep first 2 chars, replace rest with ***@***.com
//! 4. Phone numbers -- keep last 4 digits, mask the rest
//! 5. SSN patterns -- fully replaced with [REDACTED-SSN]
//! 6. Card numbers -- fully replaced with [REDACTED-CARD]
//! 7. Custom patterns from an optional redact.toml file
//!
//! redact.toml format:
//! ```toml
//! [[custom_patterns]]
//! name        = "api_key"
//! regex       = "api_key=[A-Za-z0-9_-]+"
//! replacement = "api_key=[REDACTED]"
//! ```

use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;
use std::path::Path;

// ── Static built-in patterns ──────────────────────────────────────────────────

/// Matches `Authorization: <scheme> <token>` in text (header lines or JSON values).
static AUTH_HEADER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(authorization:\s*\S+\s+)(\S{8})(\S+)").unwrap()
});

/// Matches a JSON "Authorization" key with a Bearer (or other) token value.
static AUTH_JSON_RE: Lazy<Regex> = Lazy::new(|| {
    // r#"..."# needed because the pattern contains literal double-quote characters.
    Regex::new(r#"(?i)("(?:authorization|x-auth-token)"\s*:\s*"[^"]{0,16})([^"]{8,})"#).unwrap()
});

/// Matches individual `name=value` cookie pairs.  `{1,}` (not `{4,}`) so that
/// even single-char values like `id=1` are redacted.
/// r#"..."# needed to contain a literal `"` character inside the character class.
static COOKIE_PAIR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"([A-Za-z0-9_.\-]+)=([^;,\s"]+)"#).unwrap()
});

static EMAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([a-zA-Z0-9_.+\-]{2})[a-zA-Z0-9_.+\-]*@[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}").unwrap()
});

static PHONE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?(\d{4})\b").unwrap()
});

static SSN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\d{3}[\-\s]?\d{2}[\-\s]?\d{4}\b").unwrap()
});

static CARD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    )
    .unwrap()
});

// ── TOML config types ─────────────────────────────────────────────────────────

/// Root of a `redact.toml` configuration file.
#[derive(Debug, Deserialize, Default)]
pub struct RedactConfig {
    #[serde(default)]
    pub custom_patterns: Vec<CustomPattern>,
}

/// A single custom redaction rule loaded from TOML.
#[derive(Debug, Deserialize)]
pub struct CustomPattern {
    pub name:        String,
    pub regex:       String,
    pub replacement: String,
}

impl RedactConfig {
    /// Load from a TOML file; returns a default (empty) config on error and
    /// logs a warning to stderr.
    pub fn from_file(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(s) => toml::from_str(&s).unwrap_or_else(|e| {
                eprintln!("[redact] invalid TOML in {}: {e}", path.display());
                Self::default()
            }),
            Err(e) => {
                eprintln!("[redact] cannot read {}: {e}", path.display());
                Self::default()
            }
        }
    }
}

// ── Engine ────────────────────────────────────────────────────────────────────

/// Compiled redaction engine.  Create once, call [`RedactEngine::redact`] many
/// times.
pub struct RedactEngine {
    custom: Vec<(Regex, String)>,
}

impl RedactEngine {
    /// Build a `RedactEngine` from a [`RedactConfig`].
    pub fn new(config: &RedactConfig) -> anyhow::Result<Self> {
        let mut custom = Vec::with_capacity(config.custom_patterns.len());
        for p in &config.custom_patterns {
            let re = Regex::new(&p.regex)
                .map_err(|e| anyhow::anyhow!("Invalid redact pattern '{}': {e}", p.name))?;
            custom.push((re, p.replacement.clone()));
        }
        Ok(Self { custom })
    }

    /// Build with no custom patterns (useful when no config file is provided).
    pub fn default_rules() -> Self {
        Self { custom: Vec::new() }
    }

    // ── Public methods ────────────────────────────────────────────────────────

    /// Redact all sensitive patterns in an arbitrary text string.
    pub fn redact(&self, text: &str) -> String {
        let s = self.redact_pii(text);
        self.redact_custom(&s)
    }

    /// Redact a `headers_json` blob, masking auth and cookie values.
    /// Returns the JSON with sensitive values replaced.
    pub fn redact_headers_json(&self, json: &str) -> String {
        let Ok(mut map) =
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(json)
        else {
            return json.to_owned();
        };
        for (k, v) in map.iter_mut() {
            let kl = k.to_lowercase();
            if kl == "authorization" {
                if let Some(s) = v.as_str() {
                    *v = serde_json::Value::String(redact_auth_value(s));
                }
            } else if kl == "cookie" || kl == "set-cookie" {
                if let Some(s) = v.as_str() {
                    *v = serde_json::Value::String(redact_cookie_string(s));
                }
            } else if kl.contains("token") || kl.contains("csrf") || kl.contains("xsrf") {
                if let Some(s) = v.as_str() {
                    *v = serde_json::Value::String(redact_auth_value(s));
                }
            }
        }
        serde_json::to_string_pretty(&map).unwrap_or_else(|_| json.to_owned())
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn redact_pii(&self, text: &str) -> String {
        // Auth header lines  (e.g. "Authorization: Bearer eyJ...")
        let s = AUTH_HEADER_RE.replace_all(text, |caps: &regex::Captures<'_>| {
            format!("{}{}...REDACTED", &caps[1], &caps[2])
        });
        // Auth in JSON  ("authorization": "Bearer eyJ...")
        // The pattern does NOT consume the closing `"`, so we must NOT add one
        // in the replacement — the original closing quote remains in the string.
        let s = AUTH_JSON_RE.replace_all(&s, |caps: &regex::Captures<'_>| {
            format!("{}...REDACTED", &caps[1])
        });
        // SSN (before phone to avoid partial matches)
        let s = SSN_RE.replace_all(&s, "[REDACTED-SSN]");
        // Card numbers
        let s = CARD_RE.replace_all(&s, "[REDACTED-CARD]");
        // Emails -- keep first 2 chars of local part
        let s = EMAIL_RE.replace_all(&s, |caps: &regex::Captures<'_>| {
            format!("{}***@***.com", &caps[1])
        });
        // Phones -- keep last 4 digits
        let s = PHONE_RE.replace_all(&s, |caps: &regex::Captures<'_>| {
            format!("***-***-{}", &caps[1])
        });
        s.into_owned()
    }

    fn redact_custom(&self, text: &str) -> String {
        let mut s = text.to_owned();
        for (re, replacement) in &self.custom {
            s = re.replace_all(&s, replacement.as_str()).into_owned();
        }
        s
    }
}

// ── Standalone helpers (also used by generator for curl commands) ─────────────

/// Redact an Authorization header value: keep scheme + first 8 chars of the
/// credential, then append `...REDACTED`.
///
/// Uses [`char_boundary_split`] to avoid a panic when the 8-byte offset falls
/// inside a multi-byte UTF-8 character (uncommon for auth tokens, but possible).
pub fn redact_auth_value(value: &str) -> String {
    let mut parts = value.splitn(2, ' ');
    let scheme = parts.next().unwrap_or("");
    let token  = parts.next().unwrap_or("");
    if token.len() > 8 {
        let head = char_boundary_split(token, 8);
        format!("{scheme} {head}...REDACTED")
    } else if !token.is_empty() {
        format!("{scheme} [REDACTED]")
    } else if value.len() > 8 {
        let head = char_boundary_split(value, 8);
        format!("{head}...REDACTED")
    } else {
        "[REDACTED]".to_owned()
    }
}

/// Return the first `n` bytes of `s`, walking back to the nearest char boundary
/// if byte `n` falls inside a multi-byte character.
fn char_boundary_split(s: &str, n: usize) -> &str {
    let n = n.min(s.len());
    // Walk backwards from `n` until we land on a char boundary.
    let end = (0..=n).rev().find(|&i| s.is_char_boundary(i)).unwrap_or(0);
    &s[..end]
}

/// Replace each cookie value in a `name=value; name2=value2` string with
/// `[REDACTED]`.
pub fn redact_cookie_string(s: &str) -> String {
    COOKIE_PAIR_RE
        .replace_all(s, |caps: &regex::Captures<'_>| format!("{}=[REDACTED]", &caps[1]))
        .into_owned()
}
