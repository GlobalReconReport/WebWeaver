use anyhow::Context;
use regex::Regex;
use serde::Deserialize;
use std::path::Path;

// ── Default built-in noise rules ──────────────────────────────────────────────

const DEFAULT_URL_REGEX: &[&str] = &[
    r"\.(js|jsx|mjs|ts|tsx)(\?.*)?$",
    r"\.(css|scss|less)(\?.*)?$",
    r"\.(png|jpg|jpeg|gif|svg|webp|ico)(\?.*)?$",
    r"\.(woff2?|ttf|eot|otf)(\?.*)?$",
    r"\.map(\?.*)?$",
    r"\.chunk\.[a-f0-9]+\.js",
    r"service[_-]worker\.js",
    r"sw\.js(\?.*)?$",
    r"workbox-[a-zA-Z0-9]+\.js",
    r"hot-update\.(js|json)",
];

const DEFAULT_URL_CONTAINS: &[&str] = &[
    "google-analytics.com",
    "googletagmanager.com",
    "analytics.google.com",
    "hotjar.com",
    "fullstory.com",
    "logrocket.com",
    "mixpanel.com",
    "segment.io",
    "cdn.segment.com",
    "amplitude.com",
    "heap.io",
    "clarity.ms",
    "sentry.io",
    "bugsnag.com",
    "nr-data.net",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "/csp-report",
    "/__csp-report",
    "/beacon",
    "/collect",
    "/ping",
    "/telemetry",
    "/healthz",
    "/health",
    "/ready",
    "/favicon",
    "/__webpack",
];

const DEFAULT_PATH_EXACT: &[&str] = &[
    "/favicon.ico",
    "/favicon.png",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.well-known/apple-app-site-association",
    "/.well-known/assetlinks.json",
];

// ── Config types (mirrors filter_rules.toml) ──────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct FilterConfig {
    #[serde(default)]
    pub noise: NoiseConfig,
}

#[derive(Debug, Deserialize)]
pub struct NoiseConfig {
    #[serde(default)]
    pub url_regex: Vec<String>,
    #[serde(default)]
    pub url_contains: Vec<String>,
    #[serde(default)]
    pub path_exact: Vec<String>,
    #[serde(default = "default_true")]
    pub skip_options: bool,
}

fn default_true() -> bool {
    true
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            noise: NoiseConfig {
                url_regex: DEFAULT_URL_REGEX.iter().map(|s| (*s).to_owned()).collect(),
                url_contains: DEFAULT_URL_CONTAINS
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect(),
                path_exact: DEFAULT_PATH_EXACT.iter().map(|s| (*s).to_owned()).collect(),
                skip_options: true,
            },
        }
    }
}

impl Default for NoiseConfig {
    fn default() -> Self {
        FilterConfig::default().noise
    }
}

// ── Normalizer ────────────────────────────────────────────────────────────────

pub struct Normalizer {
    config: FilterConfig,
    compiled: Vec<Regex>,
}

impl Normalizer {
    /// Load rules from a TOML file; falls back to built-in defaults if the file
    /// cannot be read or parsed.
    pub fn from_file_or_defaults<P: AsRef<Path>>(path: P) -> Self {
        Self::from_file(path).unwrap_or_else(|_| Self::with_defaults())
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let src =
            std::fs::read_to_string(path).context("Failed to read filter_rules.toml")?;
        let cfg: FilterConfig =
            toml::from_str(&src).context("Failed to parse filter_rules.toml")?;
        Self::from_config(cfg)
    }

    pub fn with_defaults() -> Self {
        Self::from_config(FilterConfig::default()).expect("built-in defaults must compile")
    }

    fn from_config(config: FilterConfig) -> anyhow::Result<Self> {
        let compiled = config
            .noise
            .url_regex
            .iter()
            .map(|pat| Regex::new(pat).with_context(|| format!("Bad regex: {pat}")))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self { config, compiled })
    }

    /// Returns `true` when the request should be **captured** (not noise-filtered).
    pub fn should_pass(&self, url: &str, method: &str) -> bool {
        // 1. Drop OPTIONS pre-flights
        if self.config.noise.skip_options && method.eq_ignore_ascii_case("OPTIONS") {
            return false;
        }

        // 2. Exact path match
        if let Ok(parsed) = url::Url::parse(url) {
            let path = parsed.path();
            if self.config.noise.path_exact.iter().any(|p| p == path) {
                return false;
            }
        }

        // 3. Substring match on full URL
        if self
            .config
            .noise
            .url_contains
            .iter()
            .any(|sub| url.contains(sub.as_str()))
        {
            return false;
        }

        // 4. Regex match on full URL
        if self.compiled.iter().any(|re| re.is_match(url)) {
            return false;
        }

        true
    }

    /// Returns `true` when the URL+method look like a GraphQL request, based on
    /// URL pattern alone (full detection is in `graphql::GraphqlDetector`).
    pub fn is_graphql_candidate(url: &str) -> bool {
        let lower = url.to_lowercase();
        lower.contains("/graphql")
            || lower.contains("/graph/")
            || lower.ends_with("/gql")
            || lower.contains("/query")
    }
}

// Safety: Regex is Send+Sync, all fields are Send+Sync.
unsafe impl Send for Normalizer {}
unsafe impl Sync for Normalizer {}
