use std::collections::HashSet;
use std::fmt::Write as _;

use async_trait::async_trait;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::check::{
    Check, CheckContext, CheckError, CheckReport, Finding, MAX_HTML_BODY_BYTES,
    MAX_TEXT_BODY_BYTES, is_same_origin, read_body_limited, validate_http_url,
};
use crate::checks::http::extract_sitemap_locs;
use crate::config::Config;

/// Default `IndexNow` submission API endpoint.
pub const DEFAULT_INDEXNOW_ENDPOINT: &str = "https://api.indexnow.org/indexnow";

/// Maximum number of URLs permitted in a single `IndexNow` batch submission.
pub const MAX_INDEXNOW_URLS: usize = 10_000;

fn default_endpoint() -> String {
    DEFAULT_INDEXNOW_ENDPOINT.to_owned()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexNowConfig {
    pub key: String,
    #[serde(default)]
    pub key_location: Option<String>,
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IndexNowPayload {
    pub host: String,
    pub key: String,
    #[serde(rename = "keyLocation")]
    pub key_location: String,
    #[serde(rename = "urlList")]
    pub url_list: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IndexNowSubmitResult {
    pub host: String,
    pub endpoint: String,
    pub key_location: String,
    pub submitted_count: usize,
    pub urls: Vec<String>,
    pub dry_run: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
}

pub struct IndexNowCheck {
    config: IndexNowConfig,
}

impl IndexNowCheck {
    #[must_use]
    pub const fn new(config: IndexNowConfig) -> Self {
        Self { config }
    }
}

fn resolve_key_location(
    base_url: &Url,
    config: &IndexNowConfig,
) -> Result<(String, Url), CheckError> {
    let key = config.key.trim();
    if key.is_empty() {
        return Err(CheckError::Config(
            "configured `indexnow.key` is empty".to_owned(),
        ));
    }

    let key_url = match config.key_location.as_deref().map(str::trim) {
        Some(loc) if !loc.is_empty() => base_url.join(loc)?,
        _ => base_url.join(&format!("/{key}.txt"))?,
    };
    validate_http_url(&key_url)?;
    Ok((key.to_owned(), key_url))
}

/// Filters candidate URLs to unique, same-origin URLs relative to `base_url`, capped at `max_urls`.
#[must_use]
pub fn filter_same_origin_urls(
    base_url: &Url,
    candidates: &[String],
    max_urls: usize,
) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut filtered = Vec::new();

    for raw in candidates {
        if filtered.len() >= max_urls {
            break;
        }
        let Ok(parsed) = Url::parse(raw.trim()) else {
            continue;
        };
        if !is_same_origin(base_url, &parsed) {
            continue;
        }
        let normalized = parsed.to_string();
        if seen.insert(normalized.clone()) {
            filtered.push(normalized);
        }
    }

    filtered
}

async fn verify_key_file(
    client: &reqwest::Client,
    key_url: &Url,
    key: &str,
) -> Result<(), CheckError> {
    let resp = client.get(key_url.clone()).send().await?;
    let status = resp.status();
    if status != StatusCode::OK {
        return Err(CheckError::Other(format!(
            "IndexNow key file at {key_url} returned HTTP {status} (expected 200)"
        )));
    }
    let body = read_body_limited(resp, MAX_TEXT_BODY_BYTES).await?;
    if body.trim() != key {
        return Err(CheckError::Other(format!(
            "IndexNow key file at {key_url} does not match configured key"
        )));
    }
    Ok(())
}

async fn fetch_sitemap_urls(ctx: &CheckContext) -> Result<Vec<String>, CheckError> {
    let sitemap_url = ctx.base_url.join("/sitemap.xml")?;
    let resp = ctx
        .same_origin_client
        .get(sitemap_url.clone())
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        return Err(CheckError::Other(format!(
            "failed to fetch {sitemap_url}: HTTP {status}"
        )));
    }
    let xml = read_body_limited(resp, MAX_HTML_BODY_BYTES).await?;
    let locs = extract_sitemap_locs(&xml);
    Ok(filter_same_origin_urls(
        &ctx.base_url,
        &locs,
        MAX_INDEXNOW_URLS,
    ))
}

/// Submits site URLs to `IndexNow` (or returns the planned submission when `dry_run` is true).
pub async fn submit_indexnow(
    config: &Config,
    explicit_urls: &[Url],
    dry_run: bool,
) -> Result<IndexNowSubmitResult, CheckError> {
    let indexnow_cfg = config.indexnow.as_ref().ok_or_else(|| {
        CheckError::Config("missing `[indexnow]` section in sitecheck.toml".to_owned())
    })?;

    let ctx = CheckContext::new(config.url.clone())?;
    let (key, key_url) = resolve_key_location(&ctx.base_url, indexnow_cfg)?;

    let endpoint_str = indexnow_cfg.endpoint.trim();
    let endpoint_url = Url::parse(endpoint_str).map_err(|err| {
        CheckError::Config(format!(
            "invalid `indexnow.endpoint` URL `{endpoint_str}`: {err}"
        ))
    })?;
    validate_http_url(&endpoint_url)?;

    let host = ctx
        .base_url
        .host_str()
        .ok_or_else(|| CheckError::Config("site `url` must include a host".to_owned()))?
        .to_owned();

    let urls = if explicit_urls.is_empty() {
        let fetched = fetch_sitemap_urls(&ctx).await?;
        if fetched.is_empty() {
            return Err(CheckError::Other(format!(
                "no same-origin `<loc>` URLs found in {}sitemap.xml",
                ctx.base_url
            )));
        }
        fetched
    } else {
        let raw: Vec<String> = explicit_urls.iter().map(Url::to_string).collect();
        let filtered = filter_same_origin_urls(&ctx.base_url, &raw, MAX_INDEXNOW_URLS);
        if filtered.is_empty() {
            return Err(CheckError::Config(format!(
                "none of the provided `--url` values match site origin {}",
                ctx.base_url
            )));
        }
        filtered
    };

    let payload = IndexNowPayload {
        host: host.clone(),
        key: key.clone(),
        key_location: key_url.to_string(),
        url_list: urls.clone(),
    };

    if dry_run {
        return Ok(IndexNowSubmitResult {
            host,
            endpoint: endpoint_url.to_string(),
            key_location: payload.key_location,
            submitted_count: urls.len(),
            urls,
            dry_run: true,
            http_status: None,
        });
    }

    verify_key_file(&ctx.client, &key_url, &key).await?;

    let resp = ctx
        .client
        .post(endpoint_url.clone())
        .json(&payload)
        .send()
        .await?;
    let status = resp.status();
    if status != StatusCode::OK && status != StatusCode::ACCEPTED {
        let body = read_body_limited(resp, MAX_TEXT_BODY_BYTES)
            .await
            .unwrap_or_default();
        return Err(CheckError::Other(format!(
            "IndexNow submission to {endpoint_url} failed (HTTP {status}): {}",
            body.trim()
        )));
    }

    Ok(IndexNowSubmitResult {
        host,
        endpoint: endpoint_url.to_string(),
        key_location: payload.key_location,
        submitted_count: urls.len(),
        urls,
        dry_run: false,
        http_status: Some(status.as_u16()),
    })
}

/// Formats an [`IndexNowSubmitResult`] for terminal output.
#[must_use]
pub fn format_indexnow_text(result: &IndexNowSubmitResult) -> String {
    let mut out = String::new();
    if result.dry_run {
        let _ = writeln!(
            out,
            "IndexNow dry-run: would submit {} URL(s) for {} to {}",
            result.submitted_count, result.host, result.endpoint
        );
    } else {
        let status = result.http_status.unwrap_or(0);
        let _ = writeln!(
            out,
            "IndexNow submitted {} URL(s) for {} to {} (HTTP {status})",
            result.submitted_count, result.host, result.endpoint
        );
    }
    let _ = writeln!(out, "Key location: {}", result.key_location);
    for url in &result.urls {
        let _ = writeln!(out, "  - {url}");
    }
    out
}

#[async_trait]
impl Check for IndexNowCheck {
    fn name(&self) -> &'static str {
        "indexnow"
    }

    async fn run(&self, ctx: &CheckContext) -> Result<CheckReport, CheckError> {
        let (key, target_url) = match resolve_key_location(&ctx.base_url, &self.config) {
            Ok(resolved) => resolved,
            Err(CheckError::Config(msg)) => {
                return Ok(CheckReport::new(
                    self.name(),
                    vec![
                        Finding::fail("IndexNow key file", Some(msg))
                            .with_rule("indexnow/key-file"),
                    ],
                ));
            }
            Err(err) => return Err(err),
        };

        let resp = match ctx.client.get(target_url.clone()).send().await {
            Ok(resp) => resp,
            Err(err) => {
                return Ok(CheckReport::new(
                    self.name(),
                    vec![
                        Finding::fail(
                            "IndexNow key file",
                            Some(format!("request to {target_url} failed: {err}")),
                        )
                        .with_rule("indexnow/key-file"),
                    ],
                ));
            }
        };

        let status = resp.status();
        if status != StatusCode::OK {
            return Ok(CheckReport::new(
                self.name(),
                vec![
                    Finding::fail(
                        "IndexNow key file",
                        Some(format!("HTTP {status} at {target_url} (expected 200)")),
                    )
                    .with_rule("indexnow/key-file"),
                ],
            ));
        }

        let body = match read_body_limited(resp, MAX_TEXT_BODY_BYTES).await {
            Ok(body) => body,
            Err(err) => {
                return Ok(CheckReport::new(
                    self.name(),
                    vec![
                        Finding::fail(
                            "IndexNow key file",
                            Some(format!("failed to read {target_url}: {err}")),
                        )
                        .with_rule("indexnow/key-file"),
                    ],
                ));
            }
        };
        let finding = if body.trim() == key {
            Finding::pass(
                "IndexNow key file",
                Some(format!("HTTP 200 at {target_url} matches configured key")),
            )
            .with_rule("indexnow/key-file")
        } else {
            Finding::fail(
                "IndexNow key file",
                Some(format!(
                    "body at {target_url} does not match configured IndexNow key"
                )),
            )
            .with_rule("indexnow/key-file")
        };

        Ok(CheckReport::new(self.name(), vec![finding]))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use url::Url;

    use super::{
        DEFAULT_INDEXNOW_ENDPOINT, IndexNowPayload, filter_same_origin_urls, submit_indexnow,
    };
    use crate::config::Config;

    #[test]
    fn serializes_indexnow_payload_with_spec_field_names() {
        let payload = IndexNowPayload {
            host: "example.com".to_owned(),
            key: "abc12345".to_owned(),
            key_location: "https://example.com/abc12345.txt".to_owned(),
            url_list: vec![
                "https://example.com/".to_owned(),
                "https://example.com/docs".to_owned(),
            ],
        };

        let value: Value = serde_json::to_value(&payload).expect("payload should serialize");
        assert_eq!(value["host"], "example.com");
        assert_eq!(value["key"], "abc12345");
        assert_eq!(value["keyLocation"], "https://example.com/abc12345.txt");
        assert_eq!(
            value["urlList"],
            serde_json::json!(["https://example.com/", "https://example.com/docs"])
        );
    }

    #[test]
    fn filters_same_origin_deduplicates_and_caps_urls() {
        let base = Url::parse("https://example.com/").expect("valid base url");
        let candidates = vec![
            "https://example.com/".to_owned(),
            "https://example.com/about".to_owned(),
            "https://example.com/about".to_owned(),
            "https://other.example.net/page".to_owned(),
            "http://example.com/insecure".to_owned(),
            "not-a-url".to_owned(),
            "https://example.com/blog".to_owned(),
        ];

        let filtered = filter_same_origin_urls(&base, &candidates, 2);
        assert_eq!(
            filtered,
            vec![
                "https://example.com/".to_owned(),
                "https://example.com/about".to_owned(),
            ]
        );
    }

    #[tokio::test]
    async fn dry_run_returns_planned_submission_without_network() {
        let cfg = Config::parse(
            r#"
url = "https://example.com/"

[indexnow]
key = "deadbeef1234"
"#,
        )
        .expect("valid config");

        let explicit = vec![
            Url::parse("https://example.com/").expect("valid url"),
            Url::parse("https://example.com/pricing").expect("valid url"),
            Url::parse("https://other.example.net/ignored").expect("valid url"),
        ];

        let result = submit_indexnow(&cfg, &explicit, true)
            .await
            .expect("dry-run should succeed without network");
        assert!(result.dry_run);
        assert_eq!(result.http_status, None);
        assert_eq!(result.host, "example.com");
        assert_eq!(result.endpoint, DEFAULT_INDEXNOW_ENDPOINT);
        assert_eq!(result.key_location, "https://example.com/deadbeef1234.txt");
        assert_eq!(result.submitted_count, 2);
        assert_eq!(
            result.urls,
            vec![
                "https://example.com/".to_owned(),
                "https://example.com/pricing".to_owned(),
            ]
        );
    }
}
