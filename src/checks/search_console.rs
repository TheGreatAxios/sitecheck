use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::{Url, form_urlencoded};

use crate::check::{
    Check, CheckContext, CheckError, CheckReport, Finding, MAX_HTML_BODY_BYTES,
    MAX_TEXT_BODY_BYTES, read_body_limited,
};
use crate::checks::http::extract_sitemap_lastmods;
use crate::checks::security_headers::parse_rfc3339_unix;

const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
const WEBMASTERS_SCOPE: &str = "https://www.googleapis.com/auth/webmasters.readonly";
const SITEMAPS_BASE: &str = "https://www.googleapis.com/webmasters/v3/sites";
const URL_INSPECTION_ENDPOINT: &str =
    "https://searchconsole.googleapis.com/v1/urlInspection/index:inspect";

fn default_service_account_env() -> String {
    "GOOGLE_APPLICATION_CREDENTIALS".to_owned()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchConsoleConfig {
    pub site_url: Option<String>,
    #[serde(default = "default_service_account_env")]
    pub service_account_env: String,
    #[serde(default)]
    pub inspect_urls: Vec<String>,
}

pub struct SearchConsoleCheck {
    config: SearchConsoleConfig,
}

impl SearchConsoleCheck {
    #[must_use]
    pub const fn new(config: SearchConsoleConfig) -> Self {
        Self { config }
    }
}

#[derive(Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    token_uri: Option<String>,
}

#[derive(Debug, Serialize)]
struct JwtClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

fn load_service_account(env_name: &str) -> Result<ServiceAccountKey, CheckError> {
    let raw = env::var(env_name).map_err(|_| {
        CheckError::Config(format!(
            "Search Console requires `{env_name}` to point to a service account JSON file or contain inline JSON"
        ))
    })?;
    let trimmed = raw.trim();
    let json_text = if trimmed.starts_with('{') {
        trimmed.to_owned()
    } else {
        fs::read_to_string(trimmed).map_err(|err| {
            CheckError::Config(format!(
                "failed to read service account file from `{env_name}`: {err}"
            ))
        })?
    };

    serde_json::from_str(&json_text).map_err(|err| {
        CheckError::Config(format!(
            "invalid Google service account JSON in `{env_name}`: {err}"
        ))
    })
}

fn validate_token_uri(uri: &str) -> Result<(), CheckError> {
    let trimmed = uri.trim();
    match Url::parse(trimmed) {
        Ok(parsed) if parsed.scheme() == "https" && parsed.host_str().is_some() => Ok(()),
        _ => Err(CheckError::Config(format!(
            "service account `token_uri` must be a valid `https://` URL (got `{trimmed}`)"
        ))),
    }
}

async fn exchange_jwt_for_token(
    client: &reqwest::Client,
    sa: &ServiceAccountKey,
) -> Result<String, CheckError> {
    let token_uri = sa.token_uri.as_deref().map_or(DEFAULT_TOKEN_URI, str::trim);
    validate_token_uri(token_uri)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| CheckError::Other(format!("system clock error: {err}")))?
        .as_secs();

    let claims = JwtClaims {
        iss: &sa.client_email,
        scope: WEBMASTERS_SCOPE,
        aud: token_uri,
        iat: now,
        exp: now + 3600,
    };

    let key = EncodingKey::from_rsa_pem(sa.private_key.as_bytes()).map_err(|err| {
        CheckError::Config(format!("invalid RSA private key in service account: {err}"))
    })?;

    let assertion = encode(&Header::new(Algorithm::RS256), &claims, &key)
        .map_err(|err| CheckError::Other(format!("failed to sign RS256 JWT: {err}")))?;

    let resp = client
        .post(token_uri)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
        ])
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let body = read_body_limited(resp, MAX_TEXT_BODY_BYTES)
            .await
            .unwrap_or_default();
        return Err(CheckError::Other(format!(
            "Google OAuth2 token exchange failed (HTTP {status}): {body}"
        )));
    }

    let body = read_body_limited(resp, MAX_TEXT_BODY_BYTES).await?;
    let token: TokenResponse = serde_json::from_str(&body)?;
    Ok(token.access_token)
}

async fn check_sitemaps(
    client: &reqwest::Client,
    access_token: &str,
    site_url: &str,
) -> Result<Vec<Finding>, CheckError> {
    let encoded_site: String = form_urlencoded::byte_serialize(site_url.as_bytes()).collect();
    let endpoint = format!("{SITEMAPS_BASE}/{encoded_site}/sitemaps");

    let resp = client
        .get(&endpoint)
        .bearer_auth(access_token)
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        let body = read_body_limited(resp, MAX_TEXT_BODY_BYTES)
            .await
            .unwrap_or_default();
        return Err(CheckError::Other(format!(
            "GSC sitemaps API returned HTTP {status}: {body}"
        )));
    }

    let body = read_body_limited(resp, MAX_HTML_BODY_BYTES).await?;
    let payload: Value = serde_json::from_str(&body)?;
    let sitemaps = payload
        .get("sitemap")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);

    if sitemaps.is_empty() {
        return Ok(vec![
            Finding::fail(
                "GSC sitemaps",
                Some(format!("no sitemaps submitted for {site_url}")),
            )
            .with_rule("gsc/sitemap"),
        ]);
    }

    let mut findings = Vec::new();
    for sm in sitemaps {
        let path = sm
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>");
        let errors = sm
            .get("errors")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u64>().ok())
            .or_else(|| sm.get("errors").and_then(Value::as_u64))
            .unwrap_or(0);
        let warnings = sm
            .get("warnings")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u64>().ok())
            .or_else(|| sm.get("warnings").and_then(Value::as_u64))
            .unwrap_or(0);

        if errors > 0 {
            findings.push(
                Finding::fail(
                    format!("GSC sitemap {path}"),
                    Some(format!("{errors} error(s), {warnings} warning(s)")),
                )
                .with_rule("gsc/sitemap"),
            );
        } else if warnings > 0 {
            findings.push(
                Finding::warn(
                    format!("GSC sitemap {path}"),
                    Some(format!("{warnings} warning(s)")),
                )
                .with_rule("gsc/sitemap"),
            );
        } else {
            findings.push(
                Finding::pass(
                    format!("GSC sitemap {path}"),
                    Some("0 errors, 0 warnings".to_owned()),
                )
                .with_rule("gsc/sitemap"),
            );
        }
    }

    Ok(findings)
}

struct UrlInspectionOutcome {
    indexed: bool,
    last_crawl_time: Option<String>,
}

fn parse_timestamp_unix(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    if trimmed.len() == 10 {
        parse_rfc3339_unix(&format!("{trimmed}T00:00:00Z"))
    } else {
        parse_rfc3339_unix(trimmed)
    }
}

async fn fetch_sitemap_lastmods(ctx: &CheckContext) -> BTreeMap<String, String> {
    let Ok(sitemap_url) = ctx.base_url.join("/sitemap.xml") else {
        return BTreeMap::new();
    };
    let Ok(resp) = ctx.same_origin_client.get(sitemap_url).send().await else {
        return BTreeMap::new();
    };
    if !resp.status().is_success() {
        return BTreeMap::new();
    }
    let Ok(xml) = read_body_limited(resp, MAX_HTML_BODY_BYTES).await else {
        return BTreeMap::new();
    };
    extract_sitemap_lastmods(&xml)
}

#[allow(clippy::cast_precision_loss)]
fn summarize_indexing_metrics(
    outcomes: &[(String, UrlInspectionOutcome)],
    sitemap_lastmods: &BTreeMap<String, String>,
) -> Vec<Finding> {
    if outcomes.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let inspected = outcomes.len();
    let indexed = outcomes.iter().filter(|(_, o)| o.indexed).count();
    let coverage_pct = (indexed as f64 / inspected as f64) * 100.0;
    let coverage_detail =
        format!("{indexed}/{inspected} inspected URLs indexed ({coverage_pct:.1}%)");
    let coverage_finding = if indexed == inspected {
        Finding::pass("GSC indexing coverage", Some(coverage_detail))
    } else if indexed > 0 {
        Finding::warn("GSC indexing coverage", Some(coverage_detail))
    } else {
        Finding::fail("GSC indexing coverage", Some(coverage_detail))
    }
    .with_rule("gsc/coverage");
    findings.push(coverage_finding);

    let mut lag_sum_days = 0.0_f64;
    let mut max_lag_days = 0.0_f64;
    let mut lag_samples = 0usize;
    let mut stale_count = 0usize;

    for (url, outcome) in outcomes {
        let Some(last_crawl) = outcome.last_crawl_time.as_deref() else {
            continue;
        };
        let lastmod = sitemap_lastmods.get(url).or_else(|| {
            Url::parse(url)
                .ok()
                .and_then(|parsed| sitemap_lastmods.get(parsed.as_str()))
        });
        let Some(lastmod) = lastmod else {
            continue;
        };
        let (Some(crawl_ts), Some(lastmod_ts)) = (
            parse_timestamp_unix(last_crawl),
            parse_timestamp_unix(lastmod),
        ) else {
            continue;
        };

        let diff_secs = crawl_ts - lastmod_ts;
        if diff_secs < 0 {
            stale_count += 1;
        }
        let lag_days = diff_secs.unsigned_abs() as f64 / 86_400.0;
        lag_sum_days += lag_days;
        if lag_days > max_lag_days {
            max_lag_days = lag_days;
        }
        lag_samples += 1;
    }

    if lag_samples > 0 {
        let avg_lag_days = lag_sum_days / lag_samples as f64;
        let lag_finding = if stale_count > 0 {
            Finding::warn(
                "GSC crawl lag",
                Some(format!(
                    "avg {avg_lag_days:.1}d, max {max_lag_days:.1}d across {lag_samples} URL(s) ({stale_count} pending recrawl since lastmod)"
                )),
            )
        } else {
            Finding::pass(
                "GSC crawl lag",
                Some(format!(
                    "avg {avg_lag_days:.1}d, max {max_lag_days:.1}d across {lag_samples} URL(s)"
                )),
            )
        }
        .with_rule("gsc/crawl-lag");
        findings.push(lag_finding);
    }

    findings
}

async fn inspect_url(
    client: &reqwest::Client,
    access_token: &str,
    site_url: &str,
    inspection_url: &str,
) -> Result<(Vec<Finding>, UrlInspectionOutcome), CheckError> {
    let resp = client
        .post(URL_INSPECTION_ENDPOINT)
        .bearer_auth(access_token)
        .json(&json!({
            "inspectionUrl": inspection_url,
            "siteUrl": site_url,
        }))
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let body = read_body_limited(resp, MAX_TEXT_BODY_BYTES)
            .await
            .unwrap_or_default();
        return Err(CheckError::Other(format!(
            "GSC URL Inspection API returned HTTP {status} for {inspection_url}: {body}"
        )));
    }

    let body = read_body_limited(resp, MAX_HTML_BODY_BYTES).await?;
    let payload: Value = serde_json::from_str(&body)?;
    let index_status = payload
        .get("inspectionResult")
        .and_then(|r| r.get("indexStatusResult"));

    let Some(index_status) = index_status else {
        return Ok((
            vec![
                Finding::warn(
                    format!("GSC inspect {inspection_url}"),
                    Some("response missing `indexStatusResult`".to_owned()),
                )
                .with_rule("gsc/index"),
            ],
            UrlInspectionOutcome {
                indexed: false,
                last_crawl_time: None,
            },
        ));
    };

    let verdict = index_status
        .get("verdict")
        .and_then(Value::as_str)
        .unwrap_or("VERDICT_UNSPECIFIED");
    let coverage = index_status
        .get("coverageState")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let last_crawl_time = index_status
        .get("lastCrawlTime")
        .and_then(Value::as_str)
        .map(str::to_owned);

    let mut findings = Vec::new();
    let coverage_finding = match verdict {
        "PASS" => Finding::pass(
            format!("GSC coverage {inspection_url}"),
            Some(coverage.to_owned()),
        ),
        "PARTIAL" | "NEUTRAL" => Finding::warn(
            format!("GSC coverage {inspection_url}"),
            Some(format!("{verdict}: {coverage}")),
        ),
        _ => Finding::fail(
            format!("GSC coverage {inspection_url}"),
            Some(format!("{verdict}: {coverage}")),
        ),
    }
    .with_rule("gsc/index");
    findings.push(coverage_finding);

    let google_canonical = index_status.get("googleCanonical").and_then(Value::as_str);
    let user_canonical = index_status.get("userCanonical").and_then(Value::as_str);

    if let (Some(g_can), Some(u_can)) = (google_canonical, user_canonical) {
        if g_can == u_can {
            findings.push(
                Finding::pass(
                    format!("GSC canonical {inspection_url}"),
                    Some(format!("Google matches user canonical ({g_can})")),
                )
                .with_rule("gsc/canonical"),
            );
        } else {
            findings.push(
                Finding::fail(
                    format!("GSC canonical {inspection_url}"),
                    Some(format!(
                        "Google selected `{g_can}`, user declared `{u_can}`"
                    )),
                )
                .with_rule("gsc/canonical"),
            );
        }
    }

    Ok((
        findings,
        UrlInspectionOutcome {
            indexed: verdict == "PASS",
            last_crawl_time,
        },
    ))
}

#[async_trait]
impl Check for SearchConsoleCheck {
    fn name(&self) -> &'static str {
        "search_console"
    }

    async fn run(&self, ctx: &CheckContext) -> Result<CheckReport, CheckError> {
        let sa = load_service_account(&self.config.service_account_env)?;
        let token = exchange_jwt_for_token(&ctx.client, &sa).await?;

        let site_url = self
            .config
            .site_url
            .as_deref()
            .unwrap_or(ctx.base_url.as_str());

        let mut findings = check_sitemaps(&ctx.client, &token, site_url).await?;
        let sitemap_lastmods = fetch_sitemap_lastmods(ctx).await;

        let urls_to_inspect: Vec<String> = if self.config.inspect_urls.is_empty() {
            vec![ctx.base_url.to_string()]
        } else {
            self.config.inspect_urls.clone()
        };

        let mut outcomes = Vec::with_capacity(urls_to_inspect.len());
        for url in &urls_to_inspect {
            let (url_findings, outcome) = inspect_url(&ctx.client, &token, site_url, url).await?;
            findings.extend(url_findings);
            outcomes.push((url.clone(), outcome));
        }

        findings.extend(summarize_indexing_metrics(&outcomes, &sitemap_lastmods));

        Ok(CheckReport::new(self.name(), findings))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{UrlInspectionOutcome, summarize_indexing_metrics, validate_token_uri};
    use crate::check::Severity;
    use crate::checks::http::extract_sitemap_lastmods;

    #[test]
    fn requires_https_token_uri() {
        assert!(validate_token_uri("https://oauth2.googleapis.com/token").is_ok());
        assert!(validate_token_uri("http://oauth2.googleapis.com/token").is_err());
        assert!(validate_token_uri("http://169.254.169.254/token").is_err());
        assert!(validate_token_uri("not-a-url").is_err());
    }

    #[test]
    fn summarizes_indexing_coverage_and_crawl_lag() {
        let outcomes = vec![
            (
                "https://example.com/".to_owned(),
                UrlInspectionOutcome {
                    indexed: true,
                    last_crawl_time: Some("2026-03-04T00:00:00Z".to_owned()),
                },
            ),
            (
                "https://example.com/about".to_owned(),
                UrlInspectionOutcome {
                    indexed: false,
                    last_crawl_time: Some("2026-03-01T00:00:00Z".to_owned()),
                },
            ),
        ];
        let lastmods = BTreeMap::from([
            ("https://example.com/".to_owned(), "2026-03-01".to_owned()),
            (
                "https://example.com/about".to_owned(),
                "2026-03-02T00:00:00Z".to_owned(),
            ),
        ]);

        let findings = summarize_indexing_metrics(&outcomes, &lastmods);
        assert_eq!(findings.len(), 2);

        assert_eq!(findings[0].rule.as_deref(), Some("gsc/coverage"));
        assert_eq!(findings[0].severity, Severity::Warn);
        assert_eq!(
            findings[0].detail.as_deref(),
            Some("1/2 inspected URLs indexed (50.0%)")
        );

        assert_eq!(findings[1].rule.as_deref(), Some("gsc/crawl-lag"));
        assert_eq!(findings[1].severity, Severity::Warn);
        assert_eq!(
            findings[1].detail.as_deref(),
            Some("avg 2.0d, max 3.0d across 2 URL(s) (1 pending recrawl since lastmod)")
        );
    }

    #[test]
    fn extracts_sitemap_lastmods_for_crawl_lag() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://example.com/</loc>
    <lastmod>2026-03-01</lastmod>
  </url>
  <url>
    <loc>https://example.com/docs</loc>
  </url>
</urlset>"#;

        let map = extract_sitemap_lastmods(xml);
        assert_eq!(map.len(), 1);
        assert_eq!(
            map.get("https://example.com/").map(String::as_str),
            Some("2026-03-01")
        );
    }
}
