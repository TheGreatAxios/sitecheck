use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::form_urlencoded;

use crate::check::{Check, CheckContext, CheckError, CheckReport, Finding};

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
                "failed to read service account file `{trimmed}` from `{env_name}`: {err}"
            ))
        })?
    };

    serde_json::from_str(&json_text).map_err(|err| {
        CheckError::Config(format!(
            "invalid Google service account JSON in `{env_name}`: {err}"
        ))
    })
}

async fn exchange_jwt_for_token(
    client: &reqwest::Client,
    sa: &ServiceAccountKey,
) -> Result<String, CheckError> {
    let token_uri = sa.token_uri.as_deref().unwrap_or(DEFAULT_TOKEN_URI);
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
        let body = resp.text().await.unwrap_or_default();
        return Err(CheckError::Other(format!(
            "Google OAuth2 token exchange failed (HTTP {status}): {body}"
        )));
    }

    let token: TokenResponse = resp.json().await?;
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
        let body = resp.text().await.unwrap_or_default();
        return Err(CheckError::Other(format!(
            "GSC sitemaps API returned HTTP {status}: {body}"
        )));
    }

    let payload: Value = resp.json().await?;
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

async fn inspect_url(
    client: &reqwest::Client,
    access_token: &str,
    site_url: &str,
    inspection_url: &str,
) -> Result<Vec<Finding>, CheckError> {
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
        let body = resp.text().await.unwrap_or_default();
        return Err(CheckError::Other(format!(
            "GSC URL Inspection API returned HTTP {status} for {inspection_url}: {body}"
        )));
    }

    let payload: Value = resp.json().await?;
    let index_status = payload
        .get("inspectionResult")
        .and_then(|r| r.get("indexStatusResult"));

    let Some(index_status) = index_status else {
        return Ok(vec![
            Finding::warn(
                format!("GSC inspect {inspection_url}"),
                Some("response missing `indexStatusResult`".to_owned()),
            )
            .with_rule("gsc/index"),
        ]);
    };

    let verdict = index_status
        .get("verdict")
        .and_then(Value::as_str)
        .unwrap_or("VERDICT_UNSPECIFIED");
    let coverage = index_status
        .get("coverageState")
        .and_then(Value::as_str)
        .unwrap_or("unknown");

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

    Ok(findings)
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

        let urls_to_inspect: Vec<String> = if self.config.inspect_urls.is_empty() {
            vec![ctx.base_url.to_string()]
        } else {
            self.config.inspect_urls.clone()
        };

        for url in &urls_to_inspect {
            findings.extend(inspect_url(&ctx.client, &token, site_url, url).await?);
        }

        Ok(CheckReport::new(self.name(), findings))
    }
}
