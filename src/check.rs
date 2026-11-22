use std::time::Duration;

use async_trait::async_trait;
use reqwest::redirect::Policy;
use serde::Serialize;
use thiserror::Error;
use url::Url;

const USER_AGENT: &str = concat!("sitecheck/", env!("CARGO_PKG_VERSION"));
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Default response body cap for HTML documents, sitemaps, and manifests (10 MiB).
pub const MAX_HTML_BODY_BYTES: usize = 10 * 1024 * 1024;
/// Default response body cap for small text files such as `robots.txt` and `llms.txt` (2 MiB).
pub const MAX_TEXT_BODY_BYTES: usize = 2 * 1024 * 1024;

pub(crate) fn validate_http_url(url: &Url) -> Result<(), CheckError> {
    if matches!(url.scheme(), "http" | "https") {
        Ok(())
    } else {
        Err(CheckError::Config(format!(
            "unsupported URL scheme `{}` in `{url}` (expected `http` or `https`)",
            url.scheme()
        )))
    }
}

/// Returns `true` when `target` shares the same scheme, host, and port as `base`.
#[must_use]
pub fn is_same_origin(base: &Url, target: &Url) -> bool {
    base.scheme().eq_ignore_ascii_case(target.scheme())
        && base.host_str().is_some()
        && base.host_str() == target.host_str()
        && base.port_or_known_default() == target.port_or_known_default()
}

/// Returns `true` when `target` uses `http`/`https` and its host matches `base`
/// (allowing `www.` <-> apex equivalence for non-IP, non-localhost domains).
#[must_use]
pub fn is_same_site_host(base: &Url, target: &Url) -> bool {
    if !matches!(target.scheme(), "http" | "https") {
        return false;
    }
    let (Some(base_host), Some(target_host)) = (base.host_str(), target.host_str()) else {
        return false;
    };
    if base_host.eq_ignore_ascii_case(target_host) {
        return true;
    }
    if matches!(base.host(), Some(url::Host::Ipv4(_) | url::Host::Ipv6(_)))
        || matches!(target.host(), Some(url::Host::Ipv4(_) | url::Host::Ipv6(_)))
        || base_host.eq_ignore_ascii_case("localhost")
        || target_host.eq_ignore_ascii_case("localhost")
    {
        return false;
    }
    let base_apex = base_host.strip_prefix("www.").unwrap_or(base_host);
    let target_apex = target_host.strip_prefix("www.").unwrap_or(target_host);
    base_apex.eq_ignore_ascii_case(target_apex)
}

/// Reads a response body as UTF-8 text up to `max_bytes`, failing if the body exceeds the cap.
pub async fn read_body_limited(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<String, CheckError> {
    if let Some(content_len) = resp.content_length()
        && u64::try_from(max_bytes).is_ok_and(|cap| content_len > cap)
    {
        return Err(CheckError::Other(format!(
            "response body ({content_len} bytes) exceeds {max_bytes}-byte limit"
        )));
    }

    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            return Err(CheckError::Other(format!(
                "response body exceeds {max_bytes}-byte limit"
            )));
        }
        buf.extend_from_slice(&chunk);
    }

    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Pass,
    Warn,
    Fail,
}

impl Severity {
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docs_url: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<String>,
}

impl Finding {
    #[must_use]
    pub fn pass(title: impl Into<String>, detail: Option<String>) -> Self {
        Self {
            severity: Severity::Pass,
            rule: None,
            title: title.into(),
            detail,
            docs_url: None,
            items: Vec::new(),
        }
    }

    #[must_use]
    pub fn warn(title: impl Into<String>, detail: Option<String>) -> Self {
        Self {
            severity: Severity::Warn,
            rule: None,
            title: title.into(),
            detail,
            docs_url: None,
            items: Vec::new(),
        }
    }

    #[must_use]
    pub fn fail(title: impl Into<String>, detail: Option<String>) -> Self {
        Self {
            severity: Severity::Fail,
            rule: None,
            title: title.into(),
            detail,
            docs_url: None,
            items: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_rule(mut self, rule: impl Into<String>) -> Self {
        self.rule = Some(rule.into());
        self
    }

    #[must_use]
    pub fn with_docs(mut self, url: impl Into<String>) -> Self {
        self.docs_url = Some(url.into());
        self
    }

    #[must_use]
    pub fn with_items(mut self, items: Vec<String>) -> Self {
        self.items = items;
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    pub name: String,
    pub findings: Vec<Finding>,
}

impl CheckReport {
    #[must_use]
    pub fn new(name: impl Into<String>, findings: Vec<Finding>) -> Self {
        Self {
            name: name.into(),
            findings,
        }
    }

    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Fail)
    }

    #[must_use]
    pub fn has_warnings(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Warn)
    }

    #[must_use]
    pub fn status(&self) -> Severity {
        if self.has_failures() {
            Severity::Fail
        } else if self.has_warnings() {
            Severity::Warn
        } else {
            Severity::Pass
        }
    }
}

#[derive(Debug, Error)]
pub enum CheckError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("{0}")]
    Other(String),
}

pub struct CheckContext {
    pub base_url: Url,
    pub client: reqwest::Client,
    pub no_redirect_client: reqwest::Client,
    pub same_origin_client: reqwest::Client,
}

impl CheckContext {
    pub fn new(base_url: Url) -> Result<Self, CheckError> {
        validate_http_url(&base_url)?;

        let site_url = base_url.clone();
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(Policy::custom(move |attempt| {
                if attempt.previous().len() >= 10 {
                    attempt.error("too many redirects")
                } else if is_same_site_host(&site_url, attempt.url()) {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
            .build()?;

        let no_redirect_client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(Policy::none())
            .build()?;

        let origin_url = base_url.clone();
        let same_origin_client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(Policy::custom(move |attempt| {
                if attempt.previous().len() >= 10 {
                    attempt.error("too many redirects")
                } else if is_same_origin(&origin_url, attempt.url()) {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
            .build()?;

        Ok(Self {
            base_url,
            client,
            no_redirect_client,
            same_origin_client,
        })
    }
}

#[async_trait]
pub trait Check: Send + Sync {
    fn name(&self) -> &'static str;
    async fn run(&self, ctx: &CheckContext) -> Result<CheckReport, CheckError>;
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::{is_same_site_host, validate_http_url};

    #[test]
    fn validates_http_and_https_urls_only() {
        let https = Url::parse("https://example.com/").expect("valid https url");
        let http = Url::parse("http://localhost:8080/").expect("valid http url");
        let file = Url::parse("file:///etc/passwd").expect("valid file url");

        assert!(validate_http_url(&https).is_ok());
        assert!(validate_http_url(&http).is_ok());
        assert!(validate_http_url(&file).is_err());
    }

    #[test]
    fn allows_only_same_site_or_www_apex_redirects() {
        let apex = Url::parse("https://example.com/").expect("valid apex url");
        let www_http = Url::parse("http://www.example.com/path").expect("valid www url");
        let www_https = Url::parse("https://www.example.com/").expect("valid www https url");
        let other = Url::parse("https://evil.example.net/").expect("valid other url");
        let loopback = Url::parse("http://127.0.0.1/").expect("valid loopback url");
        let metadata =
            Url::parse("http://169.254.169.254/latest/meta-data/").expect("valid metadata url");
        let ipv6 = Url::parse("http://[::1]:8080/").expect("valid ipv6 url");
        let file_url = Url::parse("file:///etc/passwd").expect("valid file url");

        assert!(is_same_site_host(&apex, &www_http));
        assert!(is_same_site_host(&apex, &www_https));
        assert!(is_same_site_host(&www_https, &apex));
        assert!(!is_same_site_host(&apex, &other));
        assert!(!is_same_site_host(&apex, &loopback));
        assert!(!is_same_site_host(&apex, &metadata));
        assert!(!is_same_site_host(&apex, &ipv6));
        assert!(!is_same_site_host(&apex, &file_url));
        assert!(is_same_site_host(&ipv6, &ipv6));
    }
}
