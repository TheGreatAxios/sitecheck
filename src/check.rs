use std::time::Duration;

use async_trait::async_trait;
use reqwest::redirect::Policy;
use serde::Serialize;
use thiserror::Error;
use url::Url;

const USER_AGENT: &str = concat!("sitecheck/", env!("CARGO_PKG_VERSION"));
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

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
}

impl CheckContext {
    pub fn new(base_url: Url) -> Result<Self, CheckError> {
        validate_http_url(&base_url)?;

        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()?;

        let no_redirect_client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(Policy::none())
            .build()?;

        Ok(Self {
            base_url,
            client,
            no_redirect_client,
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

    use super::validate_http_url;

    #[test]
    fn validates_http_and_https_urls_only() {
        let https = Url::parse("https://example.com/").expect("valid https url");
        let http = Url::parse("http://localhost:8080/").expect("valid http url");
        let file = Url::parse("file:///etc/passwd").expect("valid file url");

        assert!(validate_http_url(&https).is_ok());
        assert!(validate_http_url(&http).is_ok());
        assert!(validate_http_url(&file).is_err());
    }
}
