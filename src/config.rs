use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;
use url::Url;

use crate::check::Check;
use crate::checks::ai::{AiCheck, AiConfig};
use crate::checks::axe::{AxeCheck, AxeConfig};
use crate::checks::http::{HttpCheck, HttpConfig};
use crate::checks::indexnow::{IndexNowCheck, IndexNowConfig};
use crate::checks::lighthouse::{LighthouseCheck, LighthouseConfig};
use crate::checks::pagespeed::{PageSpeedCheck, PageSpeedConfig};
use crate::checks::search_console::{SearchConsoleCheck, SearchConsoleConfig};
use crate::checks::security_headers::{SecurityHeadersCheck, SecurityHeadersConfig};
use crate::checks::seo::{SeoCheck, SeoConfig};
use crate::checks::structured_data::{StructuredDataCheck, StructuredDataConfig};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse config TOML: {0}")]
    Parse(#[from] toml::de::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleLevel {
    Off,
    Warn,
    Error,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub url: Url,
    #[serde(default)]
    pub rules: BTreeMap<String, RuleLevel>,
    pub http: Option<HttpConfig>,
    pub seo: Option<SeoConfig>,
    pub security_headers: Option<SecurityHeadersConfig>,
    pub structured_data: Option<StructuredDataConfig>,
    pub ai: Option<AiConfig>,
    pub indexnow: Option<IndexNowConfig>,
    pub pagespeed: Option<PageSpeedConfig>,
    pub lighthouse: Option<LighthouseConfig>,
    pub axe: Option<AxeConfig>,
    pub search_console: Option<SearchConsoleConfig>,
}

impl Config {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(input)?)
    }

    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        Self::parse(&content)
    }

    #[must_use]
    pub fn enabled_checks(&self) -> Vec<Box<dyn Check>> {
        let mut checks: Vec<Box<dyn Check>> = Vec::new();
        if let Some(cfg) = &self.http {
            checks.push(Box::new(HttpCheck::new(cfg.clone())));
        }
        if let Some(cfg) = &self.seo {
            checks.push(Box::new(SeoCheck::new(cfg.clone())));
        }
        if let Some(cfg) = &self.security_headers {
            checks.push(Box::new(SecurityHeadersCheck::new(cfg.clone())));
        }
        if let Some(cfg) = &self.structured_data {
            checks.push(Box::new(StructuredDataCheck::new(cfg.clone())));
        }
        if let Some(cfg) = &self.ai {
            checks.push(Box::new(AiCheck::new(cfg.clone())));
        }
        if let Some(cfg) = &self.indexnow {
            checks.push(Box::new(IndexNowCheck::new(cfg.clone())));
        }
        if let Some(cfg) = &self.pagespeed {
            checks.push(Box::new(PageSpeedCheck::new(cfg.clone())));
        }
        if let Some(cfg) = &self.lighthouse {
            checks.push(Box::new(LighthouseCheck::new(cfg.clone())));
        }
        if let Some(cfg) = &self.axe {
            checks.push(Box::new(AxeCheck::new(cfg.clone())));
        }
        if let Some(cfg) = &self.search_console {
            checks.push(Box::new(SearchConsoleCheck::new(cfg.clone())));
        }
        checks
    }
}

#[must_use]
pub fn default_config_template(url: &Url) -> String {
    format!(
        r#"url = "{url}"

# [rules]
# "seo/apple-touch-icon" = "warn"
# "security/csp" = "error"
# "http/llms-txt" = "off"

[http]
check_www_redirect = true
check_https_redirect = true
check_soft_404 = true
check_html_size = true
check_head_validity = true
check_trailing_slash = true
check_canonical = true
check_sitemap = true
check_robots = true
check_llms_txt = true

[seo]
check_favicon = true

[security_headers]
# check_security_txt = true

[structured_data]
required_types = ["Organization", "WebSite"]
check_site_name = true
check_open_graph = true
check_twitter = true

[ai]
# allow_blocked = []

# [indexnow]
# key = "your-indexnow-key"
# key_location = "https://example.com/your-indexnow-key.txt"

# [pagespeed]
# strategies = ["mobile", "desktop"]
# api_key_env = "PSI_API_KEY"
# [pagespeed.min_scores]
# performance = 90
# accessibility = 95
# best_practices = 95
# seo = 95

# [lighthouse]
# form_factors = ["mobile"]
# [lighthouse.min_scores]
# performance = 90
# seo = 95

# [axe]
# tags = ["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]
# paths = ["/"]

# [search_console]
# site_url = "{url}"
# service_account_env = "GOOGLE_APPLICATION_CREDENTIALS"
# inspect_urls = ["{url}"]
"#
    )
}

#[cfg(test)]
mod tests {
    use super::{Config, RuleLevel};

    #[test]
    fn parses_full_sitecheck_toml() {
        let input = r#"
url = "https://example.com/"

[rules]
"seo/apple-touch-icon" = "off"
"security/csp" = "error"
"http/soft-404" = "warn"

[http]
check_www_redirect = true
check_trailing_slash = false
extra_paths = ["/about"]

[seo]
check_favicon = true

[security_headers]
check_security_txt = true

[structured_data]
required_types = ["Organization", "WebSite"]

[ai]
allow_blocked = ["ExaSearchBot"]

[indexnow]
key = "abc123"

[pagespeed]
strategies = ["mobile"]
[pagespeed.min_scores]
performance = 85
seo = 95

[lighthouse]
form_factors = ["desktop"]
[lighthouse.min_scores]
accessibility = 90

[axe]
tags = ["wcag2a", "wcag2aa"]
paths = ["/", "/about"]

[search_console]
site_url = "sc-domain:example.com"
inspect_urls = ["https://example.com/"]
"#;

        let config = Config::parse(input).expect("valid TOML should parse");
        assert_eq!(config.url.as_str(), "https://example.com/");
        assert_eq!(config.enabled_checks().len(), 10);
        assert_eq!(
            config.rules.get("seo/apple-touch-icon"),
            Some(&RuleLevel::Off)
        );
        assert_eq!(config.rules.get("security/csp"), Some(&RuleLevel::Error));
        assert_eq!(config.rules.get("http/soft-404"), Some(&RuleLevel::Warn));

        let http = config.http.expect("http section present");
        assert!(http.check_www_redirect);
        assert!(http.check_https_redirect);
        assert!(http.check_soft_404);
        assert!(http.check_html_size);
        assert!(http.check_head_validity);
        assert!(!http.check_trailing_slash);
        assert!(http.check_canonical);
        assert!(!http.require_content_signal);
        assert_eq!(http.max_sitemap_urls, 15);
        assert_eq!(http.extra_paths, vec!["/about"]);

        let seo = config.seo.expect("seo section present");
        assert!(seo.check_favicon);
        assert_eq!(seo.max_sitemap_urls, 15);

        let sec = config.security_headers.expect("security_headers present");
        assert!(sec.check_security_txt);

        let ai = config.ai.expect("ai section present");
        assert_eq!(ai.allow_blocked, vec!["ExaSearchBot"]);

        let indexnow = config.indexnow.expect("indexnow section present");
        assert_eq!(indexnow.key, "abc123");
        assert!(indexnow.key_location.is_none());

        let psi = config.pagespeed.expect("pagespeed section present");
        assert_eq!(psi.strategies, vec!["mobile"]);
        assert_eq!(psi.min_scores.performance, Some(85));
        assert_eq!(psi.min_scores.seo, Some(95));
    }

    #[test]
    fn parses_minimal_config_with_only_http() {
        let input = r#"
url = "https://example.com/"

[http]
"#;
        let config = Config::parse(input).expect("minimal TOML should parse");
        let checks = config.enabled_checks();
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name(), "http");
        assert!(config.rules.is_empty());
    }

    #[test]
    fn parses_example_sitecheck_toml() {
        let example = include_str!("../examples/sitecheck.toml");
        let config = Config::parse(example).expect("examples/sitecheck.toml should parse");
        assert_eq!(config.url.as_str(), "https://example.com/");
        assert!(config.http.is_some());
        assert!(config.seo.is_some());
        assert!(config.security_headers.is_some());
        assert!(config.structured_data.is_some());
        assert!(config.ai.is_some());
    }

    #[test]
    fn rejects_unknown_config_fields() {
        let bad_top_level = r#"
url = "https://example.com/"
unknown_flag = true
"#;
        assert!(Config::parse(bad_top_level).is_err());

        let bad_section_field = r#"
url = "https://example.com/"

[http]
check_canonicals = true
"#;
        assert!(Config::parse(bad_section_field).is_err());
    }
}
