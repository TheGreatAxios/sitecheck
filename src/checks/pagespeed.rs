use std::env;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use url::form_urlencoded;

use crate::check::{Check, CheckContext, CheckError, CheckReport};
use crate::checks::{MinScores, parse_lighthouse_result};

const PSI_ENDPOINT: &str = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed";

fn redact_api_key(text: &str, api_key: Option<&str>) -> String {
    let Some(key) = api_key.map(str::trim).filter(|k| !k.is_empty()) else {
        return text.to_owned();
    };
    let encoded: String = form_urlencoded::byte_serialize(key.as_bytes()).collect();
    let redacted = text.replace(key, "[REDACTED]");
    if encoded == key {
        redacted
    } else {
        redacted.replace(&encoded, "[REDACTED]")
    }
}

fn default_strategies() -> Vec<String> {
    vec!["mobile".to_owned(), "desktop".to_owned()]
}

fn default_api_key_env() -> String {
    "PSI_API_KEY".to_owned()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSpeedConfig {
    #[serde(default = "default_strategies")]
    pub strategies: Vec<String>,
    #[serde(default = "default_api_key_env")]
    pub api_key_env: String,
    #[serde(default)]
    pub min_scores: MinScores,
}

pub struct PageSpeedCheck {
    config: PageSpeedConfig,
}

impl PageSpeedCheck {
    #[must_use]
    pub const fn new(config: PageSpeedConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Check for PageSpeedCheck {
    fn name(&self) -> &'static str {
        "pagespeed"
    }

    async fn run(&self, ctx: &CheckContext) -> Result<CheckReport, CheckError> {
        let api_key = env::var(&self.config.api_key_env)
            .ok()
            .filter(|v| !v.trim().is_empty());

        let mut findings = Vec::new();
        for strategy in &self.config.strategies {
            let mut query: Vec<(&str, &str)> = vec![
                ("url", ctx.base_url.as_str()),
                ("strategy", strategy.as_str()),
                ("category", "performance"),
                ("category", "accessibility"),
                ("category", "best-practices"),
                ("category", "seo"),
            ];
            if let Some(key) = api_key.as_deref() {
                query.push(("key", key));
            }

            let resp = ctx
                .client
                .get(PSI_ENDPOINT)
                .query(&query)
                .send()
                .await
                .map_err(|err| {
                    CheckError::Other(format!(
                        "PageSpeed Insights request failed for {strategy}: {}",
                        redact_api_key(&err.to_string(), api_key.as_deref())
                    ))
                })?;
            let status = resp.status();
            if !status.is_success() {
                let raw_body = resp.text().await.unwrap_or_default();
                let body = redact_api_key(&raw_body, api_key.as_deref());
                let hint = if api_key.is_none() {
                    format!(" (hint: set `{}` env var)", self.config.api_key_env)
                } else {
                    String::new()
                };
                return Err(CheckError::Other(format!(
                    "PageSpeed Insights API returned HTTP {status} for {strategy}{hint}: {body}"
                )));
            }

            let payload: Value = resp.json().await.map_err(|err| {
                CheckError::Other(format!(
                    "failed to decode PageSpeed Insights response for {strategy}: {}",
                    redact_api_key(&err.to_string(), api_key.as_deref())
                ))
            })?;
            let lhr = payload.get("lighthouseResult").ok_or_else(|| {
                CheckError::Other(format!(
                    "PageSpeed Insights response for {strategy} missing `lighthouseResult`"
                ))
            })?;

            findings.extend(parse_lighthouse_result(
                lhr,
                self.name(),
                strategy,
                &self.config.min_scores,
            )?);
        }

        Ok(CheckReport::new(self.name(), findings))
    }
}

#[cfg(test)]
mod tests {
    use super::redact_api_key;

    #[test]
    fn redacts_raw_and_url_encoded_api_key_in_error_messages() {
        let key = "AIzaSyTest+Secret/Key=123";
        let raw_err = format!(
            "error sending request for url (https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=https%3A%2F%2Fexample.com%2F&key={key})"
        );
        let sanitized_raw = redact_api_key(&raw_err, Some(key));
        assert!(!sanitized_raw.contains(key));
        assert!(sanitized_raw.contains("&key=[REDACTED]"));

        let encoded_err = "error sending request for url (https://www.googleapis.com/pagespeedonline/v5/runPagespeed?strategy=mobile&key=AIzaSyTest%2BSecret%2FKey%3D123)";
        let sanitized_encoded = redact_api_key(encoded_err, Some(key));
        assert!(!sanitized_encoded.contains("AIzaSyTest"));
        assert!(sanitized_encoded.contains("&key=[REDACTED]"));
    }
}
