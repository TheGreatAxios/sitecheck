use std::env;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::check::{Check, CheckContext, CheckError, CheckReport};
use crate::checks::{MinScores, parse_lighthouse_result};

const PSI_ENDPOINT: &str = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed";

fn default_strategies() -> Vec<String> {
    vec!["mobile".to_owned(), "desktop".to_owned()]
}

fn default_api_key_env() -> String {
    "PSI_API_KEY".to_owned()
}

#[derive(Debug, Clone, Deserialize)]
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

            let resp = ctx.client.get(PSI_ENDPOINT).query(&query).send().await?;
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                let hint = if api_key.is_none() {
                    format!(" (hint: set `{}` env var)", self.config.api_key_env)
                } else {
                    String::new()
                };
                return Err(CheckError::Other(format!(
                    "PageSpeed Insights API returned HTTP {status} for {strategy}{hint}: {body}"
                )));
            }

            let payload: Value = resp.json().await?;
            let lhr = payload.get("lighthouseResult").ok_or_else(|| {
                CheckError::Other(format!(
                    "PageSpeed Insights response for {strategy} missing `lighthouseResult`"
                ))
            })?;

            findings.extend(parse_lighthouse_result(
                lhr,
                strategy,
                &self.config.min_scores,
            )?);
        }

        Ok(CheckReport::new(self.name(), findings))
    }
}
