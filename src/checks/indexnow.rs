use async_trait::async_trait;
use reqwest::StatusCode;
use serde::Deserialize;

use crate::check::{Check, CheckContext, CheckError, CheckReport, Finding};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexNowConfig {
    pub key: String,
    #[serde(default)]
    pub key_location: Option<String>,
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

#[async_trait]
impl Check for IndexNowCheck {
    fn name(&self) -> &'static str {
        "indexnow"
    }

    async fn run(&self, ctx: &CheckContext) -> Result<CheckReport, CheckError> {
        let key = self.config.key.trim();
        if key.is_empty() {
            return Ok(CheckReport::new(
                self.name(),
                vec![
                    Finding::fail(
                        "IndexNow key file",
                        Some("configured `indexnow.key` is empty".to_owned()),
                    )
                    .with_rule("indexnow/key-file"),
                ],
            ));
        }

        let target_url = match self.config.key_location.as_deref().map(str::trim) {
            Some(loc) if !loc.is_empty() => ctx.base_url.join(loc)?,
            _ => ctx.base_url.join(&format!("/{key}.txt"))?,
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

        let body = resp.text().await.unwrap_or_default();
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
