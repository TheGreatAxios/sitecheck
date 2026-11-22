use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tokio::process::Command;

use crate::check::{Check, CheckContext, CheckError, CheckReport, validate_http_url};
use crate::checks::{MinScores, parse_lighthouse_result};

fn default_binary() -> String {
    "lighthouse".to_owned()
}

fn default_form_factors() -> Vec<String> {
    vec!["mobile".to_owned()]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LighthouseConfig {
    #[serde(default = "default_binary")]
    pub binary: String,
    #[serde(default = "default_form_factors")]
    pub form_factors: Vec<String>,
    #[serde(default)]
    pub min_scores: MinScores,
    #[serde(default)]
    pub extra_args: Vec<String>,
}

pub struct LighthouseCheck {
    config: LighthouseConfig,
}

impl LighthouseCheck {
    #[must_use]
    pub const fn new(config: LighthouseConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Check for LighthouseCheck {
    fn name(&self) -> &'static str {
        "lighthouse"
    }

    async fn run(&self, ctx: &CheckContext) -> Result<CheckReport, CheckError> {
        validate_http_url(&ctx.base_url)?;
        let mut findings = Vec::new();

        for form_factor in &self.config.form_factors {
            let mut cmd = Command::new(&self.config.binary);
            cmd.arg(ctx.base_url.as_str())
                .arg("--output=json")
                .arg("--output-path=stdout")
                .arg("--quiet")
                .arg("--chrome-flags=--headless --no-sandbox");

            if form_factor.eq_ignore_ascii_case("desktop") {
                cmd.arg("--preset=desktop");
            }
            for extra in &self.config.extra_args {
                cmd.arg(extra);
            }

            let output = cmd.output().await.map_err(|err| {
                CheckError::Other(format!("failed to run `{}` CLI: {err}", self.config.binary))
            })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(CheckError::Other(format!(
                    "`{}` exited with {} for {form_factor}: {}",
                    self.config.binary,
                    output.status,
                    stderr.trim()
                )));
            }

            let lhr: Value = serde_json::from_slice(&output.stdout)?;
            findings.extend(parse_lighthouse_result(
                &lhr,
                form_factor,
                &self.config.min_scores,
            )?);
        }

        Ok(CheckReport::new(self.name(), findings))
    }
}
