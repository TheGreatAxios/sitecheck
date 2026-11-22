use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tokio::process::Command;

use crate::check::{Check, CheckContext, CheckError, CheckReport, validate_http_url};
use crate::checks::{MinScores, parse_lighthouse_result};

const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(120);

fn default_binary() -> String {
    "lighthouse".to_owned()
}

fn default_form_factors() -> Vec<String> {
    vec!["mobile".to_owned()]
}

fn validate_form_factors(form_factors: &[String]) -> Result<Vec<&'static str>, CheckError> {
    if form_factors.is_empty() {
        return Err(CheckError::Config(
            "lighthouse `form_factors` must not be empty (expected `mobile` and/or `desktop`)"
                .to_owned(),
        ));
    }
    let mut normalized = Vec::with_capacity(form_factors.len());
    for raw in form_factors {
        let trimmed = raw.trim();
        if trimmed.eq_ignore_ascii_case("mobile") {
            normalized.push("mobile");
        } else if trimmed.eq_ignore_ascii_case("desktop") {
            normalized.push("desktop");
        } else {
            return Err(CheckError::Config(format!(
                "unsupported lighthouse form_factor `{raw}` (expected `mobile` or `desktop`)"
            )));
        }
    }
    Ok(normalized)
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
        let form_factors = validate_form_factors(&self.config.form_factors)?;
        let mut findings = Vec::new();

        for form_factor in form_factors {
            let mut cmd = Command::new(&self.config.binary);
            cmd.kill_on_drop(true);
            cmd.arg(ctx.base_url.as_str())
                .arg("--output=json")
                .arg("--output-path=stdout")
                .arg("--quiet")
                .arg("--chrome-flags=--headless --no-sandbox");

            if form_factor == "desktop" {
                cmd.arg("--preset=desktop");
            }
            for extra in &self.config.extra_args {
                cmd.arg(extra);
            }

            let output = tokio::time::timeout(SUBPROCESS_TIMEOUT, cmd.output())
                .await
                .map_err(|_| {
                    CheckError::Other(format!(
                        "`{}` timed out after {}s for {form_factor}",
                        self.config.binary,
                        SUBPROCESS_TIMEOUT.as_secs()
                    ))
                })?
                .map_err(|err| {
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
                self.name(),
                form_factor,
                &self.config.min_scores,
            )?);
        }

        Ok(CheckReport::new(self.name(), findings))
    }
}

#[cfg(test)]
mod tests {
    use super::validate_form_factors;

    #[test]
    fn validates_lighthouse_form_factors() {
        assert_eq!(
            validate_form_factors(&["mobile".to_owned(), "Desktop".to_owned()])
                .expect("valid form factors"),
            vec!["mobile", "desktop"]
        );
        assert!(validate_form_factors(&[]).is_err());
        assert!(validate_form_factors(&["tablet".to_owned()]).is_err());
    }
}
