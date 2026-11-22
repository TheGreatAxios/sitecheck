use std::io::ErrorKind;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tokio::process::Command;

use crate::check::{Check, CheckContext, CheckError, CheckReport, Finding, validate_http_url};

const MAX_VIOLATION_ITEMS: usize = 5;
const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(120);

fn default_tags() -> Vec<String> {
    vec![
        "wcag2a".to_owned(),
        "wcag2aa".to_owned(),
        "wcag21aa".to_owned(),
        "wcag22aa".to_owned(),
    ]
}

fn default_paths() -> Vec<String> {
    vec!["/".to_owned()]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AxeConfig {
    pub bin: Option<String>,
    #[serde(default = "default_tags")]
    pub tags: Vec<String>,
    #[serde(default = "default_paths")]
    pub paths: Vec<String>,
}

impl Default for AxeConfig {
    fn default() -> Self {
        Self {
            bin: None,
            tags: default_tags(),
            paths: default_paths(),
        }
    }
}

pub struct AxeCheck {
    config: AxeConfig,
}

impl AxeCheck {
    #[must_use]
    pub const fn new(config: AxeConfig) -> Self {
        Self { config }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AxePayload {
    Multiple(Vec<AxePageReport>),
    Single(AxePageReport),
}

#[derive(Debug, Deserialize)]
struct AxePageReport {
    violations: Vec<AxeViolation>,
}

#[derive(Debug, Deserialize)]
struct AxeViolation {
    id: String,
    #[serde(default)]
    impact: Option<String>,
    #[serde(default)]
    help: String,
    #[serde(default)]
    description: String,
    #[serde(default, rename = "helpUrl")]
    help_url: Option<String>,
    #[serde(default)]
    nodes: Vec<AxeNode>,
}

#[derive(Debug, Deserialize)]
struct AxeNode {
    #[serde(default)]
    target: Vec<Value>,
    #[serde(default, rename = "failureSummary")]
    failure_summary: Option<String>,
}

fn format_target_value(val: &Value) -> Option<String> {
    match val {
        Value::String(s) => {
            let trimmed = s.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_owned())
        }
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().filter_map(format_target_value).collect();
            (!parts.is_empty()).then(|| parts.join(" "))
        }
        _ => None,
    }
}

fn format_node_item(node: &AxeNode) -> Option<String> {
    let selectors: Vec<String> = node.target.iter().filter_map(format_target_value).collect();
    let selector = (!selectors.is_empty()).then(|| selectors.join(" "));
    let summary = node
        .failure_summary
        .as_deref()
        .and_then(|s| s.lines().map(str::trim).find(|l| !l.is_empty()))
        .map(str::to_owned);

    match (selector, summary) {
        (Some(sel), Some(sum)) => Some(format!("{sel} — {sum}")),
        (Some(sel), None) => Some(sel),
        (None, Some(sum)) => Some(sum),
        (None, None) => None,
    }
}

/// Parse JSON output from `@axe-core/cli` (either `[ { violations } ]` or `{ violations }`).
pub fn parse_axe_report(json: &str) -> Result<Vec<Finding>, CheckError> {
    let payload: AxePayload = serde_json::from_str(json)?;
    let reports = match payload {
        AxePayload::Multiple(list) => list,
        AxePayload::Single(single) => vec![single],
    };

    if reports.is_empty() {
        return Err(CheckError::Other(
            "axe JSON report contained no page results".to_owned(),
        ));
    }

    let mut findings = Vec::new();
    for report in reports {
        for violation in report.violations {
            let impact = violation
                .impact
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("minor");
            let node_count = violation.nodes.len();
            let title = if violation.help.trim().is_empty() {
                violation.id.clone()
            } else {
                violation.help.trim().to_owned()
            };
            let detail = format!(
                "{impact} ({node_count} node(s)) — {}",
                violation.description.trim()
            );

            let mut finding = if impact.eq_ignore_ascii_case("critical")
                || impact.eq_ignore_ascii_case("serious")
            {
                Finding::fail(title, Some(detail))
            } else {
                Finding::warn(title, Some(detail))
            }
            .with_rule(format!("axe/{}", violation.id));

            if let Some(url) = violation
                .help_url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                finding = finding.with_docs(url);
            }

            let items: Vec<String> = violation
                .nodes
                .iter()
                .filter_map(format_node_item)
                .take(MAX_VIOLATION_ITEMS)
                .collect();
            if !items.is_empty() {
                finding = finding.with_items(items);
            }

            findings.push(finding);
        }
    }

    if findings.is_empty() {
        findings.push(
            Finding::pass(
                "WCAG accessibility",
                Some("0 accessibility violations".to_owned()),
            )
            .with_rule("axe/wcag"),
        );
    }

    Ok(findings)
}

async fn run_axe_command(
    bin: Option<&str>,
    target_url: &str,
    tags: &[String],
) -> Result<(String, std::process::Output), CheckError> {
    let mut axe_args: Vec<String> = vec![target_url.to_owned()];
    if !tags.is_empty() {
        axe_args.push("--tags".to_owned());
        axe_args.push(tags.join(","));
    }
    axe_args.push("--stdout".to_owned());
    axe_args.push("--exit".to_owned());

    if let Some(raw_bin) = bin.map(str::trim).filter(|s| !s.is_empty()) {
        let mut cmd = Command::new(raw_bin);
        cmd.kill_on_drop(true);
        cmd.args(&axe_args);
        let output = tokio::time::timeout(SUBPROCESS_TIMEOUT, cmd.output())
            .await
            .map_err(|_| {
                CheckError::Other(format!(
                    "`{raw_bin}` timed out after {}s for {target_url}",
                    SUBPROCESS_TIMEOUT.as_secs()
                ))
            })?
            .map_err(|err| CheckError::Other(format!("failed to run `{raw_bin}` CLI: {err}")))?;
        return Ok((raw_bin.to_owned(), output));
    }

    let mut cmd = Command::new("axe");
    cmd.kill_on_drop(true);
    cmd.args(&axe_args);
    match tokio::time::timeout(SUBPROCESS_TIMEOUT, cmd.output()).await {
        Ok(Ok(output)) => Ok(("axe".to_owned(), output)),
        Ok(Err(err)) if err.kind() == ErrorKind::NotFound => {
            let mut fallback = Command::new("npx");
            fallback.kill_on_drop(true);
            fallback.arg("--yes").arg("@axe-core/cli").args(&axe_args);
            let output = tokio::time::timeout(SUBPROCESS_TIMEOUT, fallback.output())
                .await
                .map_err(|_| {
                    CheckError::Other(format!(
                        "`npx --yes @axe-core/cli` timed out after {}s for {target_url}",
                        SUBPROCESS_TIMEOUT.as_secs()
                    ))
                })?
                .map_err(|fallback_err| {
                    CheckError::Other(format!(
                        "failed to run `axe` ({err}) and fallback `npx --yes @axe-core/cli` ({fallback_err})"
                    ))
                })?;
            Ok(("npx --yes @axe-core/cli".to_owned(), output))
        }
        Ok(Err(err)) => Err(CheckError::Other(format!("failed to run `axe` CLI: {err}"))),
        Err(_) => Err(CheckError::Other(format!(
            "`axe` timed out after {}s for {target_url}",
            SUBPROCESS_TIMEOUT.as_secs()
        ))),
    }
}

#[async_trait]
impl Check for AxeCheck {
    fn name(&self) -> &'static str {
        "axe"
    }

    async fn run(&self, ctx: &CheckContext) -> Result<CheckReport, CheckError> {
        let mut findings = Vec::new();
        let paths = if self.config.paths.is_empty() {
            vec!["/".to_owned()]
        } else {
            self.config.paths.clone()
        };
        let show_prefix = paths.len() > 1;

        for path in &paths {
            let target_url = ctx.base_url.join(path)?;
            validate_http_url(&target_url)?;
            let (bin_label, output) = run_axe_command(
                self.config.bin.as_deref(),
                target_url.as_str(),
                &self.config.tags,
            )
            .await?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            match parse_axe_report(&stdout) {
                Ok(mut parsed) => {
                    if show_prefix {
                        for finding in &mut parsed {
                            finding.title = format!("{path} {}", finding.title);
                        }
                    }
                    findings.extend(parsed);
                }
                Err(parse_err) => {
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        return Err(CheckError::Other(format!(
                            "`{bin_label}` exited with {} for {target_url}: {}",
                            output.status,
                            stderr.trim()
                        )));
                    }
                    return Err(parse_err);
                }
            }
        }

        Ok(CheckReport::new(self.name(), findings))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_axe_report;
    use crate::check::Severity;

    #[test]
    fn parses_zero_violations_from_array_and_object_shapes() {
        for raw in [r#"[{"violations": []}]"#, r#"{"violations": []}"#] {
            let findings = parse_axe_report(raw).expect("valid axe report should parse");
            assert_eq!(findings.len(), 1);
            let pass = &findings[0];
            assert_eq!(pass.severity, Severity::Pass);
            assert_eq!(pass.rule.as_deref(), Some("axe/wcag"));
            assert_eq!(pass.detail.as_deref(), Some("0 accessibility violations"));
        }
    }

    #[test]
    fn maps_impact_levels_to_fail_and_warn() {
        let raw = r#"[{
            "violations": [
                {
                    "id": "image-alt",
                    "impact": "critical",
                    "help": "Images must have alternative text",
                    "description": "Ensure <img> elements have alternative text.",
                    "helpUrl": "https://dequeuniversity.com/rules/axe/4.10/image-alt",
                    "nodes": [{"target": ["img.hero"]}]
                },
                {
                    "id": "color-contrast",
                    "impact": "serious",
                    "help": "Elements must meet minimum color contrast ratio thresholds",
                    "description": "Ensure contrast between foreground and background colors meets WCAG 2 AA.",
                    "helpUrl": "https://dequeuniversity.com/rules/axe/4.10/color-contrast",
                    "nodes": [{"target": ["a.cta"]}, {"target": ["footer p"]}]
                },
                {
                    "id": "landmark-one-main",
                    "impact": "moderate",
                    "help": "Document should have one main landmark",
                    "description": "Ensure the document has a main landmark.",
                    "nodes": [{"target": ["html"]}]
                },
                {
                    "id": "empty-heading",
                    "impact": "minor",
                    "help": "Headings should not be empty",
                    "description": "Ensure headings have discernible text.",
                    "nodes": [{"target": ["h2.empty"]}]
                }
            ]
        }]"#;

        let findings = parse_axe_report(raw).expect("valid axe report should parse");
        assert_eq!(findings.len(), 4);

        assert_eq!(findings[0].severity, Severity::Fail);
        assert_eq!(findings[0].rule.as_deref(), Some("axe/image-alt"));
        assert_eq!(
            findings[0].detail.as_deref(),
            Some("critical (1 node(s)) — Ensure <img> elements have alternative text.")
        );

        assert_eq!(findings[1].severity, Severity::Fail);
        assert_eq!(findings[1].rule.as_deref(), Some("axe/color-contrast"));
        assert_eq!(
            findings[1].detail.as_deref(),
            Some(
                "serious (2 node(s)) — Ensure contrast between foreground and background colors meets WCAG 2 AA."
            )
        );

        assert_eq!(findings[2].severity, Severity::Warn);
        assert_eq!(findings[2].rule.as_deref(), Some("axe/landmark-one-main"));

        assert_eq!(findings[3].severity, Severity::Warn);
        assert_eq!(findings[3].rule.as_deref(), Some("axe/empty-heading"));
    }

    #[test]
    fn extracts_up_to_five_selectors_failure_summary_and_docs_url() {
        let raw = r##"{
            "violations": [{
                "id": "color-contrast",
                "impact": "serious",
                "help": "Elements must meet minimum color contrast ratio thresholds",
                "description": "Ensure contrast ratio meets WCAG 2 AA.",
                "helpUrl": "https://dequeuniversity.com/rules/axe/4.10/color-contrast",
                "nodes": [
                    {
                        "target": ["a.cta-1"],
                        "failureSummary": "Fix any of the following:\n  Element has insufficient color contrast of 3.1."
                    },
                    {"target": [["#shadow-host", "button.cta-2"]]},
                    {"target": ["a.cta-3"], "failureSummary": "Contrast is 2.8:1"},
                    {"target": ["a.cta-4"]},
                    {"target": ["a.cta-5"]},
                    {"target": ["a.cta-6"]}
                ]
            }]
        }"##;

        let findings = parse_axe_report(raw).expect("valid axe report should parse");
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];

        assert_eq!(
            finding.docs_url.as_deref(),
            Some("https://dequeuniversity.com/rules/axe/4.10/color-contrast")
        );
        assert_eq!(
            finding.detail.as_deref(),
            Some("serious (6 node(s)) — Ensure contrast ratio meets WCAG 2 AA.")
        );
        assert_eq!(
            finding.items,
            vec![
                "a.cta-1 — Fix any of the following:",
                "#shadow-host button.cta-2",
                "a.cta-3 — Contrast is 2.8:1",
                "a.cta-4",
                "a.cta-5",
            ]
        );
    }
}
