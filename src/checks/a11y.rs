use std::collections::BTreeMap;

use async_trait::async_trait;
use clearway::{AuditOptions, Impact, Violation, audit_html};
use serde::Deserialize;

use crate::check::{
    Check, CheckContext, CheckError, CheckReport, Finding, MAX_HTML_BODY_BYTES, read_body_limited,
    validate_http_url,
};

const MAX_VIOLATION_ITEMS: usize = 5;

fn default_paths() -> Vec<String> {
    vec!["/".to_owned()]
}

fn default_tags() -> Vec<String> {
    vec![
        "wcag2a".to_owned(),
        "wcag2aa".to_owned(),
        "wcag21aa".to_owned(),
        "wcag22aa".to_owned(),
    ]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A11yConfig {
    #[serde(default = "default_paths")]
    pub paths: Vec<String>,
    #[serde(default = "default_tags")]
    pub tags: Vec<String>,
    #[serde(default)]
    pub include_incomplete: bool,
    #[serde(default)]
    pub include_disabled: bool,
}

impl Default for A11yConfig {
    fn default() -> Self {
        Self {
            paths: default_paths(),
            tags: default_tags(),
            include_incomplete: false,
            include_disabled: false,
        }
    }
}

pub struct A11yCheck {
    config: A11yConfig,
}

impl A11yCheck {
    #[must_use]
    pub const fn new(config: A11yConfig) -> Self {
        Self { config }
    }
}

const fn impact_label(impact: Impact) -> &'static str {
    match impact {
        Impact::Critical => "critical",
        Impact::Serious => "serious",
        Impact::Moderate => "moderate",
        Impact::Minor => "minor",
    }
}

fn format_violation_item(violation: &Violation, group_description: &str) -> Option<String> {
    let selector = violation.selector.trim();
    let description = violation.description.trim();
    let has_distinct_msg = !description.is_empty() && description != group_description;

    match (!selector.is_empty(), has_distinct_msg) {
        (true, true) => Some(format!("{selector} — {description}")),
        (true, false) => Some(selector.to_owned()),
        (false, true) => Some(description.to_owned()),
        (false, false) => None,
    }
}

fn push_grouped_findings(violations: &[Violation], force_warn: bool, findings: &mut Vec<Finding>) {
    let mut grouped: BTreeMap<&str, Vec<&Violation>> = BTreeMap::new();
    for violation in violations {
        grouped
            .entry(violation.rule_id.as_str())
            .or_default()
            .push(violation);
    }

    for (rule_id, group) in grouped {
        let Some(first) = group.first().copied() else {
            continue;
        };
        let impact = group.iter().map(|v| v.impact).max().unwrap_or(first.impact);
        let title = if first.help.trim().is_empty() {
            rule_id.to_owned()
        } else {
            first.help.trim().to_owned()
        };
        let group_desc = first.description.trim();
        let detail = if force_warn {
            format!("needs review ({} node(s)) — {group_desc}", group.len())
        } else {
            format!(
                "{} ({} node(s)) — {group_desc}",
                impact_label(impact),
                group.len()
            )
        };

        let mut finding = if !force_warn && matches!(impact, Impact::Critical | Impact::Serious) {
            Finding::fail(title, Some(detail))
        } else {
            Finding::warn(title, Some(detail))
        }
        .with_rule(format!("a11y/{rule_id}"));

        let docs_url = first.docs_url.trim();
        if !docs_url.is_empty() {
            finding = finding.with_docs(docs_url);
        }

        let items: Vec<String> = group
            .iter()
            .filter_map(|v| format_violation_item(v, group_desc))
            .take(MAX_VIOLATION_ITEMS)
            .collect();
        if !items.is_empty() {
            finding = finding.with_items(items);
        }

        findings.push(finding);
    }
}

/// Runs Clearway static HTML WCAG checks on `html` and converts findings to `sitecheck` format.
#[must_use]
pub fn audit_html_findings(html: &str, config: &A11yConfig) -> Vec<Finding> {
    let opts = AuditOptions {
        tags: (!config.tags.is_empty()).then(|| config.tags.clone()),
        include_disabled: config.include_disabled,
        ..AuditOptions::default()
    };
    let report = audit_html(html, &opts);

    let mut findings = Vec::new();
    push_grouped_findings(&report.violations, false, &mut findings);
    if config.include_incomplete {
        push_grouped_findings(&report.incomplete, true, &mut findings);
    }

    if findings.is_empty() {
        findings.push(
            Finding::pass(
                "WCAG accessibility",
                Some(format!(
                    "0 violations across {} static HTML rules via Clearway (computed-style checks require [axe] or [lighthouse])",
                    report.summary.rules_run
                )),
            )
            .with_rule("a11y/wcag"),
        );
    }

    findings
}

#[async_trait]
impl Check for A11yCheck {
    fn name(&self) -> &'static str {
        "a11y"
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
            let prefix = if show_prefix {
                format!("{path} ")
            } else {
                String::new()
            };

            let resp = ctx.client.get(target_url.clone()).send().await?;
            if !resp.status().is_success() {
                findings.push(
                    Finding::fail(
                        format!("{prefix}fetch"),
                        Some(format!("HTTP {} for {target_url}", resp.status())),
                    )
                    .with_rule("a11y/fetch"),
                );
                continue;
            }

            let html = read_body_limited(resp, MAX_HTML_BODY_BYTES).await?;
            let mut page_findings = audit_html_findings(&html, &self.config);
            if show_prefix {
                for finding in &mut page_findings {
                    finding.title = format!("{path} {}", finding.title);
                }
            }
            findings.extend(page_findings);
        }

        Ok(CheckReport::new(self.name(), findings))
    }
}

#[cfg(test)]
mod tests {
    use super::{A11yConfig, audit_html_findings};
    use crate::check::Severity;

    #[test]
    fn clean_accessible_html_passes_a11y_wcag() {
        let html = r#"<!doctype html>
<html lang="en">
  <head><title>Accessible Home</title></head>
  <body>
    <main>
      <h1>Welcome</h1>
      <img src="/hero.png" alt="Sunset over the valley" />
    </main>
  </body>
</html>"#;

        let findings = audit_html_findings(html, &A11yConfig::default());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Pass);
        assert_eq!(findings[0].rule.as_deref(), Some("a11y/wcag"));
        assert!(
            findings[0]
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("Clearway"))
        );
    }

    #[test]
    fn broken_html_flags_html_has_lang_and_image_alt() {
        let html = r#"<!doctype html>
<html>
  <head><title>Broken Page</title></head>
  <body>
    <main>
      <h1>Broken</h1>
      <img src="/logo.png" />
    </main>
  </body>
</html>"#;

        let findings = audit_html_findings(html, &A11yConfig::default());
        let lang = findings
            .iter()
            .find(|f| f.rule.as_deref() == Some("a11y/html-has-lang"))
            .expect("missing lang should trigger a11y/html-has-lang");
        assert_eq!(lang.severity, Severity::Fail);
        assert!(lang.docs_url.is_some());

        let img_alt = findings
            .iter()
            .find(|f| f.rule.as_deref() == Some("a11y/image-alt"))
            .expect("missing img alt should trigger a11y/image-alt");
        assert_eq!(img_alt.severity, Severity::Fail);
        assert_eq!(img_alt.items.len(), 1);
    }

    #[test]
    fn config_defaults_and_rejects_unknown_fields() {
        let parsed: A11yConfig = toml::from_str("").expect("empty [a11y] should use defaults");
        assert_eq!(parsed.paths, vec!["/"]);
        assert_eq!(
            parsed.tags,
            vec!["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]
        );
        assert!(!parsed.include_incomplete);
        assert!(!parsed.include_disabled);

        let unknown = toml::from_str::<A11yConfig>("unknown_option = true");
        assert!(unknown.is_err());
    }
}
