use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;

use crate::check::{CheckContext, CheckError, CheckReport, Severity};
use crate::config::{Config, RuleLevel};

#[derive(Debug, Serialize)]
pub struct RunSummary {
    pub url: String,
    pub passed: bool,
    pub reports: Vec<CheckReport>,
}

/// Applies per-rule severity overrides from `[rules]` to a `CheckReport`.
pub fn apply_rule_overrides(report: &mut CheckReport, rules: &BTreeMap<String, RuleLevel>) {
    if rules.is_empty() {
        return;
    }

    report.findings.retain_mut(|finding| {
        let Some(rule_id) = finding.rule.as_deref() else {
            return true;
        };
        let level = rules.get(rule_id).copied().or_else(|| {
            rule_id
                .starts_with("axe/")
                .then(|| rules.get("axe/wcag").copied())
                .flatten()
        });
        let Some(level) = level else {
            return true;
        };

        match level {
            RuleLevel::Off => false,
            RuleLevel::Warn => {
                if finding.severity == Severity::Fail {
                    finding.severity = Severity::Warn;
                }
                true
            }
            RuleLevel::Error => {
                if finding.severity == Severity::Warn {
                    finding.severity = Severity::Fail;
                }
                true
            }
        }
    });
}

pub async fn run_checks(
    config: &Config,
    only: &[String],
    strict: bool,
) -> Result<RunSummary, CheckError> {
    let ctx = CheckContext::new(config.url.clone())?;
    let all_checks = config.enabled_checks();

    if all_checks.is_empty() {
        return Err(CheckError::Config(
            "no checks enabled in sitecheck.toml".to_owned(),
        ));
    }

    let selected: Vec<_> = if only.is_empty() {
        all_checks
    } else {
        for requested in only {
            if !all_checks.iter().any(|c| c.name() == requested) {
                return Err(CheckError::Config(format!(
                    "requested check `{requested}` is not enabled in config"
                )));
            }
        }
        all_checks
            .into_iter()
            .filter(|c| only.iter().any(|name| name == c.name()))
            .collect()
    };

    let mut reports = Vec::with_capacity(selected.len());
    for check in selected {
        let mut report = check.run(&ctx).await?;
        apply_rule_overrides(&mut report, &config.rules);
        reports.push(report);
    }

    let has_failures = reports.iter().any(CheckReport::has_failures);
    let has_warnings = reports.iter().any(CheckReport::has_warnings);
    let passed = !(has_failures || strict && has_warnings);

    Ok(RunSummary {
        url: config.url.to_string(),
        passed,
        reports,
    })
}

#[must_use]
pub fn format_text(summary: &RunSummary) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "sitecheck {}", summary.url);

    let mut pass_count = 0usize;
    let mut warn_count = 0usize;
    let mut fail_count = 0usize;

    for report in &summary.reports {
        let _ = writeln!(out, "\n[{}] {}", report.status().tag(), report.name);
        for finding in &report.findings {
            match finding.severity {
                Severity::Pass => pass_count += 1,
                Severity::Warn => warn_count += 1,
                Severity::Fail => fail_count += 1,
            }
            match (&finding.rule, &finding.detail) {
                (Some(rule), Some(detail)) => {
                    let _ = writeln!(
                        out,
                        "  [{}] {rule} — {}: {detail}",
                        finding.severity.tag(),
                        finding.title
                    );
                }
                (Some(rule), None) => {
                    let _ = writeln!(
                        out,
                        "  [{}] {rule} — {}",
                        finding.severity.tag(),
                        finding.title
                    );
                }
                (None, Some(detail)) => {
                    let _ = writeln!(
                        out,
                        "  [{}] {}: {detail}",
                        finding.severity.tag(),
                        finding.title
                    );
                }
                (None, None) => {
                    let _ = writeln!(out, "  [{}] {}", finding.severity.tag(), finding.title);
                }
            }
            for item in &finding.items {
                let _ = writeln!(out, "    - {item}");
            }
            if let Some(docs_url) = &finding.docs_url {
                let _ = writeln!(out, "    docs: {docs_url}");
            }
        }
    }

    let overall = if summary.passed { "PASSED" } else { "FAILED" };
    let _ = writeln!(
        out,
        "\nResult: {overall} ({pass_count} pass, {warn_count} warn, {fail_count} fail)"
    );
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{RunSummary, apply_rule_overrides, format_text};
    use crate::check::{CheckReport, Finding, Severity};
    use crate::config::RuleLevel;

    #[test]
    fn applies_off_warn_and_error_rule_overrides() {
        let mut report = CheckReport::new(
            "seo",
            vec![
                Finding::warn("apple-touch-icon", Some("missing".to_owned()))
                    .with_rule("seo/apple-touch-icon"),
                Finding::fail("soft 404", Some("returned 200".to_owned()))
                    .with_rule("http/soft-404"),
                Finding::warn("CSP", Some("missing".to_owned())).with_rule("security/csp"),
                Finding::pass("HSTS", Some("max-age=31536000".to_owned()))
                    .with_rule("security/hsts"),
                Finding::pass("untouched", None),
            ],
        );

        let rules = BTreeMap::from([
            ("seo/apple-touch-icon".to_owned(), RuleLevel::Off),
            ("http/soft-404".to_owned(), RuleLevel::Warn),
            ("security/csp".to_owned(), RuleLevel::Error),
            ("security/hsts".to_owned(), RuleLevel::Error),
        ]);

        apply_rule_overrides(&mut report, &rules);

        assert_eq!(report.findings.len(), 4);
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule.as_deref() == Some("seo/apple-touch-icon"))
        );
        assert_eq!(report.findings[0].severity, Severity::Warn);
        assert_eq!(report.findings[1].severity, Severity::Fail);
        assert_eq!(report.findings[2].severity, Severity::Pass);
        assert_eq!(report.findings[3].severity, Severity::Pass);
    }

    #[test]
    fn formats_rule_ids_in_text_output() {
        let summary = RunSummary {
            url: "https://example.com/".to_owned(),
            passed: true,
            reports: vec![CheckReport::new(
                "seo",
                vec![
                    Finding::warn("apple-touch-icon", Some("missing".to_owned()))
                        .with_rule("seo/apple-touch-icon"),
                ],
            )],
        };

        let rendered = format_text(&summary);
        assert!(rendered.contains("[WARN] seo/apple-touch-icon — apple-touch-icon: missing"));
    }

    #[test]
    fn applies_axe_wcag_fallback_override_with_exact_precedence() {
        let mut report = CheckReport::new(
            "axe",
            vec![
                Finding::fail("Images must have alt text", None).with_rule("axe/image-alt"),
                Finding::fail("Color contrast", None).with_rule("axe/color-contrast"),
                Finding::fail("Homepage status", None).with_rule("http/homepage-status"),
            ],
        );

        let warn_rules = BTreeMap::from([
            ("axe/wcag".to_owned(), RuleLevel::Warn),
            ("axe/color-contrast".to_owned(), RuleLevel::Off),
        ]);
        apply_rule_overrides(&mut report, &warn_rules);

        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.findings[0].rule.as_deref(), Some("axe/image-alt"));
        assert_eq!(report.findings[0].severity, Severity::Warn);
        assert_eq!(
            report.findings[1].rule.as_deref(),
            Some("http/homepage-status")
        );
        assert_eq!(report.findings[1].severity, Severity::Fail);

        let off_rules = BTreeMap::from([("axe/wcag".to_owned(), RuleLevel::Off)]);
        apply_rule_overrides(&mut report, &off_rules);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].rule.as_deref(),
            Some("http/homepage-status")
        );
    }
}
