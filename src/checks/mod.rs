pub mod ai;
pub mod axe;
pub mod http;
pub mod indexnow;
pub mod lighthouse;
pub mod pagespeed;
pub mod search_console;
pub mod security_headers;
pub mod seo;
pub mod structured_data;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::check::{CheckError, Finding, Severity};

const MAX_SURFACED_AUDITS: usize = 12;
const MAX_AUDIT_ITEMS: usize = 5;

const IGNORED_INFORMATIVE_AUDITS: &[&str] = &[
    "network-requests",
    "main-thread-tasks",
    "diagnostics",
    "metrics",
    "screenshot-thumbnails",
    "final-screenshot",
    "script-treemap-data",
];

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinScores {
    pub performance: Option<u8>,
    pub accessibility: Option<u8>,
    pub best_practices: Option<u8>,
    pub seo: Option<u8>,
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn score_to_percent(score: f64) -> u8 {
    (score.clamp(0.0, 1.0) * 100.0).round() as u8
}

fn compact_text(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn strip_markdown_links(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(open_bracket) = rest.find('[') {
        out.push_str(&rest[..open_bracket]);
        let after_bracket = &rest[open_bracket + 1..];
        if let Some(mid) = after_bracket.find("](") {
            let label = &after_bracket[..mid];
            let after_mid = &after_bracket[mid + 2..];
            if let Some(close_paren) = after_mid.find(')') {
                out.push_str(label);
                rest = &after_mid[close_paren + 1..];
                continue;
            }
        }
        out.push('[');
        rest = after_bracket;
    }
    out.push_str(rest);
    out
}

fn summarize_description(description: &str) -> Option<String> {
    let plain = compact_text(&strip_markdown_links(description));
    if plain.is_empty() {
        return None;
    }
    let sentence_end = [". ", "? ", "! "]
        .into_iter()
        .filter_map(|delim| plain.find(delim))
        .min();
    let first = sentence_end.map_or(plain.as_str(), |idx| &plain[..=idx]);
    let trimmed = first.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn extract_docs_url(description: &str) -> Option<String> {
    let mut rest = description;
    while let Some(open) = rest.find("](") {
        let after = &rest[open + 2..];
        let Some(close) = after.find(')') else {
            break;
        };
        let url = after[..close].trim();
        if url.starts_with("https://") || url.starts_with("http://") {
            return Some(url.to_owned());
        }
        rest = &after[close + 1..];
    }
    None
}

fn non_empty_str(obj: &Map<String, Value>, key: &str) -> Option<String> {
    obj.get(key)
        .and_then(Value::as_str)
        .map(compact_text)
        .filter(|s| !s.is_empty())
}

fn format_audit_item(item: &Value) -> Option<String> {
    let obj = item.as_object()?;

    if let Some(node) = obj.get("node").and_then(Value::as_object) {
        let selector = non_empty_str(node, "selector");
        let explanation = non_empty_str(node, "explanation");
        let snippet = non_empty_str(node, "snippet");
        return match (selector, explanation, snippet) {
            (Some(sel), Some(exp), _) => Some(format!("{sel} — {exp}")),
            (Some(sel), None, Some(snip)) => Some(format!("{sel} ({snip})")),
            (Some(sel), None, None) => Some(sel),
            (None, Some(exp), _) => Some(exp),
            (None, None, Some(snip)) => Some(snip),
            (None, None, None) => None,
        };
    }

    if let Some(url) = non_empty_str(obj, "url") {
        let mut metrics = Vec::new();
        if let Some(bytes) = obj.get("wastedBytes").and_then(Value::as_f64)
            && bytes > 0.0
        {
            metrics.push(format!("{:.1} KiB wasted", bytes / 1024.0));
        }
        if let Some(ms) = obj.get("wastedMs").and_then(Value::as_f64)
            && ms > 0.0
        {
            metrics.push(format!("{ms:.0} ms wasted"));
        }
        if let Some(bytes) = obj.get("totalBytes").and_then(Value::as_f64)
            && bytes > 0.0
        {
            metrics.push(format!("{:.1} KiB total", bytes / 1024.0));
        }
        return if metrics.is_empty() {
            Some(url)
        } else {
            Some(format!("{url} ({})", metrics.join(", ")))
        };
    }

    let severity = non_empty_str(obj, "severity");
    let directive = non_empty_str(obj, "directive");
    let description = non_empty_str(obj, "description");
    let body = match (directive, description) {
        (Some(dir), Some(desc)) => format!("{dir}: {desc}"),
        (Some(dir), None) => dir,
        (None, Some(desc)) => desc,
        (None, None) => return None,
    };
    Some(match severity {
        Some(sev) => format!("[{sev}] {body}"),
        None => body,
    })
}

fn extract_audit_items(audit: &Value) -> Vec<String> {
    audit
        .get("details")
        .and_then(|d| d.get("items"))
        .and_then(Value::as_array)
        .map_or_default(|items| {
            items
                .iter()
                .filter_map(format_audit_item)
                .take(MAX_AUDIT_ITEMS)
                .collect()
        })
}

fn collect_audit_findings(audits: &Map<String, Value>, strategy_label: &str) -> Vec<Finding> {
    let mut ranked: Vec<(u8, u8, String, Finding)> = audits
        .iter()
        .filter_map(|(key, audit)| {
            let id = audit.get("id").and_then(Value::as_str).unwrap_or(key);
            let mode = audit
                .get("scoreDisplayMode")
                .and_then(Value::as_str)
                .unwrap_or("numeric");
            if matches!(mode, "notApplicable" | "manual" | "error") {
                return None;
            }

            let score = audit.get("score").and_then(Value::as_f64);
            let is_insight = matches!(mode, "informative" | "metricSavings");
            let items = extract_audit_items(audit);
            let display = audit
                .get("displayValue")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let description = audit.get("description").and_then(Value::as_str);
            let summary = description.and_then(summarize_description);

            let (severity, rank_group, pct, detail) = if is_insight {
                if IGNORED_INFORMATIVE_AUDITS.contains(&id)
                    || items.is_empty()
                    || score.is_some_and(|s| s >= 1.0)
                {
                    return None;
                }
                let pct = score.map_or(100, score_to_percent);
                let base = match (score, display) {
                    (Some(_), Some(val)) => Some(format!("score {pct}/100 ({val})")),
                    (None, Some(val)) => Some(val),
                    (Some(_), None) => Some(format!("score {pct}/100")),
                    (None, None) => None,
                };
                let detail = match (base, summary) {
                    (Some(b), Some(s)) => format!("{b} — {s}"),
                    (Some(b), None) => b,
                    (None, Some(s)) => s,
                    (None, None) => "insight".to_owned(),
                };
                (Severity::Warn, 2u8, pct, detail)
            } else {
                let s = score?;
                if s >= 1.0 {
                    return None;
                }
                let pct = score_to_percent(s);
                let (severity, rank_group) = if s == 0.0 {
                    (Severity::Fail, 0u8)
                } else {
                    (Severity::Warn, 1u8)
                };
                let base = match display {
                    Some(val) => format!("score {pct}/100 ({val})"),
                    None => format!("score {pct}/100"),
                };
                let detail = match summary {
                    Some(s) => format!("{base} — {s}"),
                    None => base,
                };
                (severity, rank_group, pct, detail)
            };

            let audit_title = audit
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or(id)
                .to_owned();
            let title = format!("{strategy_label} audit: {audit_title}");
            let mut finding = match severity {
                Severity::Fail => Finding::fail(title, Some(detail)),
                Severity::Warn => Finding::warn(title, Some(detail)),
                Severity::Pass => Finding::pass(title, Some(detail)),
            };
            if let Some(docs) = description.and_then(extract_docs_url) {
                finding = finding.with_docs(docs);
            }
            if !items.is_empty() {
                finding = finding.with_items(items);
            }
            Some((rank_group, pct, audit_title, finding))
        })
        .collect();

    ranked.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.cmp(&b.2))
    });
    ranked
        .into_iter()
        .take(MAX_SURFACED_AUDITS)
        .map(|(_, _, _, finding)| finding)
        .collect()
}

/// Shared Lighthouse JSON result parser used by both `pagespeed` and `lighthouse` checks.
pub fn parse_lighthouse_result(
    lhr: &Value,
    strategy_label: &str,
    min_scores: &MinScores,
) -> Result<Vec<Finding>, CheckError> {
    let categories = lhr
        .get("categories")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CheckError::Other(format!(
                "Lighthouse JSON for {strategy_label} is missing `categories`"
            ))
        })?;

    let mut findings = Vec::new();
    let specs = [
        ("performance", "Performance", min_scores.performance),
        ("accessibility", "Accessibility", min_scores.accessibility),
        (
            "best-practices",
            "Best Practices",
            min_scores.best_practices,
        ),
        ("seo", "SEO", min_scores.seo),
    ];

    for (key, label, min_threshold) in specs {
        let Some(score) = categories
            .get(key)
            .and_then(|c| c.get("score"))
            .and_then(Value::as_f64)
        else {
            if let Some(min) = min_threshold {
                findings.push(Finding::fail(
                    format!("{strategy_label} {label}"),
                    Some(format!("score missing (minimum {min})")),
                ));
            }
            continue;
        };

        let pct = score_to_percent(score);
        let title = format!("{strategy_label} {label}");
        match min_threshold {
            Some(min) if pct < min => findings.push(Finding::fail(
                title,
                Some(format!("{pct}/100 (minimum {min})")),
            )),
            Some(min) => findings.push(Finding::pass(
                title,
                Some(format!("{pct}/100 (minimum {min})")),
            )),
            None if pct < 90 => findings.push(Finding::warn(title, Some(format!("{pct}/100")))),
            None => findings.push(Finding::pass(title, Some(format!("{pct}/100")))),
        }
    }

    if let Some(audits) = lhr.get("audits").and_then(Value::as_object) {
        findings.extend(collect_audit_findings(audits, strategy_label));
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{MinScores, parse_lighthouse_result};
    use crate::check::Severity;

    #[test]
    fn parses_lighthouse_categories_and_failing_audits() {
        let lhr = json!({
            "categories": {
                "performance": { "score": 0.82 },
                "accessibility": { "score": 0.98 },
                "best-practices": { "score": 1.0 },
                "seo": { "score": 0.95 }
            },
            "audits": {
                "largest-contentful-paint": {
                    "id": "largest-contentful-paint",
                    "title": "Largest Contentful Paint",
                    "score": 0.45,
                    "scoreDisplayMode": "numeric",
                    "displayValue": "3.2 s"
                },
                "document-title": {
                    "id": "document-title",
                    "title": "Document has a title",
                    "score": 1.0,
                    "scoreDisplayMode": "binary"
                },
                "diagnostics": {
                    "id": "diagnostics",
                    "title": "Diagnostics",
                    "score": 0.0,
                    "scoreDisplayMode": "informative"
                }
            }
        });

        let mins = MinScores {
            performance: Some(90),
            accessibility: Some(95),
            best_practices: Some(95),
            seo: Some(95),
        };

        let findings = parse_lighthouse_result(&lhr, "mobile", &mins)
            .expect("valid lighthouse JSON should parse");

        assert!(
            findings
                .iter()
                .any(|f| f.title == "mobile Performance" && f.severity == Severity::Fail)
        );
        assert!(
            findings
                .iter()
                .any(|f| f.title == "mobile Accessibility" && f.severity == Severity::Pass)
        );
        assert!(
            findings
                .iter()
                .any(|f| f.title == "mobile SEO" && f.severity == Severity::Pass)
        );
        assert!(findings.iter().any(|f| {
            f.title == "mobile audit: Largest Contentful Paint"
                && f.severity == Severity::Warn
                && f.detail.as_deref() == Some("score 45/100 (3.2 s)")
        }));
        assert!(
            !findings.iter().any(
                |f| f.title.contains("Diagnostics") || f.title.contains("Document has a title")
            )
        );
    }

    #[test]
    fn extracts_dom_network_items_and_docs_url() {
        let lhr = json!({
            "categories": {
                "performance": { "score": 0.92 },
                "accessibility": { "score": 0.88 }
            },
            "audits": {
                "color-contrast": {
                    "id": "color-contrast",
                    "title": "Background and foreground colors do not have a sufficient contrast ratio.",
                    "description": "Low-contrast text is difficult to read. [Learn more](https://dequeuniversity.com/rules/axe/4.10/color-contrast).",
                    "score": 0.0,
                    "scoreDisplayMode": "binary",
                    "details": {
                        "items": [{
                            "node": {
                                "selector": "a.cta-button",
                                "snippet": "<a class=\"cta-button\">Hire us</a>",
                                "explanation": "Element has insufficient color contrast of 3.1."
                            }
                        }]
                    }
                },
                "uses-optimized-images": {
                    "id": "uses-optimized-images",
                    "title": "Efficiently encode images",
                    "description": "Use [modern formats](https://web.dev/uses-webp-images/) to load images faster. [Learn more](https://developer.chrome.com/docs/lighthouse/performance/uses-optimized-images/).",
                    "score": 0.6,
                    "scoreDisplayMode": "numeric",
                    "displayValue": "Potential savings of 120 KiB",
                    "details": {
                        "items": [{
                            "url": "https://example.com/hero.jpg",
                            "wastedBytes": 122_880,
                            "totalBytes": 204_800
                        }]
                    }
                }
            }
        });

        let findings = parse_lighthouse_result(&lhr, "desktop", &MinScores::default())
            .expect("valid lighthouse JSON should parse");

        let contrast = findings
            .iter()
            .find(|f| f.title.contains("sufficient contrast ratio"))
            .expect("color-contrast finding should be present");
        assert_eq!(contrast.severity, Severity::Fail);
        assert_eq!(
            contrast.detail.as_deref(),
            Some("score 0/100 — Low-contrast text is difficult to read.")
        );
        assert_eq!(
            contrast.docs_url.as_deref(),
            Some("https://dequeuniversity.com/rules/axe/4.10/color-contrast")
        );
        assert_eq!(
            contrast.items,
            vec!["a.cta-button — Element has insufficient color contrast of 3.1."]
        );

        let images = findings
            .iter()
            .find(|f| f.title.contains("Efficiently encode images"))
            .expect("uses-optimized-images finding should be present");
        assert_eq!(images.severity, Severity::Warn);
        assert_eq!(
            images.detail.as_deref(),
            Some(
                "score 60/100 (Potential savings of 120 KiB) — Use modern formats to load images faster."
            )
        );
        assert_eq!(
            images.docs_url.as_deref(),
            Some("https://web.dev/uses-webp-images/")
        );
        assert_eq!(
            images.items,
            vec!["https://example.com/hero.jpg (120.0 KiB wasted, 200.0 KiB total)"]
        );
    }

    #[test]
    fn surfaces_actionable_insights_and_skips_neutral_metadata() {
        let lhr = json!({
            "categories": {
                "best-practices": { "score": 1.0 }
            },
            "audits": {
                "csp-xss": {
                    "id": "csp-xss",
                    "title": "Ensure CSP is effective against XSS attacks",
                    "description": "A strong CSP reduces XSS risk. [Learn more](https://developer.chrome.com/docs/lighthouse/best-practices/csp-xss/).",
                    "score": null,
                    "scoreDisplayMode": "informative",
                    "details": {
                        "items": [{
                            "severity": "High",
                            "directive": "script-src",
                            "description": "No CSP found in enforcement mode"
                        }]
                    }
                },
                "network-requests": {
                    "id": "network-requests",
                    "title": "Network Requests",
                    "score": null,
                    "scoreDisplayMode": "informative",
                    "details": {
                        "items": [{ "url": "https://example.com/" }]
                    }
                }
            }
        });

        let findings = parse_lighthouse_result(&lhr, "desktop", &MinScores::default())
            .expect("valid lighthouse JSON should parse");

        let csp = findings
            .iter()
            .find(|f| f.title.contains("Ensure CSP is effective"))
            .expect("informative csp-xss insight should be surfaced");
        assert_eq!(csp.severity, Severity::Warn);
        assert_eq!(
            csp.detail.as_deref(),
            Some("A strong CSP reduces XSS risk.")
        );
        assert_eq!(
            csp.items,
            vec!["[High] script-src: No CSP found in enforcement mode"]
        );
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("Network Requests")),
            "neutral metadata audits should remain excluded"
        );
    }
}
