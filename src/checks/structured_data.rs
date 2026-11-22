use std::collections::HashMap;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use crate::check::{
    Check, CheckContext, CheckError, CheckReport, Finding, MAX_HTML_BODY_BYTES, read_body_limited,
};
use crate::checks::http::parse_html_attr;

const DOCS_SITE_NAMES: &str = "https://developers.google.com/search/docs/appearance/site-names";
const DOCS_DEPRECATED_SCHEMA: &str =
    "https://developers.google.com/search/blog/2025/06/simplifying-search-results";

const DEPRECATED_RICH_RESULT_TYPES: &[&str] = &[
    "SearchAction",
    "ClaimReview",
    "CourseInfo",
    "EstimatedSalary",
    "LearningVideo",
    "SpecialAnnouncement",
    "VehicleListing",
    "PracticeProblem",
];

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredDataConfig {
    #[serde(default)]
    pub required_types: Vec<String>,
    #[serde(default = "default_true")]
    pub check_site_name: bool,
    #[serde(default = "default_true")]
    pub check_open_graph: bool,
    #[serde(default = "default_true")]
    pub check_twitter: bool,
    #[serde(default)]
    pub paths: Vec<String>,
}

pub struct StructuredDataCheck {
    config: StructuredDataConfig,
}

impl StructuredDataCheck {
    #[must_use]
    pub const fn new(config: StructuredDataConfig) -> Self {
        Self { config }
    }
}

/// Extracts raw text contents of all `<script type="application/ld+json">` blocks in HTML.
#[must_use]
pub fn extract_json_ld_blocks(html: &str) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let mut blocks = Vec::new();
    let mut cursor = 0usize;

    while let Some(open_rel) = lower[cursor..].find("<script") {
        let tag_start = cursor + open_rel;
        let after_name = tag_start + 7;
        let Some(open_end_rel) = html[after_name..].find('>') else {
            break;
        };
        let open_end = after_name + open_end_rel;
        let open_tag = &html[tag_start..=open_end];
        let content_start = open_end + 1;

        let Some(close_rel) = lower[content_start..].find("</script>") else {
            break;
        };
        let content_end = content_start + close_rel;

        let is_ld_json = parse_html_attr(open_tag, "type").is_some_and(|t| {
            t.split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/ld+json"))
        });

        if is_ld_json {
            let payload = html[content_start..content_end].trim();
            if !payload.is_empty() {
                blocks.push(payload.to_owned());
            }
        }

        cursor = content_end + 9;
    }

    blocks
}

fn collect_types_from_value(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_types_from_value(item, out);
            }
        }
        Value::Object(map) => {
            if let Some(ty) = map.get("@type") {
                match ty {
                    Value::String(s) if !s.trim().is_empty() => out.push(s.trim().to_owned()),
                    Value::Array(arr) => {
                        for entry in arr {
                            if let Some(s) = entry.as_str()
                                && !s.trim().is_empty()
                            {
                                out.push(s.trim().to_owned());
                            }
                        }
                    }
                    _ => {}
                }
            }
            if let Some(graph) = map.get("@graph") {
                collect_types_from_value(graph, out);
            }
        }
        _ => {}
    }
}

/// Parses JSON-LD blocks (supporting objects, arrays, and `@graph`) and returns `(types, errors)`.
#[must_use]
pub fn extract_json_ld_types(blocks: &[String]) -> (Vec<String>, Vec<String>) {
    let mut types = Vec::new();
    let mut errors = Vec::new();

    for (idx, raw) in blocks.iter().enumerate() {
        match serde_json::from_str::<Value>(raw) {
            Ok(value) => collect_types_from_value(&value, &mut types),
            Err(err) => errors.push(format!("block #{}: {err}", idx + 1)),
        }
    }

    (types, errors)
}

fn value_has_type(map: &serde_json::Map<String, Value>, target: &str) -> bool {
    match map.get("@type") {
        Some(Value::String(s)) => s.trim() == target,
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(Value::as_str)
            .any(|s| s.trim() == target),
        _ => false,
    }
}

fn find_website_in_value(value: &Value) -> Option<(String, String)> {
    match value {
        Value::Array(items) => items.iter().find_map(find_website_in_value),
        Value::Object(map) => {
            if value_has_type(map, "WebSite") {
                let name = map
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                let url = map
                    .get("url")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                if let (Some(n), Some(u)) = (name, url) {
                    return Some((n.to_owned(), u.to_owned()));
                }
            }
            map.get("@graph").and_then(find_website_in_value)
        }
        _ => None,
    }
}

/// Checks whether JSON-LD blocks contain `@type: "WebSite"` with non-empty `name` and `url`.
#[must_use]
pub fn find_website_site_name(blocks: &[String]) -> Option<(String, String)> {
    blocks.iter().find_map(|raw| {
        serde_json::from_str::<Value>(raw)
            .ok()
            .and_then(|v| find_website_in_value(&v))
    })
}

fn collect_deprecated_from_value(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_deprecated_from_value(item, out);
            }
        }
        Value::Object(map) => {
            if let Some(ty) = map.get("@type") {
                let candidates: Vec<&str> = match ty {
                    Value::String(s) => vec![s.trim()],
                    Value::Array(arr) => arr
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::trim)
                        .collect(),
                    _ => Vec::new(),
                };
                for candidate in candidates {
                    if DEPRECATED_RICH_RESULT_TYPES.contains(&candidate)
                        && !out.iter().any(|existing| existing == candidate)
                    {
                        out.push(candidate.to_owned());
                    }
                }
            }
            for child in map.values() {
                collect_deprecated_from_value(child, out);
            }
        }
        _ => {}
    }
}

/// Finds retired/deprecated Google Search rich-result `@type` values anywhere in JSON-LD blocks.
#[must_use]
pub fn find_deprecated_types(blocks: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    for raw in blocks {
        if let Ok(value) = serde_json::from_str::<Value>(raw) {
            collect_deprecated_from_value(&value, &mut found);
        }
    }
    found
}

fn check_same_as_entry(entry: &Value, valid_count: &mut usize, invalid: &mut Vec<String>) {
    match entry.as_str() {
        Some(raw) => {
            let trimmed = raw.trim();
            match Url::parse(trimmed) {
                Ok(parsed) if parsed.scheme() == "https" && parsed.host_str().is_some() => {
                    *valid_count += 1;
                }
                _ => invalid.push(format!("`{trimmed}` is not a valid `https://` URL")),
            }
        }
        None => invalid.push(format!("non-string sameAs value: {entry}")),
    }
}

fn collect_same_as_from_value(
    value: &Value,
    saw_same_as: &mut bool,
    valid_count: &mut usize,
    invalid: &mut Vec<String>,
) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_same_as_from_value(item, saw_same_as, valid_count, invalid);
            }
        }
        Value::Object(map) => {
            if let Some(same_as) = map.get("sameAs") {
                *saw_same_as = true;
                match same_as {
                    Value::Array(entries) => {
                        for entry in entries {
                            check_same_as_entry(entry, valid_count, invalid);
                        }
                    }
                    single => check_same_as_entry(single, valid_count, invalid),
                }
            }
            for (k, child) in map {
                if k != "sameAs" {
                    collect_same_as_from_value(child, saw_same_as, valid_count, invalid);
                }
            }
        }
        _ => {}
    }
}

/// Validates all `sameAs` entries across JSON-LD blocks. Returns `None` if no `sameAs` field exists.
#[must_use]
pub fn validate_same_as_urls(blocks: &[String]) -> Option<(usize, Vec<String>)> {
    let mut saw_same_as = false;
    let mut valid_count = 0usize;
    let mut invalid = Vec::new();

    for raw in blocks {
        if let Ok(value) = serde_json::from_str::<Value>(raw) {
            collect_same_as_from_value(&value, &mut saw_same_as, &mut valid_count, &mut invalid);
        }
    }

    saw_same_as.then_some((valid_count, invalid))
}

/// Extracts `<meta>` tags as lowercase key (`property` or `name`) -> `content`.
#[must_use]
pub fn extract_meta_tags(html: &str) -> HashMap<String, String> {
    let lower = html.to_ascii_lowercase();
    let mut tags = HashMap::new();
    let mut cursor = 0usize;

    while let Some(pos) = lower[cursor..].find("<meta") {
        let tag_start = cursor + pos;
        let after_name = tag_start + 5;
        if let Some(next_ch) = html[after_name..].chars().next()
            && !next_ch.is_whitespace()
            && next_ch != '>'
            && next_ch != '/'
        {
            cursor = after_name;
            continue;
        }
        let Some(end_rel) = html[after_name..].find('>') else {
            break;
        };
        let tag = &html[tag_start..=after_name + end_rel];
        let key = parse_html_attr(tag, "property").or_else(|| parse_html_attr(tag, "name"));
        if let (Some(k), Some(v)) = (key, parse_html_attr(tag, "content")) {
            let trimmed_key = k.trim().to_ascii_lowercase();
            let trimmed_val = v.trim();
            if !trimmed_key.is_empty() && !trimmed_val.is_empty() {
                tags.insert(trimmed_key, trimmed_val.to_owned());
            }
        }
        cursor = after_name + end_rel + 1;
    }

    tags
}

fn evaluate_social_meta(
    prefix: &str,
    meta: &HashMap<String, String>,
    check_open_graph: bool,
    check_twitter: bool,
    findings: &mut Vec<Finding>,
) {
    if check_open_graph {
        let required_og = ["og:title", "og:description"];
        let recommended_og = ["og:image", "og:url"];
        let missing_required: Vec<&str> = required_og
            .into_iter()
            .filter(|k| !meta.contains_key(*k))
            .collect();
        let missing_recommended: Vec<&str> = recommended_og
            .into_iter()
            .filter(|k| !meta.contains_key(*k))
            .collect();

        if !missing_required.is_empty() {
            findings.push(
                Finding::fail(
                    format!("{prefix}Open Graph"),
                    Some(format!("missing {}", missing_required.join(", "))),
                )
                .with_rule("schema/open-graph"),
            );
        } else if !missing_recommended.is_empty() {
            findings.push(
                Finding::warn(
                    format!("{prefix}Open Graph"),
                    Some(format!(
                        "missing recommended {}",
                        missing_recommended.join(", ")
                    )),
                )
                .with_rule("schema/open-graph"),
            );
        } else {
            findings.push(
                Finding::pass(
                    format!("{prefix}Open Graph"),
                    Some("og:title, og:description, og:image, og:url present".to_owned()),
                )
                .with_rule("schema/open-graph"),
            );
        }
    }

    if check_twitter {
        if meta.contains_key("twitter:card") {
            let missing_opt: Vec<&str> = ["twitter:title", "twitter:description"]
                .into_iter()
                .filter(|k| !meta.contains_key(*k))
                .collect();
            if missing_opt.is_empty() {
                findings.push(
                    Finding::pass(
                        format!("{prefix}Twitter Card"),
                        Some("twitter:card, twitter:title, twitter:description present".to_owned()),
                    )
                    .with_rule("schema/twitter-card"),
                );
            } else {
                findings.push(
                    Finding::warn(
                        format!("{prefix}Twitter Card"),
                        Some(format!(
                            "twitter:card present; missing {}",
                            missing_opt.join(", ")
                        )),
                    )
                    .with_rule("schema/twitter-card"),
                );
            }
        } else {
            findings.push(
                Finding::fail(
                    format!("{prefix}Twitter Card"),
                    Some("missing twitter:card".to_owned()),
                )
                .with_rule("schema/twitter-card"),
            );
        }
    }
}

fn evaluate_json_ld_hygiene(prefix: &str, blocks: &[String], findings: &mut Vec<Finding>) {
    let deprecated = find_deprecated_types(blocks);
    if !deprecated.is_empty() {
        findings.push(
            Finding::warn(
                format!("{prefix}deprecated rich-result schema"),
                Some(format!(
                    "retired Google Search type(s): {}",
                    deprecated.join(", ")
                )),
            )
            .with_rule("schema/deprecated-types")
            .with_docs(DOCS_DEPRECATED_SCHEMA),
        );
    }

    if let Some((valid_count, invalid)) = validate_same_as_urls(blocks) {
        if invalid.is_empty() {
            findings.push(
                Finding::pass(
                    format!("{prefix}JSON-LD sameAs"),
                    Some(format!("{valid_count} valid `https://` URL(s)")),
                )
                .with_rule("schema/same-as"),
            );
        } else {
            findings.push(
                Finding::fail(
                    format!("{prefix}JSON-LD sameAs"),
                    Some(format!("{} invalid `sameAs` URL(s)", invalid.len())),
                )
                .with_rule("schema/same-as")
                .with_items(invalid),
            );
        }
    }
}

fn evaluate_json_ld(
    prefix: &str,
    path: &str,
    blocks: &[String],
    config: &StructuredDataConfig,
    findings: &mut Vec<Finding>,
) {
    let (types, parse_errors) = extract_json_ld_types(blocks);
    for err in parse_errors {
        findings.push(
            Finding::fail(format!("{prefix}JSON-LD syntax"), Some(err))
                .with_rule("schema/json-ld-syntax"),
        );
    }

    if blocks.is_empty() {
        if config.required_types.is_empty() {
            findings.push(
                Finding::warn(
                    format!("{prefix}JSON-LD"),
                    Some("no `<script type=\"application/ld+json\">` blocks found".to_owned()),
                )
                .with_rule("schema/json-ld-present"),
            );
        } else {
            findings.push(
                Finding::fail(
                    format!("{prefix}JSON-LD"),
                    Some(format!(
                        "no JSON-LD blocks found (required: {})",
                        config.required_types.join(", ")
                    )),
                )
                .with_rule("schema/json-ld-present"),
            );
        }
    } else {
        findings.push(
            Finding::pass(
                format!("{prefix}JSON-LD"),
                Some(format!(
                    "{} block(s), @type: [{}]",
                    blocks.len(),
                    types.join(", ")
                )),
            )
            .with_rule("schema/json-ld-present"),
        );

        for required in &config.required_types {
            if !types.iter().any(|found| found == required) {
                findings.push(
                    Finding::fail(
                        format!("{prefix}JSON-LD @type {required}"),
                        Some(format!("not found (present: [{}])", types.join(", "))),
                    )
                    .with_rule("schema/required-type"),
                );
            }
        }
    }

    if config.check_site_name && path == "/" {
        match find_website_site_name(blocks) {
            Some((name, site_url)) => findings.push(
                Finding::pass("WebSite site name", Some(format!("{name} ({site_url})")))
                    .with_rule("schema/website-site-name"),
            ),
            None => findings.push(
                Finding::warn(
                    "WebSite site name",
                    Some(
                        "homepage JSON-LD missing `@type: \"WebSite\"` with non-empty `name` and `url`"
                            .to_owned(),
                    ),
                )
                .with_rule("schema/website-site-name")
                .with_docs(DOCS_SITE_NAMES),
            ),
        }
    }

    evaluate_json_ld_hygiene(prefix, blocks, findings);
}

#[async_trait]
impl Check for StructuredDataCheck {
    fn name(&self) -> &'static str {
        "structured_data"
    }

    async fn run(&self, ctx: &CheckContext) -> Result<CheckReport, CheckError> {
        let paths: Vec<&str> = if self.config.paths.is_empty() {
            vec!["/"]
        } else {
            self.config.paths.iter().map(String::as_str).collect()
        };

        let mut findings = Vec::new();
        let show_prefix = paths.len() > 1;

        for path in paths {
            let url = ctx.base_url.join(path)?;
            let prefix = if show_prefix {
                format!("{path} ")
            } else {
                String::new()
            };

            let resp = ctx.client.get(url.clone()).send().await?;
            if !resp.status().is_success() {
                findings.push(
                    Finding::fail(
                        format!("{prefix}fetch"),
                        Some(format!("HTTP {} for {url}", resp.status())),
                    )
                    .with_rule("schema/fetch"),
                );
                continue;
            }
            let html = read_body_limited(resp, MAX_HTML_BODY_BYTES).await?;

            let blocks = extract_json_ld_blocks(&html);
            evaluate_json_ld(&prefix, path, &blocks, &self.config, &mut findings);

            let meta = extract_meta_tags(&html);
            evaluate_social_meta(
                &prefix,
                &meta,
                self.config.check_open_graph,
                self.config.check_twitter,
                &mut findings,
            );
        }

        Ok(CheckReport::new(self.name(), findings))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        extract_json_ld_blocks, extract_json_ld_types, extract_meta_tags, find_deprecated_types,
        find_website_site_name, validate_same_as_urls,
    };

    #[test]
    fn extracts_json_ld_from_graph_and_arrays() {
        let html = r#"
        <html><head>
        <script type="application/ld+json">
        {
          "@context": "https://schema.org",
          "@graph": [
            { "@type": "Organization", "name": "Example" },
            { "@type": ["WebSite", "CreativeWork"], "url": "https://example.com/" }
          ]
        }
        </script>
        <script type="application/ld+json">
        [
          { "@type": "BreadcrumbList" }
        ]
        </script>
        </head></html>
        "#;

        let blocks = extract_json_ld_blocks(html);
        assert_eq!(blocks.len(), 2);

        let (types, errors) = extract_json_ld_types(&blocks);
        assert_eq!(errors, Vec::<String>::new());
        assert_eq!(
            types,
            vec!["Organization", "WebSite", "CreativeWork", "BreadcrumbList"]
        );
    }

    #[test]
    fn reports_invalid_json_ld_block() {
        let blocks = vec!["{ invalid json".to_owned()];
        let (types, errors) = extract_json_ld_types(&blocks);
        assert_eq!(types, Vec::<String>::new());
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn extracts_open_graph_and_twitter_meta_tags() {
        let html = r#"
        <meta property="og:title" content="Example Title" />
        <meta content="Summary text" property="og:description">
        <meta name="twitter:card" content="summary_large_image">
        "#;
        let meta = extract_meta_tags(html);
        assert_eq!(
            meta.get("og:title").map(String::as_str),
            Some("Example Title")
        );
        assert_eq!(
            meta.get("og:description").map(String::as_str),
            Some("Summary text")
        );
        assert_eq!(
            meta.get("twitter:card").map(String::as_str),
            Some("summary_large_image")
        );
    }

    #[test]
    fn validates_website_site_name_in_graph_or_object() {
        let valid = vec![
            r#"{
                "@context": "https://schema.org",
                "@graph": [
                    { "@type": "WebSite", "name": "Example", "url": "https://example.com/" }
                ]
            }"#
            .to_owned(),
        ];
        assert_eq!(
            find_website_site_name(&valid),
            Some(("Example".to_owned(), "https://example.com/".to_owned()))
        );

        let missing_name = vec![
            r#"{ "@context": "https://schema.org", "@type": "WebSite", "url": "https://example.com/" }"#
                .to_owned(),
        ];
        assert_eq!(find_website_site_name(&missing_name), None);
    }

    #[test]
    fn detects_deprecated_google_rich_result_types() {
        let blocks = vec![
            r#"{
                "@context": "https://schema.org",
                "@type": "WebSite",
                "name": "Example",
                "url": "https://example.com/",
                "potentialAction": { "@type": "SearchAction", "target": "https://example.com/?q={q}" }
            }"#
            .to_owned(),
            r#"{ "@context": "https://schema.org", "@type": "ClaimReview" }"#.to_owned(),
        ];
        assert_eq!(
            find_deprecated_types(&blocks),
            vec!["SearchAction", "ClaimReview"]
        );

        let clean = vec![r#"{ "@type": "Organization", "name": "Example" }"#.to_owned()];
        assert_eq!(find_deprecated_types(&clean), Vec::<String>::new());
    }

    #[test]
    fn validates_json_ld_same_as_urls() {
        let no_same_as = vec![r#"{ "@type": "Organization", "name": "Example" }"#.to_owned()];
        assert_eq!(validate_same_as_urls(&no_same_as), None);

        let valid = vec![
            r#"{
                "@context": "https://schema.org",
                "@type": "Organization",
                "sameAs": ["https://github.com/example", "https://x.com/example"]
            }"#
            .to_owned(),
        ];
        assert_eq!(validate_same_as_urls(&valid), Some((2, Vec::new())));

        let invalid = vec![
            r#"{
                "@context": "https://schema.org",
                "@graph": [
                    { "@type": "Organization", "sameAs": ["http://insecure.example.com", "not-a-url", "https://github.com/ok"] }
                ]
            }"#
            .to_owned(),
        ];
        let (valid_count, errors) =
            validate_same_as_urls(&invalid).expect("sameAs should be detected");
        assert_eq!(valid_count, 1);
        assert_eq!(errors.len(), 2);
    }
}
