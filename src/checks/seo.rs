use std::collections::BTreeMap;

use async_trait::async_trait;
use reqwest::StatusCode;
use reqwest::header::CONTENT_TYPE;
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use crate::check::{Check, CheckContext, CheckError, CheckReport, Finding};
use crate::checks::http::{
    extract_all_canonicals, extract_head, extract_robots_directives, extract_sitemap_locs,
    is_same_origin, parse_html_attr, urls_match,
};
use crate::checks::structured_data::extract_meta_tags;

const DOCS_CANONICAL: &str =
    "https://developers.google.com/search/docs/crawling-indexing/consolidate-duplicate-urls";
const DOCS_TITLE_LINK: &str = "https://developers.google.com/search/docs/appearance/title-link";
const DOCS_SNIPPET: &str = "https://developers.google.com/search/docs/appearance/snippet";
const DOCS_FAVICON: &str = "https://developers.google.com/search/docs/appearance/favicon-in-search";
const DOCS_ROBOTS_META: &str =
    "https://developers.google.com/search/docs/crawling-indexing/robots-meta-tag";

const fn default_true() -> bool {
    true
}

const fn default_max_sitemap_urls() -> usize {
    15
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeoConfig {
    #[serde(default = "default_true")]
    pub check_favicon: bool,
    #[serde(default = "default_max_sitemap_urls")]
    pub max_sitemap_urls: usize,
}

impl Default for SeoConfig {
    fn default() -> Self {
        Self {
            check_favicon: true,
            max_sitemap_urls: default_max_sitemap_urls(),
        }
    }
}

pub struct SeoCheck {
    config: SeoConfig,
}

impl SeoCheck {
    #[must_use]
    pub const fn new(config: SeoConfig) -> Self {
        Self { config }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaviconLink {
    pub href: String,
    pub mime_type: Option<String>,
}

impl FaviconLink {
    #[must_use]
    pub fn is_svg(&self) -> bool {
        if self
            .mime_type
            .as_deref()
            .is_some_and(|m| m.eq_ignore_ascii_case("image/svg+xml"))
        {
            return true;
        }
        let path_part = self
            .href
            .split(['?', '#'])
            .next()
            .unwrap_or(&self.href)
            .trim();
        path_part
            .rsplit_once('.')
            .is_some_and(|(_, ext)| ext.eq_ignore_ascii_case("svg"))
    }
}

/// Extracts `<title>...</title>` text (collapsed and trimmed).
#[must_use]
pub fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let mut cursor = 0usize;

    while let Some(pos) = lower[cursor..].find("<title") {
        let tag_start = cursor + pos;
        let after_name = tag_start + 6;
        if let Some(next_ch) = html[after_name..].chars().next()
            && !next_ch.is_whitespace()
            && next_ch != '>'
        {
            cursor = after_name;
            continue;
        }
        let open_end = after_name + html[after_name..].find('>')?;
        let content_start = open_end + 1;
        let close_rel = lower[content_start..].find("</title>")?;
        let text = html[content_start..content_start + close_rel]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        return (!text.is_empty()).then_some(text);
    }

    None
}

/// Extracts the `lang` attribute from the `<html ...>` opening tag.
#[must_use]
pub fn extract_html_lang(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let mut cursor = 0usize;

    while let Some(pos) = lower[cursor..].find("<html") {
        let tag_start = cursor + pos;
        let after_name = tag_start + 5;
        if let Some(next_ch) = html[after_name..].chars().next()
            && !next_ch.is_whitespace()
            && next_ch != '>'
        {
            cursor = after_name;
            continue;
        }
        let end_rel = html[after_name..].find('>')?;
        let tag = &html[tag_start..=after_name + end_rel];
        return parse_html_attr(tag, "lang")
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty());
    }

    None
}

/// Extracts `<link rel="icon">` (including `rel="shortcut icon"`) declarations from HTML.
#[must_use]
pub fn extract_favicon_links(html: &str) -> Vec<FaviconLink> {
    let lower = html.to_ascii_lowercase();
    let mut links = Vec::new();
    let mut cursor = 0usize;

    while let Some(pos) = lower[cursor..].find("<link") {
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
        let is_icon = parse_html_attr(tag, "rel").is_some_and(|rel| {
            rel.split_whitespace()
                .any(|tok| tok.eq_ignore_ascii_case("icon"))
        });
        if is_icon && let Some(href) = parse_html_attr(tag, "href") {
            let trimmed = href.trim();
            if !trimmed.is_empty() {
                let mime_type = parse_html_attr(tag, "type")
                    .map(|t| t.trim().to_owned())
                    .filter(|t| !t.is_empty());
                links.push(FaviconLink {
                    href: trimmed.to_owned(),
                    mime_type,
                });
            }
        }
        cursor = after_name + end_rel + 1;
    }

    links
}

/// Returns `true` when at least one favicon link is declared and all of them are SVG-only.
#[must_use]
pub fn has_only_svg_favicon(links: &[FaviconLink]) -> bool {
    !links.is_empty() && links.iter().all(FaviconLink::is_svg)
}

/// Extracts the first `<link rel="apple-touch-icon" href="...">` value from HTML.
#[must_use]
pub fn extract_apple_touch_icon_href(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let mut precomposed: Option<String> = None;
    let mut cursor = 0usize;

    while let Some(pos) = lower[cursor..].find("<link") {
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
        if let Some(rel) = parse_html_attr(tag, "rel")
            && let Some(href) = parse_html_attr(tag, "href")
        {
            let trimmed = href.trim();
            if !trimmed.is_empty() {
                let mut exact = false;
                let mut fallback = false;
                for tok in rel.split_whitespace() {
                    if tok.eq_ignore_ascii_case("apple-touch-icon") {
                        exact = true;
                    } else if tok.eq_ignore_ascii_case("apple-touch-icon-precomposed") {
                        fallback = true;
                    }
                }
                if exact {
                    return Some(trimmed.to_owned());
                }
                if fallback && precomposed.is_none() {
                    precomposed = Some(trimmed.to_owned());
                }
            }
        }
        cursor = after_name + end_rel + 1;
    }

    precomposed
}

/// Extracts `<link rel="manifest" href="...">` declared inside `<head>`.
#[must_use]
pub fn extract_manifest_href(html: &str) -> Option<String> {
    let head = extract_head(html)?;
    let lower = head.to_ascii_lowercase();
    let mut cursor = 0usize;

    while let Some(pos) = lower[cursor..].find("<link") {
        let tag_start = cursor + pos;
        let after_name = tag_start + 5;
        if let Some(next_ch) = head[after_name..].chars().next()
            && !next_ch.is_whitespace()
            && next_ch != '>'
            && next_ch != '/'
        {
            cursor = after_name;
            continue;
        }
        let Some(end_rel) = head[after_name..].find('>') else {
            break;
        };
        let tag = &head[tag_start..=after_name + end_rel];
        let is_manifest = parse_html_attr(tag, "rel").is_some_and(|rel| {
            rel.split_whitespace()
                .any(|tok| tok.eq_ignore_ascii_case("manifest"))
        });
        if is_manifest && let Some(href) = parse_html_attr(tag, "href") {
            let trimmed = href.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_owned());
            }
        }
        cursor = after_name + end_rel + 1;
    }

    None
}

/// Validates a web app manifest JSON payload for non-empty `name` or `short_name`.
pub fn validate_web_manifest_json(body: &str) -> Result<String, String> {
    let value: Value =
        serde_json::from_str(body).map_err(|err| format!("invalid manifest JSON: {err}"))?;
    let Some(obj) = value.as_object() else {
        return Err("manifest JSON must be an object".to_owned());
    };
    let name = obj
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let short_name = obj
        .get("short_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());

    match (name, short_name) {
        (Some(n), _) => Ok(n.to_owned()),
        (None, Some(sn)) => Ok(sn.to_owned()),
        (None, None) => Err("manifest JSON missing non-empty `name` or `short_name`".to_owned()),
    }
}

/// Validates that a single absolute `https://` `<link rel="canonical">` appears in `<head>` (not `<body>`).
#[must_use]
pub fn validate_canonical_placement(html: &str) -> Finding {
    let all_canonicals = extract_all_canonicals(html);
    let head_canonicals = extract_head(html).map_or_else(Vec::new, extract_all_canonicals);

    if all_canonicals.len() > head_canonicals.len() {
        return Finding::fail(
            "canonical in <head>",
            Some("found `<link rel=\"canonical\">` outside `<head>` (e.g. in `<body>`)".to_owned()),
        )
        .with_rule("seo/canonical-head")
        .with_docs(DOCS_CANONICAL);
    }

    match head_canonicals.as_slice() {
        [] => Finding::fail(
            "canonical in <head>",
            Some("missing `<link rel=\"canonical\">` inside `<head>`".to_owned()),
        )
        .with_rule("seo/canonical-head")
        .with_docs(DOCS_CANONICAL),
        [single] => {
            if single.starts_with("https://") && Url::parse(single).is_ok() {
                Finding::pass("canonical in <head>", Some(single.clone()))
                    .with_rule("seo/canonical-head")
            } else {
                Finding::fail(
                    "canonical in <head>",
                    Some(format!("`{single}` is not an absolute `https://` URL")),
                )
                .with_rule("seo/canonical-head")
                .with_docs(DOCS_CANONICAL)
            }
        }
        multiple => Finding::fail(
            "canonical in <head>",
            Some(format!(
                "found {} `<link rel=\"canonical\">` tags in `<head>` (expected 1)",
                multiple.len()
            )),
        )
        .with_rule("seo/canonical-head")
        .with_docs(DOCS_CANONICAL),
    }
}

/// Validates core Search Appearance metadata: canonical placement, title, description, viewport, and `html[lang]`.
#[must_use]
pub fn validate_seo_metadata(html: &str) -> Vec<Finding> {
    let mut findings = vec![validate_canonical_placement(html)];
    let meta = extract_meta_tags(html);

    match extract_title(html) {
        Some(title) => findings.push(Finding::pass("<title>", Some(title)).with_rule("seo/title")),
        None => findings.push(
            Finding::fail("<title>", Some("missing or empty `<title>`".to_owned()))
                .with_rule("seo/title")
                .with_docs(DOCS_TITLE_LINK),
        ),
    }

    match meta.get("description") {
        Some(desc) => findings.push(
            Finding::pass(
                "meta description",
                Some(format!("{} chars", desc.chars().count())),
            )
            .with_rule("seo/meta-description"),
        ),
        None => findings.push(
            Finding::fail(
                "meta description",
                Some("missing or empty `<meta name=\"description\">`".to_owned()),
            )
            .with_rule("seo/meta-description")
            .with_docs(DOCS_SNIPPET),
        ),
    }

    match meta.get("viewport") {
        Some(vp) => findings
            .push(Finding::pass("meta viewport", Some(vp.clone())).with_rule("seo/meta-viewport")),
        None => findings.push(
            Finding::fail(
                "meta viewport",
                Some("missing `<meta name=\"viewport\">`".to_owned()),
            )
            .with_rule("seo/meta-viewport"),
        ),
    }

    match extract_html_lang(html) {
        Some(lang) => {
            findings.push(Finding::pass("<html lang>", Some(lang)).with_rule("seo/html-lang"));
        }
        None => findings.push(
            Finding::fail(
                "<html lang>",
                Some("missing or empty `lang` attribute on `<html>`".to_owned()),
            )
            .with_rule("seo/html-lang"),
        ),
    }

    findings
}

/// Warns if `nosnippet` or `max-image-preview:none` is present in meta robots or `X-Robots-Tag`.
#[must_use]
pub fn validate_snippet_directives(html: &str, x_robots_headers: &[&str]) -> Finding {
    let directives = extract_robots_directives(html, x_robots_headers);
    let mut blocked = Vec::new();
    for target in ["nosnippet", "max-image-preview:none"] {
        if directives.iter().any(|d| d == target) {
            blocked.push(target);
        }
    }

    if blocked.is_empty() {
        Finding::pass(
            "robots snippet guard",
            Some("no `nosnippet` or `max-image-preview:none` directive".to_owned()),
        )
        .with_rule("seo/snippet-directives")
    } else {
        Finding::warn(
            "robots snippet guard",
            Some(format!("restrictive directive(s): {}", blocked.join(", "))),
        )
        .with_rule("seo/snippet-directives")
        .with_docs(DOCS_ROBOTS_META)
    }
}

/// Finds duplicate `<title>` or `<meta name="description">` values across sampled pages.
#[must_use]
pub fn find_duplicate_metadata(pages: &[(String, Option<String>, Option<String>)]) -> Vec<Finding> {
    let mut titles: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut descriptions: BTreeMap<&str, Vec<&str>> = BTreeMap::new();

    for (url, title, desc) in pages {
        if let Some(t) = title.as_deref() {
            titles.entry(t).or_default().push(url.as_str());
        }
        if let Some(d) = desc.as_deref() {
            descriptions.entry(d).or_default().push(url.as_str());
        }
    }

    let dup_titles: Vec<String> = titles
        .into_iter()
        .filter(|(_, urls)| urls.len() > 1)
        .map(|(title, urls)| format!("\"{title}\" shared by {}", urls.join(", ")))
        .collect();

    let dup_descs: Vec<String> = descriptions
        .into_iter()
        .filter(|(_, urls)| urls.len() > 1)
        .map(|(desc, urls)| format!("\"{desc}\" shared by {}", urls.join(", ")))
        .collect();

    let mut findings = Vec::with_capacity(2);
    if dup_titles.is_empty() {
        findings.push(
            Finding::pass(
                "duplicate <title>",
                Some(format!(
                    "all {} sampled page(s) have unique titles",
                    pages.len()
                )),
            )
            .with_rule("seo/duplicate-title"),
        );
    } else {
        findings.push(
            Finding::warn(
                "duplicate <title>",
                Some(format!("{} duplicate title group(s)", dup_titles.len())),
            )
            .with_rule("seo/duplicate-title")
            .with_items(dup_titles)
            .with_docs(DOCS_TITLE_LINK),
        );
    }

    if dup_descs.is_empty() {
        findings.push(
            Finding::pass(
                "duplicate meta description",
                Some(format!(
                    "all {} sampled page(s) have unique descriptions",
                    pages.len()
                )),
            )
            .with_rule("seo/duplicate-description"),
        );
    } else {
        findings.push(
            Finding::warn(
                "duplicate meta description",
                Some(format!(
                    "{} duplicate description group(s)",
                    dup_descs.len()
                )),
            )
            .with_rule("seo/duplicate-description")
            .with_items(dup_descs)
            .with_docs(DOCS_SNIPPET),
        );
    }

    findings
}

async fn check_favicon(ctx: &CheckContext, html: &str) -> Vec<Finding> {
    let links = extract_favicon_links(html);
    let mut findings = Vec::new();

    let target_url = if let Some(first) = links.first() {
        match ctx.base_url.join(&first.href) {
            Ok(url) => url,
            Err(err) => {
                return vec![
                    Finding::fail(
                        "favicon",
                        Some(format!("invalid favicon href `{}`: {err}", first.href)),
                    )
                    .with_rule("seo/favicon")
                    .with_docs(DOCS_FAVICON),
                ];
            }
        }
    } else {
        match ctx.base_url.join("/favicon.ico") {
            Ok(url) => url,
            Err(_) => {
                return vec![
                    Finding::fail("favicon", Some("invalid base URL".to_owned()))
                        .with_rule("seo/favicon"),
                ];
            }
        }
    };

    match ctx.client.get(target_url.clone()).send().await {
        Ok(resp) if resp.status().is_success() => {
            findings.push(
                Finding::pass(
                    "favicon",
                    Some(format!("HTTP {} at {target_url}", resp.status())),
                )
                .with_rule("seo/favicon"),
            );
        }
        Ok(resp) => {
            findings.push(
                Finding::fail(
                    "favicon",
                    Some(format!("HTTP {} at {target_url}", resp.status())),
                )
                .with_rule("seo/favicon")
                .with_docs(DOCS_FAVICON),
            );
        }
        Err(err) => {
            findings.push(
                Finding::fail(
                    "favicon",
                    Some(format!("request to {target_url} failed: {err}")),
                )
                .with_rule("seo/favicon")
                .with_docs(DOCS_FAVICON),
            );
        }
    }

    if has_only_svg_favicon(&links) {
        findings.push(
            Finding::warn(
                "favicon raster fallback",
                Some(
                    "only SVG favicon declared; add a PNG/ICO/JPEG fallback for Google Search"
                        .to_owned(),
                ),
            )
            .with_rule("seo/favicon-raster")
            .with_docs(DOCS_FAVICON),
        );
    }

    findings
}

async fn check_apple_touch_icon(ctx: &CheckContext, html: &str) -> Finding {
    let Some(href) = extract_apple_touch_icon_href(html) else {
        return Finding::warn(
            "apple-touch-icon",
            Some("missing `<link rel=\"apple-touch-icon\">` for Safari/iOS".to_owned()),
        )
        .with_rule("seo/apple-touch-icon");
    };

    let Ok(url) = ctx.base_url.join(&href) else {
        return Finding::warn(
            "apple-touch-icon",
            Some(format!("invalid apple-touch-icon href `{href}`")),
        )
        .with_rule("seo/apple-touch-icon");
    };

    match ctx.client.get(url.clone()).send().await {
        Ok(resp) if resp.status() == StatusCode::OK => {
            let content_type = resp
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .trim();
            let mime = content_type
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if mime == "image/png" {
                Finding::pass(
                    "apple-touch-icon",
                    Some(format!("HTTP 200 (image/png) at {url}")),
                )
                .with_rule("seo/apple-touch-icon")
            } else {
                Finding::warn(
                    "apple-touch-icon",
                    Some(format!(
                        "HTTP 200 at {url} has content-type `{content_type}` (expected `image/png`)"
                    )),
                )
                .with_rule("seo/apple-touch-icon")
            }
        }
        Ok(resp) => Finding::warn(
            "apple-touch-icon",
            Some(format!("HTTP {} at {url} (expected 200)", resp.status())),
        )
        .with_rule("seo/apple-touch-icon"),
        Err(err) => Finding::warn(
            "apple-touch-icon",
            Some(format!("request to {url} failed: {err}")),
        )
        .with_rule("seo/apple-touch-icon"),
    }
}

async fn check_web_manifest(ctx: &CheckContext, html: &str) -> Option<Finding> {
    let href = extract_manifest_href(html)?;
    let Ok(url) = ctx.base_url.join(&href) else {
        return Some(
            Finding::fail(
                "web manifest",
                Some(format!("invalid manifest href `{href}`")),
            )
            .with_rule("seo/web-manifest"),
        );
    };

    let resp = match ctx.client.get(url.clone()).send().await {
        Ok(resp) => resp,
        Err(err) => {
            return Some(
                Finding::fail(
                    "web manifest",
                    Some(format!("request to {url} failed: {err}")),
                )
                .with_rule("seo/web-manifest"),
            );
        }
    };

    if resp.status() != StatusCode::OK {
        return Some(
            Finding::fail(
                "web manifest",
                Some(format!("HTTP {} at {url} (expected 200)", resp.status())),
            )
            .with_rule("seo/web-manifest"),
        );
    }

    let body = resp.text().await.unwrap_or_default();
    Some(match validate_web_manifest_json(&body) {
        Ok(name) => Finding::pass("web manifest", Some(format!("{name} ({url})")))
            .with_rule("seo/web-manifest"),
        Err(reason) => Finding::fail("web manifest", Some(format!("{url}: {reason}")))
            .with_rule("seo/web-manifest"),
    })
}

async fn check_sitemap_duplicates(
    ctx: &CheckContext,
    home_html: &str,
    max_urls: usize,
) -> Vec<Finding> {
    if max_urls < 2 {
        return Vec::new();
    }
    let Ok(sitemap_url) = ctx.base_url.join("/sitemap.xml") else {
        return Vec::new();
    };
    let Ok(resp) = ctx.client.get(sitemap_url).send().await else {
        return Vec::new();
    };
    if !resp.status().is_success() {
        return Vec::new();
    }
    let xml = resp.text().await.unwrap_or_default();
    let locs = extract_sitemap_locs(&xml);
    if locs.len() <= 1 {
        return Vec::new();
    }

    let mut pages = Vec::new();
    let mut off_origin = Vec::new();
    for loc in locs.iter().take(max_urls) {
        let html = if urls_match(loc, ctx.base_url.as_str()) {
            home_html.to_owned()
        } else {
            let Ok(parsed) = Url::parse(loc) else {
                continue;
            };
            if !is_same_origin(&ctx.base_url, &parsed) {
                off_origin.push(format!(
                    "{loc}: skipped off-origin URL (expected same origin as {})",
                    ctx.base_url
                ));
                continue;
            }
            let Ok(page_resp) = ctx.client.get(parsed).send().await else {
                continue;
            };
            if !page_resp.status().is_success() {
                continue;
            }
            page_resp.text().await.unwrap_or_default()
        };

        let title = extract_title(&html);
        let desc = extract_meta_tags(&html).remove("description");
        pages.push((loc.clone(), title, desc));
    }

    let mut findings = Vec::new();
    if !off_origin.is_empty() {
        findings.push(
            Finding::warn(
                "sitemap off-origin URLs",
                Some(format!(
                    "skipped {} off-origin `<loc>` URL(s) without fetching",
                    off_origin.len()
                )),
            )
            .with_rule("http/sitemap-indexability")
            .with_items(off_origin),
        );
    }

    if pages.len() > 1 {
        findings.extend(find_duplicate_metadata(&pages));
    }

    findings
}

#[async_trait]
impl Check for SeoCheck {
    fn name(&self) -> &'static str {
        "seo"
    }

    async fn run(&self, ctx: &CheckContext) -> Result<CheckReport, CheckError> {
        let resp = ctx.client.get(ctx.base_url.clone()).send().await?;
        if !resp.status().is_success() {
            return Ok(CheckReport::new(
                self.name(),
                vec![
                    Finding::fail(
                        "homepage fetch",
                        Some(format!("HTTP {} for {}", resp.status(), ctx.base_url)),
                    )
                    .with_rule("seo/homepage-fetch"),
                ],
            ));
        }

        let x_robots: Vec<String> = resp
            .headers()
            .get_all("x-robots-tag")
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_owned))
            .collect();
        let x_robots_refs: Vec<&str> = x_robots.iter().map(String::as_str).collect();
        let home_html = resp.text().await.unwrap_or_default();

        let mut findings = validate_seo_metadata(&home_html);
        findings.push(validate_snippet_directives(&home_html, &x_robots_refs));

        if self.config.check_favicon {
            findings.extend(check_favicon(ctx, &home_html).await);
        }

        findings.push(check_apple_touch_icon(ctx, &home_html).await);
        if let Some(manifest_finding) = check_web_manifest(ctx, &home_html).await {
            findings.push(manifest_finding);
        }

        findings
            .extend(check_sitemap_duplicates(ctx, &home_html, self.config.max_sitemap_urls).await);

        Ok(CheckReport::new(self.name(), findings))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        extract_apple_touch_icon_href, extract_favicon_links, extract_manifest_href,
        find_duplicate_metadata, has_only_svg_favicon, validate_canonical_placement,
        validate_seo_metadata, validate_snippet_directives, validate_web_manifest_json,
    };
    use crate::check::Severity;

    #[test]
    fn validates_canonical_placement_in_head_and_body() {
        let valid = r#"<html><head><link rel="canonical" href="https://example.com/"></head><body></body></html>"#;
        assert_eq!(validate_canonical_placement(valid).severity, Severity::Pass);

        let relative = r#"<html><head><link rel="canonical" href="/about"></head></html>"#;
        assert_eq!(
            validate_canonical_placement(relative).severity,
            Severity::Fail
        );

        let in_body = r#"<html><head></head><body><link rel="canonical" href="https://example.com/"></body></html>"#;
        assert_eq!(
            validate_canonical_placement(in_body).severity,
            Severity::Fail
        );

        let duplicate = r#"<html><head>
            <link rel="canonical" href="https://example.com/">
            <link rel="canonical" href="https://example.com/alt">
        </head></html>"#;
        assert_eq!(
            validate_canonical_placement(duplicate).severity,
            Severity::Fail
        );
    }

    #[test]
    fn validates_core_seo_metadata_tags() {
        let good = r#"<!doctype html><html lang="en"><head>
            <title>Example Site</title>
            <meta name="description" content="A helpful summary.">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <link rel="canonical" href="https://example.com/">
        </head><body></body></html>"#;
        let findings = validate_seo_metadata(good);
        assert_eq!(findings.len(), 5);
        assert!(findings.iter().all(|f| f.severity == Severity::Pass));

        let missing = "<html><head></head><body></body></html>";
        let findings = validate_seo_metadata(missing);
        assert_eq!(findings.len(), 5);
        assert!(findings.iter().all(|f| f.severity == Severity::Fail));
    }

    #[test]
    fn detects_svg_only_favicon_without_raster_fallback() {
        let svg_only = r#"<head><link rel="icon" type="image/svg+xml" href="/favicon.svg"></head>"#;
        let links = extract_favicon_links(svg_only);
        assert_eq!(links.len(), 1);
        assert!(has_only_svg_favicon(&links));

        let with_png = r#"<head>
            <link rel="icon" type="image/svg+xml" href="/favicon.svg">
            <link rel="icon" type="image/png" href="/favicon-48x48.png">
        </head>"#;
        let links = extract_favicon_links(with_png);
        assert_eq!(links.len(), 2);
        assert!(!has_only_svg_favicon(&links));
    }

    #[test]
    fn warns_on_restrictive_snippet_directives_and_duplicates() {
        let clean = r#"<html><head><meta name="robots" content="index, follow"></head></html>"#;
        assert_eq!(
            validate_snippet_directives(clean, &[]).severity,
            Severity::Pass
        );

        let nosnippet = r#"<html><head><meta name="robots" content="nosnippet"></head></html>"#;
        assert_eq!(
            validate_snippet_directives(nosnippet, &[]).severity,
            Severity::Warn
        );
        assert_eq!(
            validate_snippet_directives(clean, &["max-image-preview:none"]).severity,
            Severity::Warn
        );

        let pages = vec![
            (
                "https://example.com/".to_owned(),
                Some("Same Title".to_owned()),
                Some("Desc A".to_owned()),
            ),
            (
                "https://example.com/about".to_owned(),
                Some("Same Title".to_owned()),
                Some("Desc B".to_owned()),
            ),
        ];
        let dup_findings = find_duplicate_metadata(&pages);
        assert_eq!(dup_findings[0].severity, Severity::Warn);
        assert_eq!(dup_findings[0].items.len(), 1);
        assert_eq!(dup_findings[1].severity, Severity::Pass);
    }

    #[test]
    fn extracts_apple_touch_icon_and_web_manifest_links() {
        let html = r#"<html><head>
            <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
            <link rel="manifest" href="/site.webmanifest">
        </head><body></body></html>"#;

        assert_eq!(
            extract_apple_touch_icon_href(html).as_deref(),
            Some("/apple-touch-icon.png")
        );
        assert_eq!(
            extract_manifest_href(html).as_deref(),
            Some("/site.webmanifest")
        );

        let body_only_manifest =
            r#"<html><head></head><body><link rel="manifest" href="/bad.json"></body></html>"#;
        assert_eq!(extract_manifest_href(body_only_manifest), None);
        assert_eq!(extract_apple_touch_icon_href(body_only_manifest), None);

        assert_eq!(
            validate_web_manifest_json(r#"{"name": "Example App"}"#),
            Ok("Example App".to_owned())
        );
        assert_eq!(
            validate_web_manifest_json(r#"{"short_name": "Ex"}"#),
            Ok("Ex".to_owned())
        );
        assert!(validate_web_manifest_json(r#"{"icons": []}"#).is_err());
        assert!(validate_web_manifest_json("{invalid").is_err());
    }
}
