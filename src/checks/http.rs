use async_trait::async_trait;
use reqwest::StatusCode;
use reqwest::header::LOCATION;
use serde::Deserialize;
use url::Url;

use crate::check::{Check, CheckContext, CheckError, CheckReport, Finding};

const HTML_SIZE_WARN_BYTES: usize = 1_572_864; // 1.5 MiB
const HTML_SIZE_FAIL_BYTES: usize = 2_097_152; // 2 MiB (Googlebot cutoff)
const ROBOTS_MAX_BYTES: usize = 512_000; // 500 KiB Googlebot limit
const SOFT_404_PROBE_PATH: &str = "/__sitecheck-404-probe";

const DOCS_REDIRECTS: &str =
    "https://developers.google.com/search/docs/crawling-indexing/301-redirects";
const DOCS_HTTP_ERRORS: &str =
    "https://developers.google.com/search/docs/crawling-indexing/http-network-errors";
const DOCS_GOOGLEBOT: &str =
    "https://developers.google.com/search/docs/crawling-indexing/googlebot";
const DOCS_VALID_HEAD: &str =
    "https://developers.google.com/search/docs/crawling-indexing/valid-page-metadata";
const DOCS_ROBOTS: &str =
    "https://developers.google.com/search/docs/crawling-indexing/robots/robots_txt";
const DOCS_NOINDEX: &str =
    "https://developers.google.com/search/docs/crawling-indexing/block-indexing";

const INVALID_HEAD_TAGS: &[&str] = &[
    "div", "img", "iframe", "p", "section", "main", "header", "footer",
];

const fn default_true() -> bool {
    true
}

const fn default_max_sitemap_urls() -> usize {
    15
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Deserialize)]
pub struct HttpConfig {
    #[serde(default = "default_true")]
    pub check_www_redirect: bool,
    #[serde(default = "default_true")]
    pub check_https_redirect: bool,
    #[serde(default = "default_true")]
    pub check_soft_404: bool,
    #[serde(default = "default_true")]
    pub check_html_size: bool,
    #[serde(default = "default_true")]
    pub check_head_validity: bool,
    #[serde(default = "default_true")]
    pub check_trailing_slash: bool,
    #[serde(default = "default_true")]
    pub check_canonical: bool,
    #[serde(default = "default_true")]
    pub check_sitemap: bool,
    #[serde(default = "default_true")]
    pub check_robots: bool,
    #[serde(default)]
    pub require_content_signal: bool,
    #[serde(default)]
    pub allow_noindex: Vec<String>,
    #[serde(default = "default_max_sitemap_urls")]
    pub max_sitemap_urls: usize,
    #[serde(default = "default_true")]
    pub check_llms_txt: bool,
    #[serde(default)]
    pub extra_paths: Vec<String>,
}

pub struct HttpCheck {
    config: HttpConfig,
}

impl HttpCheck {
    #[must_use]
    pub const fn new(config: HttpConfig) -> Self {
        Self { config }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmsValidation {
    pub has_h1: bool,
    pub link_count: usize,
}

impl LlmsValidation {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.has_h1 && self.link_count > 0
    }
}

/// Validates an `llms.txt` document for an H1 heading (`# Title`) and at least one `[Text](URL)` link.
#[must_use]
pub fn validate_llms_txt(content: &str) -> LlmsValidation {
    let has_h1 = content.lines().any(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix("# ")
            .is_some_and(|rest| !rest.trim().is_empty())
    });

    let mut link_count = 0usize;
    let bytes = content.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'['
            && let Some(close_bracket) = content[i + 1..].find(']')
        {
            let text_start = i + 1;
            let text_end = text_start + close_bracket;
            let text = content[text_start..text_end].trim();
            let after_bracket = text_end + 1;
            if !text.is_empty()
                && !text.contains('\n')
                && bytes.get(after_bracket) == Some(&b'(')
                && let Some(close_paren) = content[after_bracket + 1..].find(')')
            {
                let url_start = after_bracket + 1;
                let url_end = url_start + close_paren;
                let link_url = content[url_start..url_end].trim();
                if !link_url.is_empty()
                    && !link_url.contains(char::is_whitespace)
                    && (link_url.starts_with("http://")
                        || link_url.starts_with("https://")
                        || link_url.starts_with('/'))
                {
                    link_count += 1;
                    i = url_end + 1;
                    continue;
                }
            }
        }
        i += 1;
    }

    LlmsValidation { has_h1, link_count }
}

/// Extracts the `href` of the first `<link rel="canonical" ...>` tag from HTML.
#[must_use]
pub fn extract_canonical(html: &str) -> Option<String> {
    extract_all_canonicals(html).into_iter().next()
}

/// Extracts all `<link rel="canonical" href="...">` values from an HTML fragment.
#[must_use]
pub(crate) fn extract_all_canonicals(html: &str) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let mut results = Vec::new();
    let mut cursor = 0usize;

    while let Some(rel_pos) = lower[cursor..].find("<link") {
        let tag_start = cursor + rel_pos;
        let after_name = tag_start + 5;
        if let Some(next_ch) = html[after_name..].chars().next()
            && !next_ch.is_whitespace()
            && next_ch != '>'
            && next_ch != '/'
        {
            cursor = after_name;
            continue;
        }
        let Some(tag_end_rel) = html[after_name..].find('>') else {
            break;
        };
        let tag = &html[tag_start..=after_name + tag_end_rel];
        let is_canonical = parse_html_attr(tag, "rel").is_some_and(|rel| {
            rel.split_whitespace()
                .any(|tok| tok.eq_ignore_ascii_case("canonical"))
        });
        if is_canonical && let Some(href) = parse_html_attr(tag, "href") {
            let trimmed = href.trim();
            if !trimmed.is_empty() {
                results.push(trimmed.to_owned());
            }
        }
        cursor = after_name + tag_end_rel + 1;
    }

    results
}

/// Extracts the inner HTML of `<head>...</head>`.
#[must_use]
pub(crate) fn extract_head(html: &str) -> Option<&str> {
    let lower = html.to_ascii_lowercase();
    let mut cursor = 0usize;

    while let Some(pos) = lower[cursor..].find("<head") {
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
        let open_end = after_name + html[after_name..].find('>')?;
        let content_start = open_end + 1;
        let close_rel = lower[content_start..].find("</head>")?;
        return Some(&html[content_start..content_start + close_rel]);
    }

    None
}

fn strip_delimited(input: &str, open: &str, close: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;

    while let Some(rel) = lower[cursor..].find(open) {
        let start = cursor + rel;
        out.push_str(&input[cursor..start]);
        let after_open = start + open.len();
        if let Some(end_rel) = lower[after_open..].find(close) {
            cursor = after_open + end_rel + close.len();
        } else {
            return out;
        }
    }
    out.push_str(&input[cursor..]);
    out
}

/// Returns non-metadata block/media tag names found directly inside `<head>...</head>`.
#[must_use]
pub fn find_invalid_head_tags(html: &str) -> Vec<&'static str> {
    let Some(head) = extract_head(html) else {
        return Vec::new();
    };
    let cleaned = strip_delimited(
        &strip_delimited(
            &strip_delimited(head, "<!--", "-->"),
            "<script",
            "</script>",
        ),
        "<style",
        "</style>",
    );
    let lower = cleaned.to_ascii_lowercase();

    let mut found = Vec::new();
    for &tag in INVALID_HEAD_TAGS {
        let needle = format!("<{tag}");
        let mut cursor = 0usize;
        while let Some(rel) = lower[cursor..].find(&needle) {
            let after = cursor + rel + needle.len();
            if lower[after..]
                .chars()
                .next()
                .is_some_and(|ch| ch.is_whitespace() || ch == '>' || ch == '/')
            {
                found.push(tag);
                break;
            }
            cursor = after;
        }
    }
    found
}

/// Validates that `<head>` contains no non-metadata block/media tags.
#[must_use]
pub fn validate_head(html: &str) -> Finding {
    if extract_head(html).is_none() {
        return Finding::warn(
            "<head> validity",
            Some("no `<head>...</head>` section found".to_owned()),
        )
        .with_rule("http/valid-head")
        .with_docs(DOCS_VALID_HEAD);
    }

    let invalid = find_invalid_head_tags(html);
    if invalid.is_empty() {
        Finding::pass(
            "<head> validity",
            Some("no block/media tags inside `<head>`".to_owned()),
        )
        .with_rule("http/valid-head")
    } else {
        let formatted: Vec<String> = invalid.iter().map(|t| format!("<{t}>")).collect();
        Finding::fail(
            "<head> validity",
            Some(format!(
                "invalid non-metadata tag(s) in `<head>`: {}",
                formatted.join(", ")
            )),
        )
        .with_rule("http/valid-head")
        .with_docs(DOCS_VALID_HEAD)
    }
}

/// Validates uncompressed homepage HTML size against Googlebot's 2 MiB HTML cutoff.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn validate_html_size(bytes: usize) -> Finding {
    let kib = bytes as f64 / 1024.0;
    let size_label = if bytes >= 1_048_576 {
        format!("{:.2} MiB ({bytes} bytes)", bytes as f64 / 1_048_576.0)
    } else {
        format!("{kib:.1} KiB ({bytes} bytes)")
    };

    if bytes >= HTML_SIZE_FAIL_BYTES {
        Finding::fail(
            "HTML size",
            Some(format!("{size_label} exceeds Googlebot 2 MiB HTML cutoff")),
        )
        .with_rule("http/html-size")
        .with_docs(DOCS_GOOGLEBOT)
    } else if bytes >= HTML_SIZE_WARN_BYTES {
        Finding::warn(
            "HTML size",
            Some(format!(
                "{size_label} approaching Googlebot 2 MiB HTML cutoff"
            )),
        )
        .with_rule("http/html-size")
        .with_docs(DOCS_GOOGLEBOT)
    } else {
        Finding::pass("HTML size", Some(size_label)).with_rule("http/html-size")
    }
}

/// Parsed `robots.txt` allow/disallow rules for `Googlebot` and `*`.
#[derive(Debug, Clone, Default)]
pub struct RobotsRules {
    googlebot: Vec<(bool, String)>,
    wildcard: Vec<(bool, String)>,
}

impl RobotsRules {
    #[must_use]
    pub fn parse(content: &str) -> Self {
        let mut rules = Self::default();
        let mut in_googlebot = false;
        let mut in_wildcard = false;
        let mut saw_rule = false;

        for raw_line in content.lines() {
            let line = raw_line
                .split_once('#')
                .map_or(raw_line, |(before, _)| before)
                .trim();
            let Some((key, val)) = line.split_once(':') else {
                continue;
            };
            let key = key.trim();
            let val = val.trim();

            if key.eq_ignore_ascii_case("user-agent") {
                if saw_rule {
                    in_googlebot = false;
                    in_wildcard = false;
                    saw_rule = false;
                }
                if val == "*" {
                    in_wildcard = true;
                } else if val.eq_ignore_ascii_case("googlebot") {
                    in_googlebot = true;
                }
            } else if key.eq_ignore_ascii_case("allow") || key.eq_ignore_ascii_case("disallow") {
                saw_rule = true;
                let is_allow = key.eq_ignore_ascii_case("allow");
                if val.is_empty() {
                    continue;
                }
                if in_googlebot {
                    rules.googlebot.push((is_allow, val.to_owned()));
                }
                if in_wildcard {
                    rules.wildcard.push((is_allow, val.to_owned()));
                }
            }
        }

        rules
    }

    #[must_use]
    pub fn is_disallowed(&self, path: &str) -> bool {
        let group = if self.googlebot.is_empty() {
            &self.wildcard
        } else {
            &self.googlebot
        };

        let mut best: Option<(usize, bool)> = None;
        for (is_allow, pattern) in group {
            if robots_pattern_matches(pattern, path) {
                let len = pattern.len();
                best = match best {
                    None => Some((len, *is_allow)),
                    Some((best_len, _)) if len > best_len => Some((len, *is_allow)),
                    Some((best_len, best_allow)) if len == best_len => {
                        Some((best_len, best_allow || *is_allow))
                    }
                    other => other,
                };
            }
        }

        best.is_some_and(|(_, is_allow)| !is_allow)
    }

    #[must_use]
    pub fn disallows_root(&self) -> bool {
        self.is_disallowed("/")
    }
}

pub(crate) fn robots_pattern_matches(pattern: &str, path: &str) -> bool {
    let (pat, must_end) = pattern
        .strip_suffix('$')
        .map_or((pattern, false), |p| (p, true));

    let parts: Vec<&str> = pat.split('*').collect();
    if parts.len() == 1 {
        return if must_end {
            path == pat
        } else {
            path.starts_with(pat)
        };
    }

    let Some(first) = parts.first() else {
        return false;
    };
    if !path.starts_with(first) {
        return false;
    }
    let mut rest = &path[first.len()..];

    for part in &parts[1..parts.len() - 1] {
        if part.is_empty() {
            continue;
        }
        let Some(pos) = rest.find(part) else {
            return false;
        };
        rest = &rest[pos + part.len()..];
    }

    let last = parts[parts.len() - 1];
    if must_end {
        rest.ends_with(last)
    } else if last.is_empty() {
        true
    } else {
        rest.contains(last)
    }
}

/// Checks whether a `robots.txt` body includes a `Content-Signal:` directive.
#[must_use]
pub fn has_content_signal(robots_body: &str) -> bool {
    robots_body.lines().any(|raw_line| {
        let line = raw_line
            .split_once('#')
            .map_or(raw_line, |(before, _)| before)
            .trim_start();
        line.len() >= 15 && line[..15].eq_ignore_ascii_case("content-signal:")
    })
}

/// Collects lowercased robots directives from `<meta name="robots|googlebot">` and `X-Robots-Tag`.
#[must_use]
pub(crate) fn extract_robots_directives(html: &str, x_robots_headers: &[&str]) -> Vec<String> {
    let mut directives = Vec::new();
    let lower = html.to_ascii_lowercase();
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
        let is_robots = parse_html_attr(tag, "name").is_some_and(|name| {
            let trimmed = name.trim();
            trimmed.eq_ignore_ascii_case("robots") || trimmed.eq_ignore_ascii_case("googlebot")
        });
        if is_robots && let Some(content) = parse_html_attr(tag, "content") {
            for token in content.split(',') {
                let normalized = token.trim().to_ascii_lowercase();
                if !normalized.is_empty() {
                    directives.push(normalized);
                }
            }
        }
        cursor = after_name + end_rel + 1;
    }

    for &header in x_robots_headers {
        let trimmed = header.trim();
        let body = if let Some((prefix, rest)) = trimmed.split_once(':')
            && !prefix.contains(',')
            && !prefix.contains(char::is_whitespace)
            && rest.starts_with(char::is_whitespace)
        {
            if prefix.eq_ignore_ascii_case("googlebot") {
                rest.trim()
            } else {
                continue;
            }
        } else {
            trimmed
        };
        for token in body.split(',') {
            let normalized = token.trim().to_ascii_lowercase();
            if !normalized.is_empty() {
                directives.push(normalized);
            }
        }
    }

    directives
}

/// Returns `true` if the HTML or `X-Robots-Tag` headers emit `noindex` (or `none`) for Googlebot.
#[must_use]
pub fn has_noindex(html: &str, x_robots_headers: &[&str]) -> bool {
    extract_robots_directives(html, x_robots_headers)
        .iter()
        .any(|d| d == "noindex" || d == "none")
}

#[must_use]
pub(crate) fn is_path_allowed_noindex(url_or_path: &str, allow_noindex: &[String]) -> bool {
    let path =
        Url::parse(url_or_path).map_or_else(|_| url_or_path.to_owned(), |u| u.path().to_owned());
    allow_noindex
        .iter()
        .any(|allowed| allowed == &path || allowed == url_or_path)
}

/// Extracts `<loc>...</loc>` URLs from a `sitemap.xml` document.
#[must_use]
pub fn extract_sitemap_locs(xml: &str) -> Vec<String> {
    let lower = xml.to_ascii_lowercase();
    let mut locs = Vec::new();
    let mut cursor = 0usize;

    while let Some(open_rel) = lower[cursor..].find("<loc>") {
        let start = cursor + open_rel + 5;
        let Some(close_rel) = lower[start..].find("</loc>") else {
            break;
        };
        let value = xml[start..start + close_rel].trim();
        if !value.is_empty() {
            locs.push(value.to_owned());
        }
        cursor = start + close_rel + 6;
    }

    locs
}

/// Extracts a named attribute value from a single HTML tag slice.
#[must_use]
pub(crate) fn parse_html_attr(tag: &str, attr_name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let target = attr_name.to_ascii_lowercase();
    let mut cursor = 0usize;

    while let Some(pos) = lower[cursor..].find(&target) {
        let idx = cursor + pos;
        let preceded_by_boundary = idx == 0
            || tag[..idx]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_whitespace() || c == '<');
        let after_name = idx + target.len();
        if !preceded_by_boundary {
            cursor = after_name;
            continue;
        }

        let rest = tag[after_name..].trim_start();
        let Some(after_eq) = rest.strip_prefix('=') else {
            cursor = after_name;
            continue;
        };
        let val_str = after_eq.trim_start();
        if let Some(quoted) = val_str.strip_prefix('"') {
            if let Some(end) = quoted.find('"') {
                return Some(quoted[..end].to_owned());
            }
        } else if let Some(quoted) = val_str.strip_prefix('\'') {
            if let Some(end) = quoted.find('\'') {
                return Some(quoted[..end].to_owned());
            }
        } else {
            let end = val_str
                .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
                .unwrap_or(val_str.len());
            if end > 0 {
                return Some(val_str[..end].to_owned());
            }
        }
        cursor = after_name;
    }

    None
}

pub(crate) fn urls_match(a: &str, b: &str) -> bool {
    match (Url::parse(a), Url::parse(b)) {
        (Ok(ua), Ok(ub)) => ua == ub,
        _ => a == b,
    }
}

async fn check_www_redirect(ctx: &CheckContext) -> Finding {
    let Some(host) = ctx.base_url.host_str() else {
        return Finding::warn(
            "www -> apex redirect",
            Some("base URL has no host".to_owned()),
        )
        .with_rule("http/www-redirect");
    };
    if host.starts_with("www.") || host == "localhost" || host.parse::<std::net::IpAddr>().is_ok() {
        return Finding::pass(
            "www -> apex redirect",
            Some(format!("skipped for host `{host}`")),
        )
        .with_rule("http/www-redirect");
    }

    let mut www_url = ctx.base_url.clone();
    if www_url.set_host(Some(&format!("www.{host}"))).is_err() {
        return Finding::warn(
            "www -> apex redirect",
            Some(format!("could not construct www.{host}")),
        )
        .with_rule("http/www-redirect");
    }

    let resp = match ctx.no_redirect_client.get(www_url.clone()).send().await {
        Ok(resp) => resp,
        Err(err) => {
            return Finding::fail(
                "www -> apex redirect",
                Some(format!("request to {www_url} failed: {err}")),
            )
            .with_rule("http/www-redirect");
        }
    };

    let status = resp.status();
    let location = resp
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    match (status.as_u16(), location) {
        (301 | 308, Some(loc)) => {
            let resolved = www_url
                .join(&loc)
                .map_or_else(|_| loc.clone(), |u| u.to_string());
            if urls_match(&resolved, ctx.base_url.as_str()) {
                Finding::pass(
                    "www -> apex redirect",
                    Some(format!("{www_url} -> {status} {resolved}")),
                )
            } else {
                Finding::fail(
                    "www -> apex redirect",
                    Some(format!(
                        "{www_url} redirected ({status}) to {resolved}, expected {}",
                        ctx.base_url
                    )),
                )
            }
        }
        (302 | 307, Some(loc)) => Finding::warn(
            "www -> apex redirect",
            Some(format!(
                "{www_url} returned temporary {status} -> {loc} (expected 301)"
            )),
        ),
        _ => Finding::fail(
            "www -> apex redirect",
            Some(format!("{www_url} returned HTTP {status} (expected 301)")),
        ),
    }
    .with_rule("http/www-redirect")
}

async fn check_https_redirect(ctx: &CheckContext) -> Finding {
    let title = "HTTP -> HTTPS redirect";
    let rule = "http/https-redirect";
    if ctx.base_url.scheme() != "https" {
        return Finding::pass(title, Some("skipped for non-HTTPS base URL".to_owned()))
            .with_rule(rule);
    }
    let Some(host) = ctx.base_url.host_str() else {
        return Finding::warn(title, Some("base URL has no host".to_owned())).with_rule(rule);
    };
    if host == "localhost" || host.parse::<std::net::IpAddr>().is_ok() {
        return Finding::pass(title, Some(format!("skipped for host `{host}`"))).with_rule(rule);
    }

    let mut current = ctx.base_url.clone();
    if current.set_scheme("http").is_err() {
        return Finding::warn(title, Some("could not construct HTTP URL".to_owned()))
            .with_rule(rule);
    }
    let start_url = current.to_string();

    for hop in 1..=2 {
        let resp = match ctx.no_redirect_client.get(current.clone()).send().await {
            Ok(resp) => resp,
            Err(err) => {
                return Finding::fail(title, Some(format!("request to {current} failed: {err}")))
                    .with_rule(rule)
                    .with_docs(DOCS_REDIRECTS);
            }
        };

        let status = resp.status();
        let location = resp
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        match (status.as_u16(), location) {
            (301 | 308, Some(loc)) => {
                let resolved = current
                    .join(&loc)
                    .map_or_else(|_| loc.clone(), |u| u.to_string());
                if urls_match(&resolved, ctx.base_url.as_str()) {
                    return Finding::pass(
                        title,
                        Some(format!("{start_url} -> {status} {resolved} ({hop} hop)")),
                    )
                    .with_rule(rule);
                }
                if hop == 2 {
                    return Finding::fail(
                        title,
                        Some(format!(
                            "exceeded 2 hops: {current} -> {status} {resolved}, expected {}",
                            ctx.base_url
                        )),
                    )
                    .with_rule(rule)
                    .with_docs(DOCS_REDIRECTS);
                }
                let Ok(next_url) = Url::parse(&resolved) else {
                    return Finding::fail(
                        title,
                        Some(format!("invalid redirect target `{resolved}`")),
                    )
                    .with_rule(rule)
                    .with_docs(DOCS_REDIRECTS);
                };
                current = next_url;
            }
            (302 | 307, Some(loc)) => {
                return Finding::warn(
                    title,
                    Some(format!(
                        "{current} returned temporary {status} -> {loc} (expected 301/308)"
                    )),
                )
                .with_rule(rule)
                .with_docs(DOCS_REDIRECTS);
            }
            _ => {
                return Finding::fail(
                    title,
                    Some(format!(
                        "{current} returned HTTP {status} (expected 301/308 to {})",
                        ctx.base_url
                    )),
                )
                .with_rule(rule)
                .with_docs(DOCS_REDIRECTS);
            }
        }
    }

    Finding::fail(title, Some("redirect loop exceeded 2 hops".to_owned()))
        .with_rule(rule)
        .with_docs(DOCS_REDIRECTS)
}

async fn check_soft_404(ctx: &CheckContext) -> Finding {
    let Ok(url) = ctx.base_url.join(SOFT_404_PROBE_PATH) else {
        return Finding::fail("soft 404", Some("invalid base URL".to_owned()))
            .with_rule("http/soft-404");
    };

    let resp = match ctx.no_redirect_client.get(url.clone()).send().await {
        Ok(resp) => resp,
        Err(err) => {
            return Finding::fail("soft 404", Some(format!("request to {url} failed: {err}")))
                .with_rule("http/soft-404")
                .with_docs(DOCS_HTTP_ERRORS);
        }
    };

    let status = resp.status();
    if matches!(status, StatusCode::NOT_FOUND | StatusCode::GONE) {
        Finding::pass(
            "soft 404",
            Some(format!("{SOFT_404_PROBE_PATH} -> {status}")),
        )
        .with_rule("http/soft-404")
    } else {
        Finding::fail(
            "soft 404",
            Some(format!(
                "{SOFT_404_PROBE_PATH} returned HTTP {status} (expected 404 or 410)"
            )),
        )
        .with_rule("http/soft-404")
        .with_docs(DOCS_HTTP_ERRORS)
    }
}

async fn check_trailing_slash_paths(
    ctx: &CheckContext,
    extra_paths: &[String],
    sitemap_locs: &[String],
) -> Vec<Finding> {
    let mut candidate_urls: Vec<Url> = Vec::new();
    if extra_paths.is_empty() {
        for loc in sitemap_locs {
            if let Ok(parsed) = Url::parse(loc)
                && parsed.path() != "/"
                && parsed.host_str() == ctx.base_url.host_str()
            {
                candidate_urls.push(parsed);
                if candidate_urls.len() >= 3 {
                    break;
                }
            }
        }
    } else {
        for path in extra_paths {
            if let Ok(joined) = ctx.base_url.join(path)
                && joined.path() != "/"
            {
                candidate_urls.push(joined);
            }
        }
    }

    if candidate_urls.is_empty() {
        return vec![
            Finding::pass(
                "trailing-slash redirect",
                Some("no non-root paths to test".to_owned()),
            )
            .with_rule("http/trailing-slash"),
        ];
    }

    let mut findings = Vec::new();
    for canonical_url in candidate_urls {
        let mut flipped = canonical_url.clone();
        let current_path = canonical_url.path();
        if let Some(stripped) = current_path.strip_suffix('/') {
            flipped.set_path(stripped);
        } else {
            flipped.set_path(&format!("{current_path}/"));
        }

        let resp = match ctx.no_redirect_client.get(flipped.clone()).send().await {
            Ok(resp) => resp,
            Err(err) => {
                findings.push(
                    Finding::fail(
                        format!("trailing-slash {}", flipped.path()),
                        Some(format!("request failed: {err}")),
                    )
                    .with_rule("http/trailing-slash"),
                );
                continue;
            }
        };

        let status = resp.status();
        let location = resp
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        let finding = match (status.as_u16(), location) {
            (301 | 308, Some(loc)) => {
                let resolved = flipped
                    .join(&loc)
                    .map_or_else(|_| loc.clone(), |u| u.to_string());
                if urls_match(&resolved, canonical_url.as_str()) {
                    Finding::pass(
                        format!("trailing-slash {}", flipped.path()),
                        Some(format!("{status} -> {}", canonical_url.path())),
                    )
                } else {
                    Finding::fail(
                        format!("trailing-slash {}", flipped.path()),
                        Some(format!("{status} -> {resolved}, expected {canonical_url}")),
                    )
                }
            }
            (302 | 307, Some(loc)) => Finding::warn(
                format!("trailing-slash {}", flipped.path()),
                Some(format!("temporary {status} -> {loc} (expected 301)")),
            ),
            _ => Finding::fail(
                format!("trailing-slash {}", flipped.path()),
                Some(format!(
                    "HTTP {status} for {} (expected 301 to {})",
                    flipped.path(),
                    canonical_url.path()
                )),
            ),
        };
        findings.push(finding.with_rule("http/trailing-slash"));
    }

    findings
}

fn evaluate_robots_body(body: &str, require_content_signal: bool) -> (Vec<Finding>, RobotsRules) {
    let mut findings = Vec::new();
    let rules = RobotsRules::parse(body);

    if body.len() >= ROBOTS_MAX_BYTES {
        findings.push(
            Finding::fail(
                "robots.txt size",
                Some(format!(
                    "{} bytes exceeds Googlebot 500 KiB limit",
                    body.len()
                )),
            )
            .with_rule("http/robots-size")
            .with_docs(DOCS_ROBOTS),
        );
    }

    if rules.disallows_root() {
        findings.push(
            Finding::fail(
                "robots.txt crawlability",
                Some("disallows `/` for `*` or `Googlebot`".to_owned()),
            )
            .with_rule("http/robots-crawlable")
            .with_docs(DOCS_ROBOTS),
        );
    }

    let has_sitemap = body.lines().any(|line| {
        line.trim_start()
            .to_ascii_lowercase()
            .starts_with("sitemap:")
    });

    if has_sitemap {
        findings.push(
            Finding::pass(
                "robots.txt",
                Some(format!(
                    "HTTP 200 ({} bytes) with Sitemap directive",
                    body.len()
                )),
            )
            .with_rule("http/robots-txt"),
        );
    } else {
        findings.push(
            Finding::warn(
                "robots.txt",
                Some("HTTP 200 but missing `Sitemap:` directive".to_owned()),
            )
            .with_rule("http/robots-txt"),
        );
    }

    if require_content_signal {
        if has_content_signal(body) {
            findings.push(
                Finding::pass(
                    "robots.txt Content-Signal",
                    Some("`Content-Signal:` directive present".to_owned()),
                )
                .with_rule("http/content-signal"),
            );
        } else {
            findings.push(
                Finding::fail(
                    "robots.txt Content-Signal",
                    Some("missing required `Content-Signal:` directive".to_owned()),
                )
                .with_rule("http/content-signal"),
            );
        }
    }

    (findings, rules)
}

async fn check_robots(
    ctx: &CheckContext,
    require_content_signal: bool,
) -> (Vec<Finding>, RobotsRules) {
    let Ok(url) = ctx.base_url.join("/robots.txt") else {
        return (
            vec![
                Finding::fail("robots.txt", Some("invalid base URL".to_owned()))
                    .with_rule("http/robots-txt"),
            ],
            RobotsRules::default(),
        );
    };

    let resp = match ctx.client.get(url.clone()).send().await {
        Ok(resp) => resp,
        Err(err) => {
            return (
                vec![
                    Finding::fail("robots.txt", Some(format!("request failed: {err}")))
                        .with_rule("http/robots-txt"),
                ],
                RobotsRules::default(),
            );
        }
    };

    let status = resp.status();
    if !status.is_success() {
        return (
            vec![
                Finding::fail("robots.txt", Some(format!("HTTP {status} at {url}")))
                    .with_rule("http/robots-txt"),
            ],
            RobotsRules::default(),
        );
    }

    let body = resp.text().await.unwrap_or_default();
    if body.trim().is_empty() {
        return (
            vec![
                Finding::fail("robots.txt", Some("file is empty".to_owned()))
                    .with_rule("http/robots-txt"),
            ],
            RobotsRules::default(),
        );
    }

    evaluate_robots_body(&body, require_content_signal)
}

async fn check_sitemap_urls(
    ctx: &CheckContext,
    sitemap_locs: &[String],
    max_urls: usize,
    robots: &RobotsRules,
    allow_noindex: &[String],
) -> Finding {
    let sampled: Vec<&String> = sitemap_locs.iter().take(max_urls).collect();
    let mut issues = Vec::new();

    for loc in &sampled {
        let Ok(parsed) = Url::parse(loc) else {
            issues.push(format!("{loc}: invalid URL"));
            continue;
        };

        if robots.is_disallowed(parsed.path()) {
            issues.push(format!("{loc}: blocked by robots.txt"));
        }

        let resp = match ctx.client.get(parsed.clone()).send().await {
            Ok(r) => r,
            Err(err) => {
                issues.push(format!("{loc}: request failed ({err})"));
                continue;
            }
        };

        let status = resp.status();
        if status != StatusCode::OK {
            issues.push(format!("{loc}: HTTP {status} (expected 200)"));
            continue;
        }

        let x_robots: Vec<String> = resp
            .headers()
            .get_all("x-robots-tag")
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_owned))
            .collect();
        let x_robots_refs: Vec<&str> = x_robots.iter().map(String::as_str).collect();
        let html = resp.text().await.unwrap_or_default();

        if !is_path_allowed_noindex(loc, allow_noindex) && has_noindex(&html, &x_robots_refs) {
            issues.push(format!("{loc}: emits `noindex`"));
        }
    }

    if issues.is_empty() {
        Finding::pass(
            "sitemap URLs indexability",
            Some(format!(
                "checked {} of {} URL(s): all 200, crawlable, indexable",
                sampled.len(),
                sitemap_locs.len()
            )),
        )
        .with_rule("http/sitemap-indexability")
    } else {
        Finding::fail(
            "sitemap URLs indexability",
            Some(format!(
                "{} issue(s) across {} sampled sitemap URL(s)",
                issues.len(),
                sampled.len()
            )),
        )
        .with_rule("http/sitemap-indexability")
        .with_items(issues)
        .with_docs(DOCS_NOINDEX)
    }
}

async fn check_llms_txt(ctx: &CheckContext) -> Finding {
    let Ok(url) = ctx.base_url.join("/llms.txt") else {
        return Finding::fail("llms.txt", Some("invalid base URL".to_owned()))
            .with_rule("http/llms-txt");
    };

    let resp = match ctx.client.get(url.clone()).send().await {
        Ok(resp) => resp,
        Err(err) => {
            return Finding::fail("llms.txt", Some(format!("request failed: {err}")))
                .with_rule("http/llms-txt");
        }
    };

    let status = resp.status();
    if !status.is_success() {
        return Finding::fail("llms.txt", Some(format!("HTTP {status} at {url}")))
            .with_rule("http/llms-txt");
    }

    let body = resp.text().await.unwrap_or_default();
    let validation = validate_llms_txt(&body);
    if validation.is_valid() {
        Finding::pass(
            "llms.txt",
            Some(format!(
                "H1 present, {} markdown link(s)",
                validation.link_count
            )),
        )
        .with_rule("http/llms-txt")
    } else {
        let mut missing = Vec::new();
        if !validation.has_h1 {
            missing.push("H1 heading (`# Title`)");
        }
        if validation.link_count == 0 {
            missing.push("markdown link (`[Text](URL)`)");
        }
        Finding::fail(
            "llms.txt",
            Some(format!("missing {}", missing.join(" and "))),
        )
        .with_rule("http/llms-txt")
    }
}

async fn check_sitemap(
    ctx: &CheckContext,
    canonical: Option<&str>,
    robots_rules: &RobotsRules,
    config: &HttpConfig,
) -> Result<(Vec<Finding>, Vec<String>), CheckError> {
    let mut findings = Vec::new();
    let sitemap_url = ctx.base_url.join("/sitemap.xml")?;
    let resp = ctx.client.get(sitemap_url.clone()).send().await?;
    let status = resp.status();
    if !status.is_success() {
        findings.push(
            Finding::fail(
                "sitemap.xml",
                Some(format!("HTTP {status} at {sitemap_url}")),
            )
            .with_rule("http/sitemap"),
        );
        return Ok((findings, Vec::new()));
    }

    let xml = resp.text().await.unwrap_or_default();
    let sitemap_locs = extract_sitemap_locs(&xml);
    if sitemap_locs.is_empty() {
        findings.push(
            Finding::fail(
                "sitemap.xml",
                Some("HTTP 200 but contains no `<loc>` URLs".to_owned()),
            )
            .with_rule("http/sitemap"),
        );
        return Ok((findings, sitemap_locs));
    }

    findings.push(
        Finding::pass(
            "sitemap.xml",
            Some(format!("{} URL(s)", sitemap_locs.len())),
        )
        .with_rule("http/sitemap"),
    );
    let expected_home = canonical.unwrap_or(ctx.base_url.as_str());
    if sitemap_locs
        .iter()
        .any(|loc| urls_match(loc, expected_home))
    {
        findings.push(
            Finding::pass(
                "canonical/sitemap parity",
                Some(format!("{expected_home} listed in sitemap.xml")),
            )
            .with_rule("http/sitemap-canonical-parity"),
        );
    } else {
        findings.push(
            Finding::fail(
                "canonical/sitemap parity",
                Some(format!("{expected_home} not found in sitemap.xml")),
            )
            .with_rule("http/sitemap-canonical-parity"),
        );
    }

    if config.max_sitemap_urls > 0 {
        findings.push(
            check_sitemap_urls(
                ctx,
                &sitemap_locs,
                config.max_sitemap_urls,
                robots_rules,
                &config.allow_noindex,
            )
            .await,
        );
    }

    Ok((findings, sitemap_locs))
}

#[async_trait]
impl Check for HttpCheck {
    fn name(&self) -> &'static str {
        "http"
    }

    async fn run(&self, ctx: &CheckContext) -> Result<CheckReport, CheckError> {
        let mut findings = Vec::new();

        let home_resp = ctx.client.get(ctx.base_url.clone()).send().await?;
        let home_status = home_resp.status();
        let home_html = home_resp.text().await.unwrap_or_default();
        if home_status.is_success() {
            findings.push(
                Finding::pass(
                    "homepage",
                    Some(format!("HTTP {home_status} {}", ctx.base_url)),
                )
                .with_rule("http/homepage-status"),
            );
        } else {
            findings.push(
                Finding::fail(
                    "homepage",
                    Some(format!("HTTP {home_status} {}", ctx.base_url)),
                )
                .with_rule("http/homepage-status"),
            );
        }

        if self.config.check_html_size {
            findings.push(validate_html_size(home_html.len()));
        }
        if self.config.check_head_validity {
            findings.push(validate_head(&home_html));
        }
        if self.config.check_https_redirect {
            findings.push(check_https_redirect(ctx).await);
        }
        if self.config.check_www_redirect {
            findings.push(check_www_redirect(ctx).await);
        }
        if self.config.check_soft_404 {
            findings.push(check_soft_404(ctx).await);
        }

        let canonical = if self.config.check_canonical {
            if let Some(href) = extract_canonical(&home_html) {
                if urls_match(&href, ctx.base_url.as_str()) {
                    findings.push(
                        Finding::pass("canonical", Some(href.clone())).with_rule("http/canonical"),
                    );
                } else {
                    findings.push(
                        Finding::fail(
                            "canonical",
                            Some(format!("got `{href}`, expected `{}`", ctx.base_url)),
                        )
                        .with_rule("http/canonical"),
                    );
                }
                Some(href)
            } else {
                findings.push(
                    Finding::fail(
                        "canonical",
                        Some("missing `<link rel=\"canonical\">` on homepage".to_owned()),
                    )
                    .with_rule("http/canonical"),
                );
                None
            }
        } else {
            None
        };

        let robots_rules = if self.config.check_robots {
            let (robot_findings, rules) =
                check_robots(ctx, self.config.require_content_signal).await;
            findings.extend(robot_findings);
            rules
        } else {
            RobotsRules::default()
        };

        let sitemap_locs = if self.config.check_sitemap {
            let (sitemap_findings, locs) =
                check_sitemap(ctx, canonical.as_deref(), &robots_rules, &self.config).await?;
            findings.extend(sitemap_findings);
            locs
        } else {
            Vec::new()
        };

        if self.config.check_trailing_slash {
            findings.extend(
                check_trailing_slash_paths(ctx, &self.config.extra_paths, &sitemap_locs).await,
            );
        }
        if self.config.check_llms_txt {
            findings.push(check_llms_txt(ctx).await);
        }

        Ok(CheckReport::new(self.name(), findings))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HTML_SIZE_FAIL_BYTES, HTML_SIZE_WARN_BYTES, RobotsRules, extract_canonical,
        extract_sitemap_locs, find_invalid_head_tags, has_content_signal, has_noindex,
        is_path_allowed_noindex, validate_head, validate_html_size, validate_llms_txt,
    };
    use crate::check::Severity;

    #[test]
    fn validates_llms_txt_with_h1_and_markdown_links() {
        let valid = "# Example Site\n\n> Summary line.\n\n- [Home](https://example.com/)\n- [Docs](/docs)\n";
        let res = validate_llms_txt(valid);
        assert!(res.is_valid());
        assert!(res.has_h1);
        assert_eq!(res.link_count, 2);

        let missing_h1 = "## Not H1\n\n- [Home](https://example.com/)\n";
        let res = validate_llms_txt(missing_h1);
        assert!(!res.is_valid());
        assert!(!res.has_h1);
        assert_eq!(res.link_count, 1);

        let missing_links = "# Example Site\n\nPlain text only.\n";
        let res = validate_llms_txt(missing_links);
        assert!(!res.is_valid());
        assert!(res.has_h1);
        assert_eq!(res.link_count, 0);
    }

    #[test]
    fn extracts_canonical_link_regardless_of_attribute_order() {
        let html_a =
            r#"<html><head><link rel="canonical" href="https://example.com/"></head></html>"#;
        assert_eq!(
            extract_canonical(html_a).as_deref(),
            Some("https://example.com/")
        );

        let html_b = r"<LINK href='https://example.com/about' REL='canonical' />";
        assert_eq!(
            extract_canonical(html_b).as_deref(),
            Some("https://example.com/about")
        );

        let html_none = r#"<html><head><link rel="stylesheet" href="/app.css"></head></html>"#;
        assert_eq!(extract_canonical(html_none), None);
    }

    #[test]
    fn extracts_sitemap_locs() {
        let xml = r#"<?xml version="1.0"?>
<urlset>
  <url><loc>https://example.com/</loc></url>
  <url><loc> https://example.com/work </loc></url>
</urlset>"#;
        assert_eq!(
            extract_sitemap_locs(xml),
            vec!["https://example.com/", "https://example.com/work"]
        );
    }

    #[test]
    fn validates_html_size_thresholds() {
        assert_eq!(validate_html_size(50_000).severity, Severity::Pass);
        assert_eq!(
            validate_html_size(HTML_SIZE_WARN_BYTES).severity,
            Severity::Warn
        );
        let fail = validate_html_size(HTML_SIZE_FAIL_BYTES);
        assert_eq!(fail.severity, Severity::Fail);
        assert!(fail.docs_url.is_some());
    }

    #[test]
    fn detects_invalid_block_tags_in_head_and_ignores_scripts() {
        let clean = r#"<html><head>
            <title>Ok</title>
            <script type="application/ld+json">{"description": "<p>Safe inside script</p>"}</script>
            <!-- <div>commented out</div> -->
        </head><body><div>body div</div></body></html>"#;
        assert_eq!(find_invalid_head_tags(clean), Vec::<&str>::new());
        assert_eq!(validate_head(clean).severity, Severity::Pass);

        let broken = r#"<html><head><title>Bad</title><img src="/pixel.gif"><div class="banner"></div></head></html>"#;
        assert_eq!(find_invalid_head_tags(broken), vec!["div", "img"]);
        let finding = validate_head(broken);
        assert_eq!(finding.severity, Severity::Fail);
        assert!(finding.docs_url.is_some());
    }

    #[test]
    fn evaluates_robots_disallow_and_content_signal() {
        let robots =
            "User-agent: *\nDisallow: /admin/\nAllow: /admin/public\nContent-Signal: ai-train=no\n";
        let rules = RobotsRules::parse(robots);
        assert!(!rules.disallows_root());
        assert!(rules.is_disallowed("/admin/secret"));
        assert!(!rules.is_disallowed("/admin/public"));
        assert!(!rules.is_disallowed("/about"));
        assert!(has_content_signal(robots));

        let blocked_all = "User-agent: *\nDisallow: /\n";
        let blocked_rules = RobotsRules::parse(blocked_all);
        assert!(blocked_rules.disallows_root());
        assert!(!has_content_signal(blocked_all));

        let googlebot_override = "User-agent: *\nDisallow: /\n\nUser-agent: Googlebot\nAllow: /\n";
        let override_rules = RobotsRules::parse(googlebot_override);
        assert!(!override_rules.disallows_root());
    }

    #[test]
    fn detects_noindex_in_meta_and_headers() {
        let html_noindex =
            r#"<html><head><meta name="robots" content="index, noindex"></head></html>"#;
        assert!(has_noindex(html_noindex, &[]));

        let html_googlebot = r#"<html><head><meta name="googlebot" content="none"></head></html>"#;
        assert!(has_noindex(html_googlebot, &[]));

        let html_clean =
            r#"<html><head><meta name="robots" content="index, follow"></head></html>"#;
        assert!(!has_noindex(html_clean, &[]));
        assert!(has_noindex(html_clean, &["noindex, nofollow"]));
        assert!(has_noindex(html_clean, &["googlebot: noindex"]));
        assert!(!has_noindex(html_clean, &["bingbot: noindex"]));

        assert!(is_path_allowed_noindex(
            "https://example.com/draft",
            &["/draft".to_owned()]
        ));
        assert!(!is_path_allowed_noindex(
            "https://example.com/about",
            &["/draft".to_owned()]
        ));
    }
}
