use std::fmt::Write as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleSpec {
    pub id: &'static str,
    pub category: &'static str,
    pub default_severity: &'static str,
    pub description: &'static str,
}

pub const BUILTIN_RULES: &[RuleSpec] = &[
    // http
    RuleSpec {
        id: "http/homepage-status",
        category: "http",
        default_severity: "fail",
        description: "Homepage returns an HTTP 2xx status",
    },
    RuleSpec {
        id: "http/html-size",
        category: "http",
        default_severity: "fail",
        description: "Homepage HTML stays under Googlebot's 2 MiB cutoff (warn >= 1.5 MiB)",
    },
    RuleSpec {
        id: "http/valid-head",
        category: "http",
        default_severity: "fail",
        description: "<head> contains no non-metadata block or media tags",
    },
    RuleSpec {
        id: "http/https-redirect",
        category: "http",
        default_severity: "fail",
        description: "HTTP permanently redirects (301/308) to HTTPS within 2 hops",
    },
    RuleSpec {
        id: "http/www-redirect",
        category: "http",
        default_severity: "fail",
        description: "www subdomain permanently redirects (301/308) to apex domain",
    },
    RuleSpec {
        id: "http/soft-404",
        category: "http",
        default_severity: "fail",
        description: "Unknown path returns HTTP 404 or 410 (no soft 404)",
    },
    RuleSpec {
        id: "http/canonical",
        category: "http",
        default_severity: "fail",
        description: "Homepage <link rel=\"canonical\"> matches configured base URL",
    },
    RuleSpec {
        id: "http/robots-txt",
        category: "http",
        default_severity: "fail",
        description: "/robots.txt is reachable, non-empty, and declares a Sitemap directive",
    },
    RuleSpec {
        id: "http/robots-size",
        category: "http",
        default_severity: "fail",
        description: "/robots.txt stays under Googlebot's 500 KiB limit",
    },
    RuleSpec {
        id: "http/robots-crawlable",
        category: "http",
        default_severity: "fail",
        description: "/robots.txt does not disallow `/` for `*` or `Googlebot`",
    },
    RuleSpec {
        id: "http/content-signal",
        category: "http",
        default_severity: "fail",
        description: "/robots.txt declares a `Content-Signal:` directive (opt-in)",
    },
    RuleSpec {
        id: "http/sitemap",
        category: "http",
        default_severity: "fail",
        description: "/sitemap.xml is reachable and contains `<loc>` URLs",
    },
    RuleSpec {
        id: "http/sitemap-canonical-parity",
        category: "http",
        default_severity: "fail",
        description: "Homepage canonical URL is listed in /sitemap.xml",
    },
    RuleSpec {
        id: "http/sitemap-indexability",
        category: "http",
        default_severity: "fail",
        description: "Sampled sitemap URLs return HTTP 200, are crawlable, and omit `noindex`",
    },
    RuleSpec {
        id: "http/trailing-slash",
        category: "http",
        default_severity: "fail",
        description: "Flipped trailing-slash URLs permanently redirect to canonical form",
    },
    RuleSpec {
        id: "http/llms-txt",
        category: "http",
        default_severity: "fail",
        description: "/llms.txt exists with an H1 heading and at least one markdown link",
    },
    // seo
    RuleSpec {
        id: "seo/homepage-fetch",
        category: "seo",
        default_severity: "fail",
        description: "Homepage is reachable for SEO metadata inspection",
    },
    RuleSpec {
        id: "seo/canonical-head",
        category: "seo",
        default_severity: "fail",
        description: "Single absolute https:// <link rel=\"canonical\"> inside <head>",
    },
    RuleSpec {
        id: "seo/title",
        category: "seo",
        default_severity: "fail",
        description: "Non-empty <title> tag is present",
    },
    RuleSpec {
        id: "seo/meta-description",
        category: "seo",
        default_severity: "fail",
        description: "Non-empty <meta name=\"description\"> tag is present",
    },
    RuleSpec {
        id: "seo/meta-viewport",
        category: "seo",
        default_severity: "fail",
        description: "<meta name=\"viewport\"> tag is present",
    },
    RuleSpec {
        id: "seo/html-lang",
        category: "seo",
        default_severity: "fail",
        description: "Non-empty `lang` attribute is present on <html>",
    },
    RuleSpec {
        id: "seo/snippet-directives",
        category: "seo",
        default_severity: "warn",
        description: "No restrictive `nosnippet` or `max-image-preview:none` directive",
    },
    RuleSpec {
        id: "seo/favicon",
        category: "seo",
        default_severity: "fail",
        description: "Declared favicon (or /favicon.ico) returns HTTP 2xx",
    },
    RuleSpec {
        id: "seo/favicon-raster",
        category: "seo",
        default_severity: "warn",
        description: "Raster (PNG/ICO/JPEG) favicon fallback present alongside SVG",
    },
    RuleSpec {
        id: "seo/apple-touch-icon",
        category: "seo",
        default_severity: "warn",
        description: "<link rel=\"apple-touch-icon\"> exists and returns HTTP 200 image/png",
    },
    RuleSpec {
        id: "seo/web-manifest",
        category: "seo",
        default_severity: "fail",
        description: "Declared <link rel=\"manifest\"> returns HTTP 200 valid JSON with name/short_name",
    },
    RuleSpec {
        id: "seo/duplicate-title",
        category: "seo",
        default_severity: "warn",
        description: "Sampled sitemap pages have unique <title> values",
    },
    RuleSpec {
        id: "seo/duplicate-description",
        category: "seo",
        default_severity: "warn",
        description: "Sampled sitemap pages have unique meta descriptions",
    },
    // security
    RuleSpec {
        id: "security/hsts",
        category: "security",
        default_severity: "warn",
        description: "Strict-Transport-Security header is present",
    },
    RuleSpec {
        id: "security/csp",
        category: "security",
        default_severity: "warn",
        description: "Content-Security-Policy header is present",
    },
    RuleSpec {
        id: "security/coop",
        category: "security",
        default_severity: "warn",
        description: "Cross-Origin-Opener-Policy header is present",
    },
    RuleSpec {
        id: "security/x-content-type-options",
        category: "security",
        default_severity: "warn",
        description: "X-Content-Type-Options header is present",
    },
    RuleSpec {
        id: "security/referrer-policy",
        category: "security",
        default_severity: "warn",
        description: "Referrer-Policy header is present",
    },
    RuleSpec {
        id: "security/security-txt",
        category: "security",
        default_severity: "fail",
        description: "/.well-known/security.txt (RFC 9116) has valid Contact and unexpired Expires (opt-in)",
    },
    // schema
    RuleSpec {
        id: "schema/fetch",
        category: "schema",
        default_severity: "fail",
        description: "Target path is reachable for structured data inspection",
    },
    RuleSpec {
        id: "schema/json-ld-syntax",
        category: "schema",
        default_severity: "fail",
        description: "All <script type=\"application/ld+json\"> blocks contain valid JSON",
    },
    RuleSpec {
        id: "schema/json-ld-present",
        category: "schema",
        default_severity: "warn",
        description: "Page includes at least one JSON-LD block (fail when required_types is configured)",
    },
    RuleSpec {
        id: "schema/required-type",
        category: "schema",
        default_severity: "fail",
        description: "All configured required_types appear in JSON-LD @type values",
    },
    RuleSpec {
        id: "schema/website-site-name",
        category: "schema",
        default_severity: "warn",
        description: "Homepage JSON-LD includes @type WebSite with non-empty name and url",
    },
    RuleSpec {
        id: "schema/deprecated-types",
        category: "schema",
        default_severity: "warn",
        description: "No retired Google Search rich-result @type values present",
    },
    RuleSpec {
        id: "schema/same-as",
        category: "schema",
        default_severity: "fail",
        description: "Every JSON-LD `sameAs` entry is a valid https:// URL",
    },
    RuleSpec {
        id: "schema/open-graph",
        category: "schema",
        default_severity: "fail",
        description: "Open Graph meta tags (og:title, og:description, og:image, og:url) are present",
    },
    RuleSpec {
        id: "schema/twitter-card",
        category: "schema",
        default_severity: "fail",
        description: "Twitter Card meta tags (twitter:card, twitter:title, twitter:description) are present",
    },
    // ai
    RuleSpec {
        id: "ai/search-bots-allowed",
        category: "ai",
        default_severity: "fail",
        description: "Search and live-retrieval bots (Googlebot, Bingbot, Applebot, OAI-SearchBot, etc.) are not disallowed on `/`",
    },
    RuleSpec {
        id: "ai/training-policy",
        category: "ai",
        default_severity: "pass",
        description: "Reports which AI training bots are disallowed vs allowed and whether Content-Signal is declared",
    },
    // indexnow (optional adapter)
    RuleSpec {
        id: "indexnow/key-file",
        category: "indexnow",
        default_severity: "fail",
        description: "IndexNow key file returns HTTP 200 with body matching configured key",
    },
    // axe (optional adapter)
    RuleSpec {
        id: "axe/wcag",
        category: "axe",
        default_severity: "fail",
        description: "Optional @axe-core/cli WCAG accessibility audit reports zero critical/serious violations",
    },
];

#[must_use]
pub fn format_rules_catalog() -> String {
    let id_width = BUILTIN_RULES
        .iter()
        .map(|r| r.id.len())
        .max()
        .unwrap_or(10)
        .max("RULE".len());
    let cat_width = BUILTIN_RULES
        .iter()
        .map(|r| r.category.len())
        .max()
        .unwrap_or(8)
        .max("CATEGORY".len());
    let sev_width = BUILTIN_RULES
        .iter()
        .map(|r| r.default_severity.len())
        .max()
        .unwrap_or(7)
        .max("DEFAULT".len());

    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<id_width$}  {:<cat_width$}  {:<sev_width$}  DESCRIPTION",
        "RULE", "CATEGORY", "DEFAULT"
    );
    let _ = writeln!(
        out,
        "{:-<id_width$}  {:-<cat_width$}  {:-<sev_width$}  {:-<40}",
        "", "", "", ""
    );

    for rule in BUILTIN_RULES {
        let _ = writeln!(
            out,
            "{:<id_width$}  {:<cat_width$}  {:<sev_width$}  {}",
            rule.id, rule.category, rule.default_severity, rule.description
        );
    }

    let core_count = BUILTIN_RULES
        .iter()
        .filter(|r| !matches!(r.category, "indexnow" | "axe"))
        .count();
    let adapter_count = BUILTIN_RULES.len() - core_count;
    let _ = writeln!(
        out,
        "\n{} cataloged rules ({core_count} built-in HTTP/SEO/security/schema/AI + {adapter_count} optional adapter rules).",
        BUILTIN_RULES.len()
    );
    out
}

#[cfg(test)]
mod tests {
    use super::BUILTIN_RULES;

    #[test]
    fn all_builtin_rules_use_valid_severities() {
        for rule in BUILTIN_RULES {
            assert!(
                matches!(rule.default_severity, "pass" | "warn" | "fail"),
                "rule `{}` has invalid default_severity `{}`",
                rule.id,
                rule.default_severity
            );
        }
    }
}
