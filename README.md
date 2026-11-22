# sitecheck

[![CI](https://github.com/TheGreatAxios/sitecheck/actions/workflows/ci.yml/badge.svg)](https://github.com/TheGreatAxios/sitecheck/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/sitecheck.svg)](https://crates.io/crates/sitecheck)
[![docs.rs](https://docs.rs/sitecheck/badge.svg)](https://docs.rs/sitecheck)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`sitecheck` is a config-driven CLI with 48 built-in deterministic rules for auditing websites. It checks HTTP crawling and indexing, SEO metadata, Safari/iOS icons and web manifests, security headers and RFC 9116 `security.txt`, JSON-LD structured data, and AI crawler `robots.txt` directives. Optional adapters also run IndexNow, PageSpeed Insights, Lighthouse, axe-core, and Google Search Console checks from the same `sitecheck.toml` file.

## Quickstart

```sh
cargo install sitecheck
sitecheck init https://example.com/
sitecheck run
```

Sample output:

```text
sitecheck https://example.com/

[PASS] http
  [PASS] http/homepage-status — Homepage returned HTTP 200
  [PASS] http/robots-txt — /robots.txt is reachable and declares a Sitemap

[WARN] security_headers
  [WARN] security/csp — Missing Content-Security-Policy header

Result: PASSED (2 pass, 1 warn, 0 fail)
```

List all 48 built-in rules and their default severities with `sitecheck rules`.

## Configuration and `[rules]` overrides

Every deterministic rule has a stable `category/rule-name` ID that you can override under `[rules]` to `"off"`, `"warn"`, or `"error"`. See [`examples/sitecheck.toml`](examples/sitecheck.toml) for the full commented reference.

```toml
url = "https://example.com/"

[rules]
"seo/apple-touch-icon" = "warn"
"security/csp" = "error"
"http/llms-txt" = "off"

[http]
check_canonical = true
check_robots = true
check_sitemap = true

[seo]
check_favicon = true

[security_headers]
check_security_txt = false

[structured_data]
required_types = ["Organization", "WebSite"]

[ai]
allow_blocked = []
```

## Using with coding agents and CI

```sh
# Machine-readable JSON, failing on both errors and warnings
sitecheck run --json --strict

# Run a targeted subset of modules during a fix loop
sitecheck run --only http,seo,structured_data,ai --json
```

`sitecheck run` exits non-zero when any check fails (or on warnings when `--strict` is set). Each JSON finding includes a stable `rule` ID, `items` listing the affected URLs or headers, and a `docs_url` pointing to the relevant specification so coding agents and CI jobs can act on failures without scraping terminal text.

## Adding a new check

1. Create `src/checks/<name>.rs` with a config struct and a check type implementing `crate::check::Check`.
2. Attach stable `category/rule-name` IDs via `Finding::with_rule(...)` and register them in `BUILTIN_RULES` (`src/rules.rs`).
3. Add `pub <name>: Option<...>` to `Config` in `src/config.rs` and register it in `Config::enabled_checks()`.

## License

Dual-licensed under MIT (LICENSE-MIT) or Apache-2.0 (LICENSE-APACHE), at your option.
