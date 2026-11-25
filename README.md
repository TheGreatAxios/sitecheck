# sitecheck

[![CI](https://github.com/TheGreatAxios/sitecheck/actions/workflows/ci.yml/badge.svg)](https://github.com/TheGreatAxios/sitecheck/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/sitecheck.svg)](https://crates.io/crates/sitecheck)
[![docs.rs](https://docs.rs/sitecheck/badge.svg)](https://docs.rs/sitecheck)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A single-config CLI to audit live websites for HTTP, SEO, security headers, structured data, AI crawler readiness, and WCAG accessibility.

## Quickstart

Install from [crates.io](https://crates.io/crates/sitecheck):

```sh
cargo install sitecheck
```

Or install from source:

```sh
git clone https://github.com/TheGreatAxios/sitecheck.git
cd sitecheck
cargo install --path .
```

Generate `sitecheck.toml` and run an audit:

```sh
sitecheck init https://example.com/
sitecheck run
sitecheck run --json --strict
sitecheck indexnow --dry-run
sitecheck rules
```

Sample output:

```text
sitecheck https://example.com/

[PASS] http
  [PASS] http/homepage-status — homepage: HTTP 200 https://example.com/
  [PASS] http/robots-txt — robots.txt: HTTP 200 (128 bytes) with Sitemap directive

[WARN] security_headers
  [WARN] security/csp — Content-Security-Policy: missing header; add a Content-Security-Policy restricting script and frame sources
    docs: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy

Result: PASSED (2 pass, 1 warn, 0 fail)
```

Override any rule severity (`off`, `warn`, or `error`) in `sitecheck.toml`:

```toml
[rules]
"seo/apple-touch-icon" = "warn"
"security/csp" = "error"
"http/llms-txt" = "off"
```

## Checks

Built-in checks cover 47 cataloged rules (plus Clearway's built-in static WCAG 2.0/2.1/2.2 HTML rules under `[a11y]`). A check runs when its `[section]` appears in `sitecheck.toml`. `sitecheck init` enables all built-in sections by default.

| Section | Type | What it checks |
| --- | --- | --- |
| `[http]` | Built-in | Status codes, redirects, `robots.txt`, and sitemaps |
| `[seo]` | Built-in | Canonical tags, page metadata, favicons, and manifests |
| `[security_headers]` | Built-in | Security response headers and `security.txt` |
| `[structured_data]` | Built-in | JSON-LD schemas, Open Graph, and Twitter Cards |
| `[ai]` | Built-in | AI search and training bots in `robots.txt` |
| `[a11y]` | Built-in | Static HTML WCAG 2.0/2.1/2.2 accessibility via Clearway (no browser required) |
| `[indexnow]` | Opt-in | IndexNow verification key file check and `sitecheck indexnow` post-deploy submission |
| `[pagespeed]` | Opt-in | Google PageSpeed Insights category scores |
| `[lighthouse]` | Opt-in | Local Lighthouse runs in headless Chrome |
| `[axe]` | Opt-in | Live-browser WCAG accessibility audits via `@axe-core/cli` (including computed-style contrast) |
| `[search_console]` | Opt-in | Google Search Console sitemaps, URL inspection, indexing coverage %, and crawl lag |

## Post-Deploy IndexNow & Indexing Tracking

Ping IndexNow search engines right after deploying a site (reads `[indexnow]` and submits all same-origin `/sitemap.xml` URLs by default, or specific `--url` flags):

```sh
wrangler deploy && sitecheck indexnow
sitecheck indexnow --dry-run --json
sitecheck indexnow --url https://example.com/ --url https://example.com/blog
```

To track SEO, AEO, and Google Search Console indexing coverage/crawl lag over time in CI or cron, see [examples/track-indexing.sh](examples/track-indexing.sh).

## Documentation

- [Configuration reference](docs/configuration.md): all `sitecheck.toml` sections, rule overrides, and environment variables.
- [Extending and agent loops](docs/extending.md): writing check modules and running `--json --strict` in CI.
- [Example config](examples/sitecheck.toml): commented starter file.
- [Indexing tracker script](examples/track-indexing.sh): CI/CD post-deploy IndexNow ping and JSONL health history logger.
- [API docs on docs.rs](https://docs.rs/sitecheck) (or build locally with `cargo doc --no-deps --open`).

## License

Dual-licensed under MIT ([LICENSE-MIT](LICENSE-MIT)) or Apache-2.0 ([LICENSE-APACHE](LICENSE-APACHE)), at your option.
