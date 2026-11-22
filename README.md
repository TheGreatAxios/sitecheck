# sitecheck

[![CI](https://github.com/TheGreatAxios/sitecheck/actions/workflows/ci.yml/badge.svg)](https://github.com/TheGreatAxios/sitecheck/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/sitecheck.svg)](https://crates.io/crates/sitecheck)
[![docs.rs](https://docs.rs/sitecheck/badge.svg)](https://docs.rs/sitecheck)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Config-driven CLI with 48 deterministic rules for auditing websites—HTTP redirects, SEO, security headers, structured data, and AI crawlers.

## What It Checks

- **HTTP & Crawling:** `www`→apex and HTTPS 301s, trailing slashes, soft-404 probe, `<head>` validity, Googlebot 2 MB HTML cutoff, `robots.txt`, `sitemap.xml` indexability, `llms.txt`
- **SEO & Discovery:** canonical in `<head>`, unique titles and descriptions, raster favicon and Apple touch icon, web manifest, AI search vs. training bot `robots.txt` rules
- **Security & Structured Data:** HSTS, CSP, COOP, `X-Content-Type-Options`, `Referrer-Policy`, RFC 9116 `security.txt`, JSON-LD (`WebSite` Site Name, retired schema warnings, `sameAs`), Open Graph and Twitter Cards
- **Optional adapters:** IndexNow, PageSpeed Insights, Lighthouse, axe-core, Google Search Console
- **Built for CI & coding agents:** `[rules]` severity overrides (`off`/`warn`/`error`), `--json`, `--strict`

## Quickstart

```sh
cargo install sitecheck
sitecheck init https://example.com/
sitecheck run
sitecheck run --json --strict
sitecheck rules
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

Override any built-in rule severity in `sitecheck.toml`:

```toml
url = "https://example.com/"

[rules]
"seo/apple-touch-icon" = "warn"
"security/csp" = "error"
"http/llms-txt" = "off"

[http]
[seo]
[security_headers]
```

## Documentation

- [Configuration reference](docs/configuration.md) — all `sitecheck.toml` sections, rule overrides, and environment variables
- [Extending & agent loops](docs/extending.md) — adding a check module and running `--json --strict` in CI or coding agents
- [Example config](examples/sitecheck.toml) — complete commented starter file
- [API documentation](https://docs.rs/sitecheck) — Rust crate reference on docs.rs

## License

Dual-licensed under MIT (LICENSE-MIT) or Apache-2.0 (LICENSE-APACHE), at your option.
