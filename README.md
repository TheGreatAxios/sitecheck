# sitecheck

[![CI](https://github.com/TheGreatAxios/sitecheck/actions/workflows/ci.yml/badge.svg)](https://github.com/TheGreatAxios/sitecheck/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Config-driven CLI with 46 built-in HTTP, SEO, security, structured data, and AI crawler rules, plus optional adapters for IndexNow, PageSpeed Insights, Lighthouse, axe-core, and Google Search Console.

## What It Checks

- **HTTP & Crawling:** `www`→apex and HTTPS 301s, trailing slashes, soft-404 probe, `<head>` validity, Googlebot 2 MiB HTML cutoff, `robots.txt`, `sitemap.xml` indexability (same-origin enforced), `llms.txt`
- **SEO & Discovery:** canonical in `<head>`, unique titles and descriptions, raster favicon and Apple touch icon, web manifest, AI search vs. training bot `robots.txt` rules
- **Security & Structured Data:** HSTS, CSP, COOP, `X-Content-Type-Options`, `Referrer-Policy`, RFC 9116 `security.txt`, JSON-LD (`WebSite` Site Name, retired schema warnings, `sameAs`), Open Graph and Twitter Cards
- **Optional adapters:** IndexNow, PageSpeed Insights, Lighthouse, axe-core, Google Search Console
- **Built for CI & coding agents:** `[rules]` severity overrides (`off`/`warn`/`error`), per-check error isolation, `--json`, `--strict`

## Quickstart

Install from source (pre-release; `cargo install sitecheck` will be available once published to crates.io):

```sh
git clone https://github.com/TheGreatAxios/sitecheck.git
cd sitecheck
cargo install --path .
```

Run an audit:

```sh
sitecheck init https://example.com/
sitecheck run
sitecheck run --json --strict
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

Override any rule severity in `sitecheck.toml`:

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

- [Configuration reference](docs/configuration.md) — all `sitecheck.toml` sections, rule overrides, external tool behavior, and environment variables
- [Extending & agent loops](docs/extending.md) — adding a check module and running `--json --strict` in CI or coding agents
- [Example config](examples/sitecheck.toml) — complete commented starter file
- Rust API docs — generate locally with `cargo doc --no-deps --open`

## License

Dual-licensed under MIT (LICENSE-MIT) or Apache-2.0 (LICENSE-APACHE), at your option.
