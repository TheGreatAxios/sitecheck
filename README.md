# sitecheck

[![CI](https://github.com/TheGreatAxios/sitecheck/actions/workflows/ci.yml/badge.svg)](https://github.com/TheGreatAxios/sitecheck/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/sitecheck.svg)](https://crates.io/crates/sitecheck)
[![docs.rs](https://docs.rs/sitecheck/badge.svg)](https://docs.rs/sitecheck)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A single-config CLI to audit live websites for HTTP, SEO, security headers, structured data, and AI crawler readiness.

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

Built-in checks cover 46 rules. A check runs when its `[section]` appears in `sitecheck.toml`.

| Section | Type | What it checks |
| --- | --- | --- |
| `[http]` | Built-in | Status codes, redirects, `robots.txt`, and sitemaps |
| `[seo]` | Built-in | Canonical tags, page metadata, favicons, and manifests |
| `[security_headers]` | Built-in | Security response headers and `security.txt` |
| `[structured_data]` | Built-in | JSON-LD schemas, Open Graph, and Twitter Cards |
| `[ai]` | Built-in | AI search and training bots in `robots.txt` |
| `[indexnow]` | Opt-in | IndexNow verification key file availability |
| `[pagespeed]` | Opt-in | Google PageSpeed Insights category scores |
| `[lighthouse]` | Opt-in | Local Lighthouse runs in headless Chrome |
| `[axe]` | Opt-in | WCAG accessibility audits via `@axe-core/cli` |
| `[search_console]` | Opt-in | Google Search Console sitemaps and URL inspection |

## Documentation

- [Configuration reference](docs/configuration.md): all `sitecheck.toml` sections, rule overrides, and environment variables.
- [Extending and agent loops](docs/extending.md): writing check modules and running `--json --strict` in CI.
- [Example config](examples/sitecheck.toml): commented starter file.
- [API docs on docs.rs](https://docs.rs/sitecheck) (or build locally with `cargo doc --no-deps --open`).

## License

Dual-licensed under MIT ([LICENSE-MIT](LICENSE-MIT)) or Apache-2.0 ([LICENSE-APACHE](LICENSE-APACHE)), at your option.
