# Configuration Reference

`sitecheck` reads its configuration from `sitecheck.toml` (or the path passed to `--config`). Unknown fields are rejected at parse time so typos fail fast.

```toml
url = "https://example.com/"
```

Only `url` is required at the top level. A check module runs when its `[section]` table is present in the file.

## `[rules]`

Override the severity of any rule by its `category/rule-name` ID. Run `sitecheck rules` to list the 46 built-in HTTP/SEO/security/schema/AI rules plus the 2 cataloged optional adapter rules (`indexnow/key-file`, `axe/wcag`) and their default severities (`pass`, `warn`, or `fail`).

| Value | Effect |
| --- | --- |
| `"off"` | Suppress findings for this rule |
| `"warn"` | Downgrade `fail` findings to `warn` |
| `"error"` | Escalate `warn` findings to `fail` |

```toml
[rules]
"seo/apple-touch-icon" = "warn"
"security/csp" = "error"
"http/llms-txt" = "off"
```

Optional adapters also attach rule IDs so `[rules]` works uniformly across all modules:
- `[axe]`: `axe/<violation-id>`, with `"axe/wcag"` acting as a fallback for all `axe/*` findings.
- `[pagespeed]`: `pagespeed/score-<category>` and `pagespeed/<audit-id>`.
- `[lighthouse]`: `lighthouse/score-<category>` and `lighthouse/<audit-id>`.
- `[search_console]`: `gsc/sitemap`, `gsc/index`, and `gsc/canonical`.
- Check runtime errors: `<check-name>/error` (when a check returns an error, `sitecheck` records a `fail` finding and continues running remaining checks).

## `[http]`

Checks HTTP status codes, redirects, HTML size, `<head>` validity, canonical tags, `robots.txt`, `sitemap.xml`, and `llms.txt`.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `check_www_redirect` | `bool` | `true` | Verify `www.` permanently redirects (301/308) to the apex domain |
| `check_https_redirect` | `bool` | `true` | Verify `http://` permanently redirects (301/308) to `https://` |
| `check_soft_404` | `bool` | `true` | Probe an unknown path and require HTTP 404 or 410 |
| `check_html_size` | `bool` | `true` | Warn at 1.5 MiB and fail at Googlebot's 2 MiB HTML cutoff |
| `check_head_validity` | `bool` | `true` | Reject body/media tags (`div`, `img`, `iframe`, etc.) inside `<head>` |
| `check_trailing_slash` | `bool` | `true` | Verify trailing-slash redirect consistency |
| `check_canonical` | `bool` | `true` | Require homepage `<link rel="canonical">` to match `url` |
| `check_sitemap` | `bool` | `true` | Fetch `/sitemap.xml`, check canonical parity, and verify sampled URLs |
| `check_robots` | `bool` | `true` | Fetch `/robots.txt`, check size (< 500 KiB), crawlability, and `Sitemap:` |
| `require_content_signal` | `bool` | `false` | Require a `Content-Signal:` directive in `/robots.txt` |
| `allow_noindex` | `string[]` | `[]` | Paths permitted to declare `noindex` |
| `max_sitemap_urls` | `usize` | `15` | Maximum sitemap URLs sampled for indexability checks |
| `check_llms_txt` | `bool` | `true` | Validate `/llms.txt` structure (H1 heading and Markdown links) |
| `extra_paths` | `string[]` | `[]` | Paths to probe for trailing-slash redirects (when non-empty, overrides the sitemap sample) |

## `[seo]`

Checks `<head>` canonical placement, unique titles and meta descriptions across sampled pages, favicons, Apple touch icons, and web app manifests.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `check_favicon` | `bool` | `true` | Probe `<link rel="icon">` (or `/favicon.ico`) and warn if only SVG is declared; Apple touch icon and web manifest checks (`name`/`short_name` JSON validation) run whenever `[seo]` is enabled |
| `max_sitemap_urls` | `usize` | `15` | Maximum sitemap URLs sampled for uniqueness and metadata checks |

## `[security_headers]`

Checks `Strict-Transport-Security`, `Content-Security-Policy`, `Cross-Origin-Opener-Policy`, `X-Content-Type-Options`, and `Referrer-Policy` on the homepage response.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `check_security_txt` | `bool` | `false` | Validate `/.well-known/security.txt` per RFC 9116 |

## `[structured_data]`

Parses `<script type="application/ld+json">` blocks and social metadata tags.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `required_types` | `string[]` | `[]` | Schema.org `@type` values that must appear on the homepage |
| `check_site_name` | `bool` | `true` | Check for `WebSite` JSON-LD with a valid `name` |
| `check_open_graph` | `bool` | `true` | Verify Open Graph (`og:*`) meta tags |
| `check_twitter` | `bool` | `true` | Verify Twitter Card (`twitter:*`) meta tags |
| `paths` | `string[]` | `[]` | Paths to inspect; when non-empty, overrides the default `["/"]` list (include `"/"` to also check the homepage) |

## `[ai]`

Evaluates `/robots.txt` rules against search bots (`Googlebot`, `Bingbot`, `Applebot`, `OAI-SearchBot`, `ChatGPT-User`, `Claude-SearchBot`, `Claude-User`, `PerplexityBot`, `ExaSearchBot`) and training bots (`GPTBot`, `ClaudeBot`, `Applebot-Extended`, `Google-Extended`, `Meta-ExternalAgent`, `CCBot`).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `allow_blocked` | `string[]` | `[]` | Search bot user agents intentionally disallowed in `/robots.txt` |

## `[indexnow]`

Verifies that the configured IndexNow verification key file is served at HTTP 200 and matches `key`.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `string` | *(required)* | IndexNow verification key |
| `key_location` | `string` | `/<key>.txt` | Custom path or URL for the key file |

## `[pagespeed]`

Queries the Google PageSpeed Insights API and enforces minimum category scores (0–100).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `strategies` | `string[]` | `["mobile", "desktop"]` | Strategies to query (`"mobile"`, `"desktop"`) |
| `api_key_env` | `string` | `"PSI_API_KEY"` | Environment variable holding an optional PSI API key |
| `min_scores` | `table` | `{}` | Optional thresholds: `performance`, `accessibility`, `best_practices`, `seo` (`0..=100`) |

## `[lighthouse]`

Runs a local `lighthouse` CLI binary in headless Chrome and enforces minimum category scores (0–100). When `[lighthouse]` is enabled, `sitecheck` launches Chrome with `--chrome-flags="--headless --no-sandbox"`.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `binary` | `string` | `"lighthouse"` | Path or name of the Lighthouse executable |
| `form_factors` | `string[]` | `["mobile"]` | Form factors to run (`"mobile"`, `"desktop"`) |
| `min_scores` | `table` | `{}` | Optional thresholds: `performance`, `accessibility`, `best_practices`, `seo` (`0..=100`) |
| `extra_args` | `string[]` | `[]` | Additional CLI flags forwarded to `lighthouse` |

## `[axe]`

Runs `@axe-core/cli` against configured paths to check WCAG accessibility rules. If `bin` is omitted and `axe` is not found on `PATH`, `sitecheck` falls back to running `npx --yes @axe-core/cli`, which downloads and runs the package via npm.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `bin` | `string` | `None` | Path or name of the axe CLI executable (defaults to searching `PATH` for `axe`, then falling back to `npx --yes @axe-core/cli`; setting `bin = "axe"` explicitly disables the `npx` fallback) |
| `tags` | `string[]` | `["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]` | axe rule tags to evaluate |
| `paths` | `string[]` | `["/"]` | Site paths to audit |

## `[search_console]`

Queries Google Search Console sitemaps and URL Inspection APIs using a Google Cloud service account.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `site_url` | `string` | top-level `url` | Search Console property (URL prefix or `sc-domain:example.com`) |
| `service_account_env` | `string` | `"GOOGLE_APPLICATION_CREDENTIALS"` | Env var pointing to a service account JSON file path or inline JSON |
| `inspect_urls` | `string[]` | `[]` | URLs to submit to the URL Inspection API (defaults to inspecting the site's homepage `url` when empty) |

## Environment Variables

| Variable | Used By | Required | Notes |
| --- | --- | --- | --- |
| `PSI_API_KEY` | `[pagespeed]` | Optional | Raises Google PageSpeed Insights rate limits. Override the variable name with `pagespeed.api_key_env`. |
| `GOOGLE_APPLICATION_CREDENTIALS` | `[search_console]` | Required when `[search_console]` is enabled | Path to a Google service account JSON key file, or the raw JSON string itself. Override the variable name with `search_console.service_account_env`. |
