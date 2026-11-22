# Extending `sitecheck` & Agent Loops

## Adding a New Check Module

Adding a check module takes three steps:

1. **Implement `Check` in `src/checks/<name>.rs`** — Define a `Deserialize` config struct with `#[serde(deny_unknown_fields)]` and a check type implementing `crate::check::Check`, then export the module from `src/checks/mod.rs`.
2. **Attach stable rule IDs** — Tag each finding with `.with_rule("category/rule-name")` (plus optional `.with_docs(url)` and `.with_items(vec)`), and add a matching `RuleSpec` entry to `BUILTIN_RULES` in `src/rules.rs` so it appears in `sitecheck rules` and supports `[rules]` overrides.
3. **Register the section in `src/config.rs`** — Add `pub <name>: Option<YourConfig>` to `Config` and instantiate it inside `Config::enabled_checks()`.

## Using `sitecheck` in CI and Coding-Agent Loops

Use `--json --strict` so CI jobs and coding agents get structured output and a non-zero exit code on any warning or failure:

```sh
# Full audit in CI (fails on any error or warning)
sitecheck run --json --strict

# Fast fix-loop targeting only deterministic modules
sitecheck run --only http,seo,security_headers,structured_data,ai --json --strict
```

Each JSON report has the shape:

```json
{
  "url": "https://example.com/",
  "passed": false,
  "reports": [
    {
      "name": "security_headers",
      "findings": [
        {
          "severity": "warn",
          "rule": "security/csp",
          "title": "Content-Security-Policy",
          "detail": "missing header; add a Content-Security-Policy restricting script and frame sources",
          "docs_url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"
        }
      ]
    }
  ]
}
```

Every finding includes `severity`, `rule`, and `title`; `detail`, `items` (affected URLs, headers, or selectors), and `docs_url` are included when applicable. A coding agent can loop over `reports[].findings[]` where `severity != "pass"`, inspect those fields, apply a fix, and re-run `sitecheck run --only <module> --json --strict` until `passed` is `true` and exit code is `0`.
