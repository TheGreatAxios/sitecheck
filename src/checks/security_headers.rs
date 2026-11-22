use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use reqwest::StatusCode;
use reqwest::header::HeaderMap;
use serde::Deserialize;

use crate::check::{
    Check, CheckContext, CheckError, CheckReport, Finding, MAX_TEXT_BODY_BYTES, read_body_limited,
};

const DOCS_SECURITY_TXT: &str = "https://www.rfc-editor.org/rfc/rfc9116";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityHeadersConfig {
    #[serde(default)]
    pub check_security_txt: bool,
}

pub struct SecurityHeadersCheck {
    config: SecurityHeadersConfig,
}

impl SecurityHeadersCheck {
    #[must_use]
    pub const fn new(config: SecurityHeadersConfig) -> Self {
        Self { config }
    }
}

struct HeaderSpec {
    rule: &'static str,
    name: &'static str,
    hint: &'static str,
    docs_url: &'static str,
}

const REQUIRED_HEADERS: &[HeaderSpec] = &[
    HeaderSpec {
        rule: "security/hsts",
        name: "Strict-Transport-Security",
        hint: "missing header; add e.g. Strict-Transport-Security: max-age=31536000; includeSubDomains",
        docs_url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    },
    HeaderSpec {
        rule: "security/csp",
        name: "Content-Security-Policy",
        hint: "missing header; add a Content-Security-Policy restricting script and frame sources",
        docs_url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    },
    HeaderSpec {
        rule: "security/coop",
        name: "Cross-Origin-Opener-Policy",
        hint: "missing header; add e.g. Cross-Origin-Opener-Policy: same-origin",
        docs_url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
    },
    HeaderSpec {
        rule: "security/x-content-type-options",
        name: "X-Content-Type-Options",
        hint: "missing header; add X-Content-Type-Options: nosniff",
        docs_url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    },
    HeaderSpec {
        rule: "security/referrer-policy",
        name: "Referrer-Policy",
        hint: "missing header; add e.g. Referrer-Policy: strict-origin-when-cross-origin",
        docs_url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    },
];

#[must_use]
pub fn evaluate_security_headers(headers: &HeaderMap) -> Vec<Finding> {
    REQUIRED_HEADERS
        .iter()
        .map(
            |spec| match headers.get(spec.name).and_then(|v| v.to_str().ok()) {
                Some(value) if !value.trim().is_empty() => {
                    Finding::pass(spec.name, Some(value.trim().to_owned())).with_rule(spec.rule)
                }
                _ => Finding::warn(spec.name, Some(spec.hint.to_owned()))
                    .with_rule(spec.rule)
                    .with_docs(spec.docs_url),
            },
        )
        .collect()
}

const fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

const fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Converts a Gregorian civil date to days since 1970-01-01 (Howard Hinnant's algorithm).
const fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = month as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parses an RFC 3339 timestamp (e.g. `2027-01-01T00:00:00Z`) into Unix epoch seconds.
#[must_use]
pub fn parse_rfc3339_unix(input: &str) -> Option<i64> {
    let trimmed = input.trim();
    let bytes = trimmed.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't' | b' ')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }

    let year: i64 = trimmed.get(0..4)?.parse().ok()?;
    let month: u32 = trimmed.get(5..7)?.parse().ok()?;
    let day: u32 = trimmed.get(8..10)?.parse().ok()?;
    let hour: u32 = trimmed.get(11..13)?.parse().ok()?;
    let minute: u32 = trimmed.get(14..16)?.parse().ok()?;
    let second: u32 = trimmed.get(17..19)?.parse().ok()?;

    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }

    let mut rest = trimmed.get(19..)?;
    if let Some(after_dot) = rest.strip_prefix('.') {
        let frac_len = after_dot.bytes().take_while(u8::is_ascii_digit).count();
        if frac_len == 0 {
            return None;
        }
        rest = after_dot.get(frac_len..)?;
    }

    let offset_secs: i64 = if rest.eq_ignore_ascii_case("Z") {
        0
    } else if rest.len() == 6 && rest.as_bytes()[3] == b':' {
        let sign = match rest.as_bytes()[0] {
            b'+' => 1i64,
            b'-' => -1i64,
            _ => return None,
        };
        let off_h: i64 = rest.get(1..3)?.parse().ok()?;
        let off_m: i64 = rest.get(4..6)?.parse().ok()?;
        if off_h > 23 || off_m > 59 {
            return None;
        }
        sign * (off_h * 3600 + off_m * 60)
    } else {
        return None;
    };

    let days = days_from_civil(year, month, day);
    let secs_in_day = i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second);
    Some(days * 86_400 + secs_in_day - offset_secs)
}

fn is_valid_security_contact(value: &str) -> bool {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("mailto:") {
        !rest.is_empty() && rest.contains('@')
    } else if let Some(rest) = lower.strip_prefix("https://") {
        !rest.is_empty()
    } else if let Some(rest) = lower.strip_prefix("tel:") {
        !rest.is_empty()
    } else {
        false
    }
}

/// Validates RFC 9116 `/.well-known/security.txt` content against `now_unix` (Unix epoch seconds).
#[must_use]
pub fn validate_security_txt(body: &str, now_unix: i64) -> Finding {
    let mut valid_contacts = 0usize;
    let mut expires_raw: Option<String> = None;

    for raw_line in body.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let val = val.trim();
        if key.eq_ignore_ascii_case("contact") && is_valid_security_contact(val) {
            valid_contacts += 1;
        } else if key.eq_ignore_ascii_case("expires") && expires_raw.is_none() {
            expires_raw = Some(val.to_owned());
        }
    }

    let mut issues = Vec::new();
    if valid_contacts == 0 {
        issues.push("missing valid `Contact:` (`mailto:`, `https://`, or `tel:`)".to_owned());
    }

    match expires_raw.as_deref() {
        None => issues.push("missing `Expires:` RFC 3339 timestamp".to_owned()),
        Some(raw) => match parse_rfc3339_unix(raw) {
            None => issues.push(format!("invalid RFC 3339 `Expires:` value `{raw}`")),
            Some(ts) if ts <= now_unix => {
                issues.push(format!("`Expires:` timestamp `{raw}` is in the past"));
            }
            Some(_) => {}
        },
    }

    if issues.is_empty() {
        Finding::pass(
            "security.txt",
            Some(format!(
                "{valid_contacts} contact(s), expires {}",
                expires_raw.as_deref().unwrap_or("")
            )),
        )
        .with_rule("security/security-txt")
    } else {
        Finding::fail("security.txt", Some(issues.join("; ")))
            .with_rule("security/security-txt")
            .with_docs(DOCS_SECURITY_TXT)
    }
}

async fn check_security_txt(ctx: &CheckContext) -> Finding {
    let Ok(url) = ctx.base_url.join("/.well-known/security.txt") else {
        return Finding::fail("security.txt", Some("invalid base URL".to_owned()))
            .with_rule("security/security-txt");
    };

    let resp = match ctx.client.get(url.clone()).send().await {
        Ok(resp) => resp,
        Err(err) => {
            return Finding::fail(
                "security.txt",
                Some(format!("request to {url} failed: {err}")),
            )
            .with_rule("security/security-txt")
            .with_docs(DOCS_SECURITY_TXT);
        }
    };

    if resp.status() != StatusCode::OK {
        return Finding::fail(
            "security.txt",
            Some(format!("HTTP {} at {url} (expected 200)", resp.status())),
        )
        .with_rule("security/security-txt")
        .with_docs(DOCS_SECURITY_TXT);
    }

    let body = match read_body_limited(resp, MAX_TEXT_BODY_BYTES).await {
        Ok(body) => body,
        Err(err) => {
            return Finding::fail("security.txt", Some(format!("failed to read {url}: {err}")))
                .with_rule("security/security-txt")
                .with_docs(DOCS_SECURITY_TXT);
        }
    };
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    validate_security_txt(&body, now_unix)
}

#[async_trait]
impl Check for SecurityHeadersCheck {
    fn name(&self) -> &'static str {
        "security_headers"
    }

    async fn run(&self, ctx: &CheckContext) -> Result<CheckReport, CheckError> {
        let head = ctx.client.head(ctx.base_url.clone()).send().await?;
        let resp = if matches!(
            head.status(),
            StatusCode::METHOD_NOT_ALLOWED | StatusCode::NOT_IMPLEMENTED
        ) {
            ctx.client.get(ctx.base_url.clone()).send().await?
        } else {
            head
        };

        let mut findings = evaluate_security_headers(resp.headers());
        if self.config.check_security_txt {
            findings.push(check_security_txt(ctx).await);
        }

        Ok(CheckReport::new(self.name(), findings))
    }
}

#[cfg(test)]
mod tests {
    use reqwest::header::{HeaderMap, HeaderValue};

    use super::{evaluate_security_headers, parse_rfc3339_unix, validate_security_txt};
    use crate::check::Severity;

    #[test]
    fn passes_when_all_headers_present() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
        headers.insert(
            "content-security-policy",
            HeaderValue::from_static("default-src 'self'"),
        );
        headers.insert(
            "cross-origin-opener-policy",
            HeaderValue::from_static("same-origin"),
        );
        headers.insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
        headers.insert(
            "referrer-policy",
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        );

        let findings = evaluate_security_headers(&headers);
        assert_eq!(findings.len(), 5);
        assert!(findings.iter().all(|f| f.severity == Severity::Pass));
        assert!(findings.iter().all(|f| f.rule.is_some()));
    }

    #[test]
    fn warns_with_docs_url_when_headers_missing() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );

        let findings = evaluate_security_headers(&headers);
        assert_eq!(findings.len(), 5);

        let xcto = findings
            .iter()
            .find(|f| f.title == "X-Content-Type-Options")
            .expect("x-content-type-options finding present");
        assert_eq!(xcto.severity, Severity::Pass);
        assert_eq!(
            xcto.rule.as_deref(),
            Some("security/x-content-type-options")
        );
        assert_eq!(xcto.detail.as_deref(), Some("nosniff"));
        assert!(xcto.docs_url.is_none());

        let csp = findings
            .iter()
            .find(|f| f.title == "Content-Security-Policy")
            .expect("csp finding present");
        assert_eq!(csp.severity, Severity::Warn);
        assert_eq!(csp.rule.as_deref(), Some("security/csp"));
        assert!(csp.detail.as_deref().is_some_and(|d| d.contains("missing")));
        assert!(
            csp.docs_url
                .as_deref()
                .is_some_and(|u| u.starts_with("https://developer.mozilla.org/"))
        );
    }

    #[test]
    fn validates_security_txt_contact_and_expires() {
        let now = parse_rfc3339_unix("2026-06-01T00:00:00Z").expect("valid test timestamp");

        let valid = "\
# Security policy
Contact: mailto:security@example.com
Expires: 2027-06-01T00:00:00Z
";
        let pass = validate_security_txt(valid, now);
        assert_eq!(pass.severity, Severity::Pass);
        assert_eq!(pass.rule.as_deref(), Some("security/security-txt"));

        let missing_contact = "Expires: 2027-06-01T00:00:00Z\n";
        let fail_contact = validate_security_txt(missing_contact, now);
        assert_eq!(fail_contact.severity, Severity::Fail);
        assert!(
            fail_contact
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("Contact:"))
        );

        let expired = "\
Contact: https://example.com/security
Expires: 2026-05-31T23:59:59Z
";
        let fail_expired = validate_security_txt(expired, now);
        assert_eq!(fail_expired.severity, Severity::Fail);
        assert!(
            fail_expired
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("past"))
        );
    }
}
