use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::Deserialize;

use crate::check::{Check, CheckContext, CheckError, CheckReport, Finding};
use crate::checks::http::{has_content_signal, robots_pattern_matches};

const SEARCH_BOTS: &[&str] = &[
    "Googlebot",
    "Bingbot",
    "Applebot",
    "OAI-SearchBot",
    "ChatGPT-User",
    "Claude-SearchBot",
    "Claude-User",
    "PerplexityBot",
    "ExaSearchBot",
];

const TRAINING_BOTS: &[&str] = &[
    "GPTBot",
    "ClaudeBot",
    "Applebot-Extended",
    "Google-Extended",
    "Meta-ExternalAgent",
    "CCBot",
];

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiConfig {
    #[serde(default)]
    pub allow_blocked: Vec<String>,
}

pub struct AiCheck {
    config: AiConfig,
}

impl AiCheck {
    #[must_use]
    pub const fn new(config: AiConfig) -> Self {
        Self { config }
    }
}

/// Multi-agent RFC 9309 `robots.txt` policy evaluator.
#[derive(Debug, Clone, Default)]
pub struct RobotsPolicy {
    groups: BTreeMap<String, Vec<(bool, String)>>,
}

impl RobotsPolicy {
    #[must_use]
    pub fn parse(content: &str) -> Self {
        let mut groups: BTreeMap<String, Vec<(bool, String)>> = BTreeMap::new();
        let mut current_agents: Vec<String> = Vec::new();
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
                    current_agents.clear();
                    saw_rule = false;
                }
                if !val.is_empty() {
                    current_agents.push(val.to_ascii_lowercase());
                }
            } else if key.eq_ignore_ascii_case("allow") || key.eq_ignore_ascii_case("disallow") {
                saw_rule = true;
                let is_allow = key.eq_ignore_ascii_case("allow");
                for agent in &current_agents {
                    let entry = groups.entry(agent.clone()).or_default();
                    if !val.is_empty() {
                        entry.push((is_allow, val.to_owned()));
                    }
                }
            }
        }

        Self { groups }
    }

    #[must_use]
    pub fn is_disallowed(&self, agent: &str, path: &str) -> bool {
        let key = agent.to_ascii_lowercase();
        let Some(rules) = self.groups.get(&key).or_else(|| self.groups.get("*")) else {
            return false;
        };

        let mut best: Option<(usize, bool)> = None;
        for (is_allow, pattern) in rules {
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
}

/// Evaluates `robots.txt` against search/live-retrieval bots and AI training bots.
#[must_use]
pub fn evaluate_ai_robots(robots_body: &str, allow_blocked: &[String]) -> Vec<Finding> {
    let policy = RobotsPolicy::parse(robots_body);

    let blocked_search: Vec<String> = SEARCH_BOTS
        .iter()
        .copied()
        .filter(|bot| {
            !allow_blocked
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(bot))
                && policy.is_disallowed(bot, "/")
        })
        .map(str::to_owned)
        .collect();

    let search_finding = if blocked_search.is_empty() {
        Finding::pass(
            "AI & search bots crawlable",
            Some(format!(
                "all {} search/retrieval bots allowed on `/`",
                SEARCH_BOTS.len()
            )),
        )
        .with_rule("ai/search-bots-allowed")
    } else {
        Finding::fail(
            "AI & search bots crawlable",
            Some(format!(
                "{} search/retrieval bot(s) blocked on `/`",
                blocked_search.len()
            )),
        )
        .with_rule("ai/search-bots-allowed")
        .with_items(blocked_search)
    };

    let mut disallowed_training = Vec::new();
    let mut allowed_training = Vec::new();
    for &bot in TRAINING_BOTS {
        if policy.is_disallowed(bot, "/") {
            disallowed_training.push(bot);
        } else {
            allowed_training.push(bot);
        }
    }

    let content_signal = if has_content_signal(robots_body) {
        "Content-Signal: declared"
    } else {
        "Content-Signal: none"
    };
    let disallowed_str = if disallowed_training.is_empty() {
        "none".to_owned()
    } else {
        disallowed_training.join(", ")
    };
    let allowed_str = if allowed_training.is_empty() {
        "none".to_owned()
    } else {
        allowed_training.join(", ")
    };

    let training_finding = Finding::pass(
        "AI training policy",
        Some(format!(
            "disallowed: [{disallowed_str}]; allowed: [{allowed_str}]; {content_signal}"
        )),
    )
    .with_rule("ai/training-policy");

    vec![search_finding, training_finding]
}

#[async_trait]
impl Check for AiCheck {
    fn name(&self) -> &'static str {
        "ai"
    }

    async fn run(&self, ctx: &CheckContext) -> Result<CheckReport, CheckError> {
        let url = ctx.base_url.join("/robots.txt")?;
        let resp = match ctx.client.get(url.clone()).send().await {
            Ok(resp) => resp,
            Err(err) => {
                return Ok(CheckReport::new(
                    self.name(),
                    vec![
                        Finding::fail(
                            "AI & search bots crawlable",
                            Some(format!("failed to fetch {url}: {err}")),
                        )
                        .with_rule("ai/search-bots-allowed"),
                    ],
                ));
            }
        };

        let status = resp.status();
        if !status.is_success() {
            return Ok(CheckReport::new(
                self.name(),
                vec![
                    Finding::fail(
                        "AI & search bots crawlable",
                        Some(format!("HTTP {status} at {url}")),
                    )
                    .with_rule("ai/search-bots-allowed"),
                ],
            ));
        }

        let body = resp.text().await.unwrap_or_default();
        let findings = evaluate_ai_robots(&body, &self.config.allow_blocked);
        Ok(CheckReport::new(self.name(), findings))
    }
}

#[cfg(test)]
mod tests {
    use super::evaluate_ai_robots;
    use crate::check::Severity;

    #[test]
    fn fails_when_search_or_retrieval_bots_are_blocked() {
        let robots = "\
User-agent: *
Allow: /

User-agent: OAI-SearchBot
User-agent: Applebot
Disallow: /
";
        let findings = evaluate_ai_robots(robots, &[]);
        let search = &findings[0];
        assert_eq!(search.rule.as_deref(), Some("ai/search-bots-allowed"));
        assert_eq!(search.severity, Severity::Fail);
        assert_eq!(search.items, vec!["Applebot", "OAI-SearchBot"]);

        let allowed =
            evaluate_ai_robots(robots, &["applebot".to_owned(), "OAI-SearchBot".to_owned()]);
        assert_eq!(allowed[0].severity, Severity::Pass);
    }

    #[test]
    fn allows_blocking_training_bots_without_failing_search_bots() {
        let robots = "\
User-agent: *
Content-Signal: ai-train=no, search=yes, ai-input=yes
Allow: /

User-agent: GPTBot
User-agent: ClaudeBot
Disallow: /
";
        let findings = evaluate_ai_robots(robots, &[]);
        assert_eq!(findings[0].rule.as_deref(), Some("ai/search-bots-allowed"));
        assert_eq!(findings[0].severity, Severity::Pass);

        let training = &findings[1];
        assert_eq!(training.rule.as_deref(), Some("ai/training-policy"));
        assert_eq!(training.severity, Severity::Pass);
        let detail = training.detail.as_deref().unwrap_or_default();
        assert!(detail.contains("disallowed: [GPTBot, ClaudeBot]"));
        assert!(detail.contains("Content-Signal: declared"));
    }

    #[test]
    fn wildcard_disallow_blocks_all_search_bots_unless_overridden() {
        let robots = "\
User-agent: *
Disallow: /

User-agent: Googlebot
Disallow:
";
        let findings = evaluate_ai_robots(robots, &[]);
        assert_eq!(findings[0].severity, Severity::Fail);
        assert!(!findings[0].items.iter().any(|b| b == "Googlebot"));
        assert!(findings[0].items.iter().any(|b| b == "Bingbot"));
        assert!(findings[0].items.iter().any(|b| b == "OAI-SearchBot"));
    }
}
