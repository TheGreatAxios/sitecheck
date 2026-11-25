#!/usr/bin/env bash
# Example CI/CD and periodic indexing health tracker using sitecheck.
#
# Usage:
#   ./examples/track-indexing.sh [path/to/sitecheck.toml] [output.jsonl]
#
# Typical post-deploy pipeline (e.g. Cloudflare Workers):
#   wrangler deploy && sitecheck indexnow --config sitecheck.toml
#
# Periodic health & indexing coverage snapshot (requires jq):
#   ./examples/track-indexing.sh sitecheck.toml indexing-history.jsonl

set -euo pipefail

CONFIG="${1:-sitecheck.toml}"
LOG_FILE="${2:-indexing-history.jsonl}"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# 1. Notify IndexNow search engines (Bing, Yandex, Naver, Seznam) of sitemap URLs.
#    Pass --dry-run to preview without posting.
if [[ "${INDEXNOW_PING:-0}" == "1" ]]; then
  sitecheck indexnow --config "$CONFIG"
fi

# 2. Run full SEO/AEO/indexing audit and capture structured JSON.
RAW_JSON="$(sitecheck run --config "$CONFIG" --json || true)"

# 3. Append a compact timestamped snapshot to JSONL for trend tracking.
if command -v jq >/dev/null 2>&1; then
  printf '%s\n' "$RAW_JSON" | jq -c --arg ts "$TIMESTAMP" '
    {
      timestamp: $ts,
      url: .url,
      passed: .passed,
      pass: ([.reports[].findings[] | select(.severity == "pass")] | length),
      warn: ([.reports[].findings[] | select(.severity == "warn")] | length),
      fail: ([.reports[].findings[] | select(.severity == "fail")] | length),
      gsc_coverage: ([.reports[].findings[] | select(.rule == "gsc/coverage") | .detail] | first),
      gsc_crawl_lag: ([.reports[].findings[] | select(.rule == "gsc/crawl-lag") | .detail] | first)
    }
  ' >> "$LOG_FILE"
  echo "Recorded snapshot in $LOG_FILE ($TIMESTAMP)"
else
  printf '%s\n' "$RAW_JSON" >> "$LOG_FILE"
  echo "Recorded raw JSON snapshot in $LOG_FILE ($TIMESTAMP) (install jq for compact summaries)"
fi
