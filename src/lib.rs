//! Config-driven website auditor with 46 built-in HTTP, SEO, security,
//! structured data, and AI crawler rules, plus optional adapters for `IndexNow`,
//! `PageSpeed` Insights, Lighthouse, axe-core, and Google Search Console.
//!
//! `sitecheck` is primarily used as a CLI (`sitecheck init`, `sitecheck run`,
//! `sitecheck rules`), and also exposes its configuration, check trait, rule
//! catalog, and runner as a Rust library.
//!
//! # Modules
//!
//! - [`config`] — Parse `sitecheck.toml` and build the enabled check list.
//! - [`check`] — Core [`check::Check`] trait, [`check::CheckContext`], and [`check::Finding`] types.
//! - [`checks`] — Built-in deterministic checks and optional external adapters.
//! - [`rules`] — Catalog of built-in `category/rule-name` rule definitions.
//! - [`runner`] — Execute checks, apply `[rules]` overrides, and format reports.
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//! use sitecheck::config::Config;
//! use sitecheck::runner::run_checks;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let cfg = Config::from_file(Path::new("sitecheck.toml"))?;
//! let summary = run_checks(&cfg, &[], true).await?;
//! assert!(summary.passed);
//! # Ok(())
//! # }
//! ```

pub mod check;
pub mod checks;
pub mod config;
pub mod rules;
pub mod runner;
