use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use url::Url;

use sitecheck::checks::indexnow::{format_indexnow_text, submit_indexnow};
use sitecheck::config::{Config, default_config_template};
use sitecheck::rules::format_rules_catalog;
use sitecheck::runner::{format_text, run_checks};

#[derive(Debug, Parser)]
#[command(name = "sitecheck", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run enabled health checks from a sitecheck.toml file.
    Run {
        /// Path to the sitecheck configuration file.
        #[arg(long, default_value = "sitecheck.toml")]
        config: PathBuf,
        /// Comma-separated list of check names to run.
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        /// Emit results as JSON.
        #[arg(long)]
        json: bool,
        /// Treat warnings as failures (non-zero exit code).
        #[arg(long)]
        strict: bool,
    },
    /// Generate a starter sitecheck.toml for a URL.
    Init {
        /// Base URL of the site (e.g. `<https://example.com/>`).
        url: Url,
        /// Output path for the generated config file.
        #[arg(long, default_value = "sitecheck.toml")]
        output: PathBuf,
    },
    /// List all cataloged rules (built-in checks and optional adapters) and their default severities.
    Rules,
    /// Submit site URLs to `IndexNow` (Bing, Yandex, Naver, Seznam) after deploy.
    Indexnow {
        /// Path to the sitecheck configuration file.
        #[arg(long, default_value = "sitecheck.toml")]
        config: PathBuf,
        /// Print the URLs and target endpoint without verifying the key file or submitting.
        #[arg(long)]
        dry_run: bool,
        /// Specific URL(s) to submit (repeatable; defaults to all same-origin URLs in /sitemap.xml).
        #[arg(long = "url")]
        urls: Vec<Url>,
        /// Emit submission result as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Rules => {
            print!("{}", format_rules_catalog());
            ExitCode::SUCCESS
        }
        Command::Init { url, output } => {
            if output.exists() {
                eprintln!("error: {} already exists", output.display());
                return ExitCode::FAILURE;
            }
            let template = default_config_template(&url);
            if let Err(err) = fs::write(&output, template) {
                eprintln!("error: failed to write {}: {err}", output.display());
                return ExitCode::FAILURE;
            }
            println!("Created {}", output.display());
            ExitCode::SUCCESS
        }
        Command::Run {
            config,
            only,
            json,
            strict,
        } => {
            let cfg = match Config::from_file(&config) {
                Ok(cfg) => cfg,
                Err(err) => {
                    eprintln!("error: {err}");
                    return ExitCode::FAILURE;
                }
            };

            let summary = match run_checks(&cfg, &only, strict).await {
                Ok(summary) => summary,
                Err(err) => {
                    eprintln!("error: {err}");
                    return ExitCode::FAILURE;
                }
            };

            if json {
                match serde_json::to_string_pretty(&summary) {
                    Ok(rendered) => println!("{rendered}"),
                    Err(err) => {
                        eprintln!("error: failed to serialize JSON: {err}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                print!("{}", format_text(&summary));
            }

            if summary.passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Command::Indexnow {
            config,
            dry_run,
            urls,
            json,
        } => {
            let cfg = match Config::from_file(&config) {
                Ok(cfg) => cfg,
                Err(err) => {
                    eprintln!("error: {err}");
                    return ExitCode::FAILURE;
                }
            };

            let result = match submit_indexnow(&cfg, &urls, dry_run).await {
                Ok(result) => result,
                Err(err) => {
                    eprintln!("error: {err}");
                    return ExitCode::FAILURE;
                }
            };

            if json {
                match serde_json::to_string_pretty(&result) {
                    Ok(rendered) => println!("{rendered}"),
                    Err(err) => {
                        eprintln!("error: failed to serialize JSON: {err}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                print!("{}", format_indexnow_text(&result));
            }

            ExitCode::SUCCESS
        }
    }
}
