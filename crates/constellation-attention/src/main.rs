//! `constellation-attention`: one bounded evaluation pass per invocation.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use constellation_attention::build_info;
use constellation_attention::config::Config;
use constellation_attention::engine::{self, PassOptions};
use constellation_attention::intent::policy_digest;
use constellation_attention::registry::{
    PAGE_RESEND_SECONDS, REGISTRY_VERSION, RESEND_INTERVAL_SECONDS, RESOLVE_CONFIRM_SECONDS, RULES,
    UNKNOWN_GAP_SECONDS,
};
use constellation_attention::state::State;
use constellation_attention::util::parse_rfc3339;
use serde_json::json;

const USAGE: &str = "usage:
  constellation-attention --version | --build-info
  constellation-attention evaluate --config FILE [--dry-run] [--now RFC3339]
  constellation-attention state --config FILE
  constellation-attention reset-clock --config FILE
  constellation-attention rules
  constellation-attention check-config --config FILE";

struct Arguments {
    command: String,
    config: Option<PathBuf>,
    dry_run: bool,
    now: Option<String>,
}

fn parse(mut raw: impl Iterator<Item = String>) -> Result<Arguments, String> {
    let command = raw.next().ok_or_else(|| USAGE.to_owned())?;
    let mut arguments = Arguments {
        command,
        config: None,
        dry_run: false,
        now: None,
    };
    while let Some(flag) = raw.next() {
        match flag.as_str() {
            "--config" => {
                arguments.config = Some(PathBuf::from(raw.next().ok_or("--config needs a path")?));
            }
            "--now" if matches!(arguments.command.as_str(), "evaluate" | "reset-clock") => {
                arguments.now = Some(raw.next().ok_or("--now needs an RFC3339 time")?);
            }
            "--dry-run" if arguments.command == "evaluate" => arguments.dry_run = true,
            other => return Err(format!("unexpected argument {other:?}\n{USAGE}")),
        }
    }
    Ok(arguments)
}

fn load(arguments: &Arguments) -> Result<Config, String> {
    let path = arguments
        .config
        .as_ref()
        .ok_or_else(|| format!("--config is required\n{USAGE}"))?;
    Config::load(path)
}

fn print(value: &serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).unwrap_or_default()
    );
}

/// Unix seconds and milliseconds of `--now`, or of the system clock.
fn clock(now: Option<&str>) -> Result<(i64, i64), (u8, String)> {
    if let Some(value) = now {
        let time = parse_rfc3339(value).map_err(|error| (2, error))?;
        let ms = i64::try_from(time.unix_timestamp_nanos() / 1_000_000)
            .map_err(|_| (2, "--now out of range".to_owned()))?;
        return Ok((time.unix_timestamp(), ms));
    }
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| (1, "system clock before 1970".to_owned()))?;
    let ms =
        i64::try_from(elapsed.as_millis()).map_err(|_| (1, "clock out of range".to_owned()))?;
    Ok((ms / 1000, ms))
}

fn run() -> Result<u8, (u8, String)> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    match raw
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--version"] => {
            println!("{}", build_info::version_line());
            return Ok(0);
        }
        ["--build-info"] => {
            println!(
                "{}",
                serde_json::to_string(&build_info::build_information())
                    .map_err(|error| (1, error.to_string()))?
            );
            return Ok(0);
        }
        _ => {}
    }
    let arguments = parse(raw.into_iter()).map_err(|error| (2, error))?;
    match arguments.command.as_str() {
        "rules" => {
            if arguments.config.is_some() {
                return Err((2, USAGE.to_owned()));
            }
            print(&json!({
                "registry": REGISTRY_VERSION,
                "resolve_confirm_seconds": RESOLVE_CONFIRM_SECONDS,
                "resend_interval_seconds": RESEND_INTERVAL_SECONDS,
                "page_resend_seconds": PAGE_RESEND_SECONDS,
                "unknown_gap_seconds": UNKNOWN_GAP_SECONDS,
                "rules": RULES,
            }));
            Ok(0)
        }
        "reset-clock" => {
            // Only debug builds (the test suite) may choose the time.
            if arguments.now.is_some() && !cfg!(debug_assertions) {
                return Err((2, "reset-clock uses the system clock".to_owned()));
            }
            let config = load(&arguments).map_err(|error| (2, error))?;
            let (now, _) = clock(arguments.now.as_deref())?;
            print(&engine::reset_clock(&config, now).map_err(|error| (1, error))?);
            Ok(0)
        }
        "check-config" => {
            let config = load(&arguments).map_err(|error| (2, error))?;
            let rules = config.effective_rules();
            print(&json!({
                "valid": true,
                "site": config.site,
                "registry": REGISTRY_VERSION,
                "attention_policy_digest": policy_digest(&rules, &config.remediation.targets),
                "rules": engine::rules_report(&rules, &config),
            }));
            Ok(0)
        }
        "state" => {
            let config = load(&arguments).map_err(|error| (2, error))?;
            let state =
                State::load(&config.state_path, &config.site).map_err(|error| (1, error))?;
            print(&serde_json::to_value(&state).map_err(|error| (1, error.to_string()))?);
            Ok(0)
        }
        "evaluate" => {
            // A chosen time is for what-if dry runs. Release builds refuse it
            // for a real pass; debug builds accept it so the test suite can
            // drive the clock.
            if arguments.now.is_some() && !arguments.dry_run && !cfg!(debug_assertions) {
                return Err((2, "--now is accepted only with --dry-run".to_owned()));
            }
            let config = load(&arguments).map_err(|error| (2, error))?;
            let (now, now_ms) = clock(arguments.now.as_deref())?;
            let result = engine::evaluate(
                &config,
                &PassOptions {
                    dry_run: arguments.dry_run,
                    now,
                    now_ms,
                },
            )
            .map_err(|error| (1, error))?;
            let summary = json!({
                "evaluated_at": result.report["evaluated_at"],
                "dry_run": arguments.dry_run,
                "inputs": result.report["inputs"].as_array().map_or(0, Vec::len),
                "conditions": result.report["conditions"].as_array().map_or(0, Vec::len),
                "intents": result.report["intents"],
            });
            println!("{}", serde_json::to_string(&summary).unwrap_or_default());
            Ok(u8::try_from(result.exit_code).unwrap_or(1))
        }
        _ => Err((2, USAGE.to_owned())),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err((code, error)) => {
            eprintln!("constellation-attention: {error}");
            ExitCode::from(code)
        }
    }
}
