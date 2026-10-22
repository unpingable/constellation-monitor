//! `constellation-remediation-consumer --config PATH [--decider
//! deterministic|model]`: one pass, one JSON summary line on stdout. Exit 0
//! for every judged pass (acted, abstained, refused, escalated, pending,
//! busy); 2 for a configuration or state-store fault. The model decider
//! needs the configuration's `[model]` section; it is never the default.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use constellation_remediation_consumer::Config;
use constellation_remediation_consumer::pass::{Decider, run_pass_with};

const USAGE: &str = "usage: constellation-remediation-consumer --config PATH \
[--decider deterministic|model] [--check-config]\n       constellation-remediation-consumer --build-info | --version | -V";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn main() {
    match constellation_remediation_consumer::build_info::write_if_requested(
        "constellation-remediation-consumer",
    ) {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            eprintln!("constellation-remediation-consumer: {error}");
            std::process::exit(2);
        }
    }
    let mut config = None;
    let mut check_only = false;
    let mut decider = Decider::Deterministic;
    let mut arguments = std::env::args().skip(1);
    while let Some(flag) = arguments.next() {
        match flag.as_str() {
            "--config" => config = arguments.next().map(PathBuf::from),
            "--check-config" => check_only = true,
            "--decider" => match arguments.next().as_deref().map(Decider::parse) {
                Some(Ok(chosen)) => decider = chosen,
                Some(Err(error)) => {
                    eprintln!("constellation-remediation-consumer: {error}");
                    std::process::exit(2);
                }
                None => {
                    eprintln!("{USAGE}");
                    std::process::exit(2);
                }
            },
            "--version" => {
                println!(
                    "constellation-remediation-consumer {}",
                    constellation_remediation_consumer::build_info::VERSION_STRING
                );
                return;
            }
            _ => {
                eprintln!("{USAGE}");
                std::process::exit(2);
            }
        }
    }
    let Some(path) = config else {
        eprintln!("{USAGE}");
        std::process::exit(2);
    };
    let config = match Config::load(&path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("constellation-remediation-consumer: {error}");
            std::process::exit(2);
        }
    };
    if decider == Decider::Model
        && let Err(error) = config.model()
    {
        eprintln!("constellation-remediation-consumer: {error}");
        std::process::exit(2);
    }
    if check_only {
        println!(
            "{}",
            serde_json::json!({
                "config": "ok",
                "condition_id": config.condition_id(),
                "decider": decider.as_str(),
                "journal_max_bytes": constellation_remediation_consumer::store::MAX_JOURNAL_BYTES,
                "journal_max_sealed": constellation_remediation_consumer::store::MAX_SEALED_JOURNALS,
                "journal_sealed_present": constellation_remediation_consumer::store::sealed_journal_count(&config.consumer.state_dir),
                "model": config.model.as_ref().map(|_| constellation_remediation_consumer::decider::MODEL),
            })
        );
        return;
    }
    match run_pass_with(&config, decider, &now_ms) {
        Ok(summary) => println!("{}", summary.to_json()),
        Err(error) => {
            eprintln!("constellation-remediation-consumer: {error}");
            std::process::exit(2);
        }
    }
}
