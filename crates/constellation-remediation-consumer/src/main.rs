//! `constellation-remediation-consumer --config PATH`: one pass, one JSON
//! summary line on stdout. Exit 0 for every judged pass (acted, abstained,
//! refused, pending, busy); 2 for a configuration or state-store fault.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use constellation_remediation_consumer::{Config, run_pass};

const USAGE: &str = "usage: constellation-remediation-consumer --config PATH [--check-config]";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn main() {
    let mut config = None;
    let mut check_only = false;
    let mut arguments = std::env::args().skip(1);
    while let Some(flag) = arguments.next() {
        match flag.as_str() {
            "--config" => config = arguments.next().map(PathBuf::from),
            "--check-config" => check_only = true,
            "--version" => {
                println!(
                    "constellation-remediation-consumer {}",
                    env!("CARGO_PKG_VERSION")
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
    if check_only {
        println!(
            "{{\"config\":\"ok\",\"condition_id\":{:?}}}",
            config.condition_id()
        );
        return;
    }
    match run_pass(&config, &now_ms) {
        Ok(summary) => println!("{}", summary.to_json()),
        Err(error) => {
            eprintln!("constellation-remediation-consumer: {error}");
            std::process::exit(2);
        }
    }
}
