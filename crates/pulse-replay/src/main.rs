#![forbid(unsafe_code)]

use std::env;
use std::fs;

use pulse_replay::{DEMO_TRACE, ReplayError, run_jsonl};

fn main() {
    if let Err(error) = run() {
        eprintln!("pulse-replay: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), ReplayError> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().ok_or_else(|| {
        ReplayError::new("usage: pulse-replay demo | replay TRACE.jsonl | replay-json TRACE.jsonl")
    })?;
    let (input, json) = match command.as_str() {
        "demo" => {
            if arguments.next().is_some() {
                return Err(ReplayError::new("demo accepts no arguments"));
            }
            (DEMO_TRACE.to_owned(), false)
        }
        "replay" | "replay-json" => {
            let path = arguments
                .next()
                .ok_or_else(|| ReplayError::new("replay requires one trace path"))?;
            if arguments.next().is_some() {
                return Err(ReplayError::new("unexpected extra arguments"));
            }
            (
                fs::read_to_string(path).map_err(|error| ReplayError::new(error.to_string()))?,
                command == "replay-json",
            )
        }
        "--help" | "-h" => {
            println!("usage: pulse-replay demo | replay TRACE.jsonl | replay-json TRACE.jsonl");
            return Ok(());
        }
        _ => return Err(ReplayError::new(format!("unknown command: {command}"))),
    };
    let report = run_jsonl(&input)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| ReplayError::new(error.to_string()))?
        );
    } else {
        for line in report.terminal_lines {
            println!("{line}");
        }
    }
    Ok(())
}
