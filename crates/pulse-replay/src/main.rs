#![forbid(unsafe_code)]

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

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
        ReplayError::new(
            "usage: pulse-replay demo | replay TRACE.jsonl | replay-json TRACE.jsonl [REPORT.json]",
        )
    })?;
    let (input, json, output_path) = match command.as_str() {
        "demo" => {
            if arguments.next().is_some() {
                return Err(ReplayError::new("demo accepts no arguments"));
            }
            (DEMO_TRACE.to_owned(), false, None)
        }
        "replay" | "replay-json" => {
            let path = arguments
                .next()
                .ok_or_else(|| ReplayError::new("replay requires one trace path"))?;
            let output_path = if command == "replay-json" {
                arguments.next().map(PathBuf::from)
            } else {
                None
            };
            if arguments.next().is_some() {
                return Err(ReplayError::new("unexpected extra arguments"));
            }
            (
                fs::read_to_string(path).map_err(|error| ReplayError::new(error.to_string()))?,
                command == "replay-json",
                output_path,
            )
        }
        "--help" | "-h" => {
            println!(
                "usage: pulse-replay demo | replay TRACE.jsonl | replay-json TRACE.jsonl [REPORT.json]"
            );
            return Ok(());
        }
        _ => return Err(ReplayError::new(format!("unknown command: {command}"))),
    };
    let report = run_jsonl(&input)?;
    if json {
        let mut serialized = serde_json::to_string_pretty(&report)
            .map_err(|error| ReplayError::new(error.to_string()))?;
        serialized.push('\n');
        if let Some(path) = output_path {
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|error| ReplayError::new(error.to_string()))?;
            output
                .write_all(serialized.as_bytes())
                .map_err(|error| ReplayError::new(error.to_string()))?;
            eprintln!("stored deterministic replay report at {}", path.display());
        } else {
            print!("{serialized}");
        }
    } else {
        for line in report.terminal_lines {
            println!("{line}");
        }
    }
    Ok(())
}
