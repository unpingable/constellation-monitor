#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

use pulse_runtime::{run_crash_child, run_crash_harness};
use serde::Serialize;

fn write_json<T: Serialize>(path: Option<&str>, value: &T) -> Result<(), Box<dyn Error>> {
    let Some(path) = path else {
        return Ok(());
    };
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn usage() {
    eprintln!(
        "usage: pulse-crash-campaign <crash-harness> [create-new-json-path]\n\
         internal: pulse-crash-campaign crash-child <scenario> <journal> <marker>"
    );
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.first().map(String::as_str) {
        Some("crash-child") if arguments.len() == 4 => {
            run_crash_child(
                &arguments[1],
                Path::new(&arguments[2]),
                Path::new(&arguments[3]),
            )?;
        }
        Some("crash-harness") if arguments.len() <= 2 => {
            let executable = env::current_exe()?;
            let artifact = run_crash_harness(&executable)?;
            if !artifact.all_restart_invariants_held {
                return Err(io::Error::other("one crash restart invariant failed").into());
            }
            println!(
                "crash_scenarios={} restart_invariants=PASS current_reconstructed={} authority_reconstructed={}",
                artifact.scenarios.len(),
                artifact.current_standing_reconstructed,
                artifact.active_escalation_authority_reconstructed
            );
            for scenario in &artifact.scenarios {
                println!(
                    "{} outcome={:?} damage={:?} records={} restart={} support={} deadlines={}",
                    scenario.name,
                    scenario.journal_outcome,
                    scenario.journal_damage,
                    scenario.records_recovered,
                    scenario.current_standing_after_restart,
                    scenario.supporting_evidence_after_restart,
                    scenario.active_deadlines_after_restart
                );
            }
            write_json(arguments.get(1).map(String::as_str), &artifact)?;
        }
        _ => {
            usage();
            return Err(io::Error::other("invalid crash campaign command").into());
        }
    }
    Ok(())
}
