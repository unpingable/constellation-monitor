#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

use pulse_runtime::{
    qualification_manifest, run_crash_child, run_crash_harness, run_journal_corruption_corpus,
    run_live_linux_exercise, run_reactor_demo, run_restart_demo,
};
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
        "usage: pulse-crash-campaign <reactor-demo|restart-demo|torn-journal-demo|interior-corruption-demo|crash-harness|corruption-corpus|live-linux|qualification> [create-new-json-path]\n\
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
        Some("reactor-demo") if arguments.len() <= 2 => {
            let artifact = run_reactor_demo()?;
            for line in &artifact.terminal_trace {
                println!("{line}");
            }
            write_json(arguments.get(1).map(String::as_str), &artifact)?;
        }
        Some("restart-demo") if arguments.len() <= 2 => {
            let executable = env::current_exe()?;
            let artifact = run_restart_demo(&executable)?;
            for line in &artifact.terminal_trace {
                println!("{line}");
            }
            write_json(arguments.get(1).map(String::as_str), &artifact)?;
        }
        Some("corruption-corpus") if arguments.len() <= 2 => {
            let artifact = run_journal_corruption_corpus()?;
            println!(
                "journal_scenarios={} truncation_positions={} first_damage_stop={} standing_reconstructed={}",
                artifact.scenarios.len(),
                artifact.truncation_sweep.byte_positions_tested,
                artifact.all_damage_stopped_at_first_invalid_frame,
                !artifact.all_recovery_reconstructed_no_standing
            );
            for scenario in &artifact.scenarios {
                println!(
                    "{} outcome={:?} damage={:?} records={} damaged_offset={:?} complete={}",
                    scenario.name,
                    scenario.outcome,
                    scenario.damage,
                    scenario.records_recovered,
                    scenario.first_damaged_offset,
                    scenario.history_complete
                );
            }
            write_json(arguments.get(1).map(String::as_str), &artifact)?;
        }
        Some("torn-journal-demo") if arguments.len() <= 2 => {
            let artifact = run_journal_corruption_corpus()?;
            let scenario = artifact
                .scenarios
                .iter()
                .find(|scenario| scenario.name == "valid_prefix_followed_by_torn_suffix")
                .ok_or_else(|| io::Error::other("torn suffix scenario is absent"))?;
            println!("valid records appended");
            println!("final record torn");
            println!(
                "restart outcome={:?} valid_prefix_records={} damaged_offset={:?}",
                scenario.outcome, scenario.records_recovered, scenario.first_damaged_offset
            );
            println!("history_complete={}", scenario.history_complete);
            println!("current standing UNKNOWN (not reconstructed)");
            write_json(arguments.get(1).map(String::as_str), scenario)?;
        }
        Some("interior-corruption-demo") if arguments.len() <= 2 => {
            let artifact = run_journal_corruption_corpus()?;
            let scenario = artifact
                .scenarios
                .iter()
                .find(|scenario| scenario.name == "interior_bit_corruption")
                .ok_or_else(|| io::Error::other("interior corruption scenario is absent"))?;
            println!("valid record");
            println!("corrupted interior record");
            println!("later valid-looking bytes present");
            println!(
                "recovery outcome={:?} damage={:?} damaged_offset={:?}",
                scenario.outcome, scenario.damage, scenario.first_damaged_offset
            );
            println!("complete replay refused; current standing not reconstructed");
            write_json(arguments.get(1).map(String::as_str), scenario)?;
        }
        Some("live-linux") if arguments.len() <= 2 => {
            let executable = env::current_exe()?;
            let artifact = run_live_linux_exercise(&executable)?;
            println!(
                "timer_samples={} lateness_ms={:?} overshoot_ms={:?} sigkill_scenarios={}",
                artifact.timer_samples.len(),
                artifact.wakeup_lateness_ms,
                artifact.stale_positive_overshoot_ms,
                artifact.sigkill_scenarios
            );
            for sample in &artifact.timer_samples {
                println!(
                    "{} deadline={} wake={} withdrawal={} lateness={} overshoot={} restart={}",
                    sample.name,
                    sample.requested_support_deadline_monotonic_ms,
                    sample.actual_wakeup_monotonic_ms,
                    sample.actual_withdrawal_monotonic_ms,
                    sample.wakeup_lateness_ms,
                    sample.stale_positive_overshoot_ms,
                    sample.restart_standing
                );
            }
            write_json(arguments.get(1).map(String::as_str), &artifact)?;
        }
        Some("qualification") if arguments.len() <= 2 => {
            let artifact = qualification_manifest();
            println!(
                "qualification_checks={} current_standing_durable={} mutation_authority_emitted={}",
                artifact.checks.len(),
                artifact.current_standing_durable,
                artifact.mutation_authority_emitted
            );
            write_json(arguments.get(1).map(String::as_str), &artifact)?;
        }
        _ => {
            usage();
            return Err(io::Error::other("invalid crash campaign command").into());
        }
    }
    Ok(())
}
