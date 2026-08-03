#![forbid(unsafe_code)]

use std::env;
use std::fs;

use pulse_l3_bridge::StubL3Bridge;
use pulse_types::{BridgeId, ClockId, DiagnosticEscalationRequestV1};

fn main() {
    if let Err(error) = run() {
        eprintln!("pulse-l3-bridge: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let path = arguments
        .next()
        .ok_or_else(|| "usage: pulse-l3-bridge REQUEST.json NOW_MONOTONIC_MS".to_owned())?;
    let now: u64 = arguments
        .next()
        .ok_or_else(|| "missing NOW_MONOTONIC_MS".to_owned())?
        .parse()
        .map_err(|_| "NOW_MONOTONIC_MS must be an unsigned integer".to_owned())?;
    if arguments.next().is_some() {
        return Err("unexpected extra arguments".to_owned());
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let request: DiagnosticEscalationRequestV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let mut bridge = StubL3Bridge::new(
        BridgeId::new("bridge:local-stub-v1"),
        ClockId::new("clock:local-v1"),
    );
    let outcome = bridge.handle(&request, now);
    println!(
        "{}",
        serde_json::to_string_pretty(&outcome.disposition).map_err(|error| error.to_string())?
    );
    if let Some(receipt) = outcome.receipt {
        println!(
            "{}",
            serde_json::to_string_pretty(&receipt).map_err(|error| error.to_string())?
        );
    }
    Ok(())
}
