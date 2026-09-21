#![forbid(unsafe_code)]

use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use pulse_agent::{AgentConfig, AgentError, ProducerProfile, PulseAgent, ShutdownToken};

#[derive(Debug)]
struct Cli {
    profile: ProducerProfile,
    count: u64,
    cadence_ms: u64,
    validity_ms: u64,
    subject: String,
    observer: String,
    fault_at: Option<u64>,
    coverage_collapse_at: Option<u64>,
    wire: Option<PathBuf>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("pulse-agent: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), AgentError> {
    let cli = parse_args(env::args().skip(1))?;
    let mut config = match cli.profile {
        ProducerProfile::Synthetic => AgentConfig::synthetic(),
        ProducerProfile::LinuxProc => AgentConfig::linux_proc(),
    };
    config.subject = pulse_types::SubjectId::new(cli.subject);
    config.observer = pulse_types::ObserverId::new(cli.observer);
    config.cadence = std::time::Duration::from_millis(cli.cadence_ms);
    config.validity_ms = cli.validity_ms;
    config.fault_at_sequence = cli.fault_at;
    config.coverage_collapse_at_sequence = cli.coverage_collapse_at;
    let mut agent = PulseAgent::new(config)?;
    let shutdown = ShutdownToken::new();
    let signal_token = shutdown.clone();
    ctrlc::set_handler(move || signal_token.request())
        .map_err(|error| AgentError::new(format!("cannot install shutdown handler: {error}")))?;

    if let Some(path) = cli.wire {
        let file = File::create(&path)?;
        let mut writer = BufWriter::new(file);
        let produced = agent.run(cli.count, &shutdown, |frame| {
            let bytes = frame
                .encode_wire()
                .map_err(|error| AgentError::new(error.to_string()))?;
            let length = u32::try_from(bytes.len())
                .map_err(|_| AgentError::new("wire frame length exceeds u32"))?;
            writer.write_all(&length.to_be_bytes())?;
            writer.write_all(&bytes)?;
            Ok(())
        })?;
        writer.flush()?;
        eprintln!(
            "pulse-agent stopped cleanly after {produced} pulse(s); compact wire={}",
            path.display()
        );
    } else {
        let produced = agent.run(cli.count, &shutdown, |frame| {
            println!(
                "pulse seq={} subject={} observer={} incarnation={} validity={}ms coverage={}/{} digest={}",
                frame.sequence,
                frame.subject,
                frame.observer,
                frame.observer_incarnation,
                frame.validity_ms,
                frame.coverage.observed.len(),
                frame.coverage.expected.len(),
                frame.observation_digest
            );
            Ok(())
        })?;
        eprintln!("pulse-agent stopped cleanly after {produced} pulse(s)");
    }
    Ok(())
}

fn parse_args(arguments: impl Iterator<Item = String>) -> Result<Cli, AgentError> {
    let mut cli = Cli {
        profile: ProducerProfile::Synthetic,
        count: 5,
        cadence_ms: 250,
        validity_ms: 750,
        subject: "subject:demo-host".to_owned(),
        observer: "observer:local".to_owned(),
        fault_at: None,
        coverage_collapse_at: None,
        wire: None,
    };
    let mut arguments = arguments;
    while let Some(argument) = arguments.next() {
        let value = |name: &str, arguments: &mut dyn Iterator<Item = String>| {
            arguments
                .next()
                .ok_or_else(|| AgentError::new(format!("{name} requires a value")))
        };
        match argument.as_str() {
            "--profile" => {
                cli.profile = match value("--profile", &mut arguments)?.as_str() {
                    "synthetic" => ProducerProfile::Synthetic,
                    "proc" => ProducerProfile::LinuxProc,
                    _ => return Err(AgentError::new("--profile must be synthetic or proc")),
                };
            }
            "--count" => cli.count = parse_u64("--count", value("--count", &mut arguments)?)?,
            "--cadence-ms" => {
                cli.cadence_ms = parse_u64("--cadence-ms", value("--cadence-ms", &mut arguments)?)?;
            }
            "--validity-ms" => {
                cli.validity_ms =
                    parse_u64("--validity-ms", value("--validity-ms", &mut arguments)?)?;
            }
            "--subject" => cli.subject = value("--subject", &mut arguments)?,
            "--observer" => cli.observer = value("--observer", &mut arguments)?,
            "--fault-at" => {
                cli.fault_at = Some(parse_u64(
                    "--fault-at",
                    value("--fault-at", &mut arguments)?,
                )?);
            }
            "--coverage-collapse-at" => {
                cli.coverage_collapse_at = Some(parse_u64(
                    "--coverage-collapse-at",
                    value("--coverage-collapse-at", &mut arguments)?,
                )?);
            }
            "--wire" => cli.wire = Some(PathBuf::from(value("--wire", &mut arguments)?)),
            "--help" | "-h" => {
                println!(
                    "usage: pulse-agent [--profile synthetic|proc] [--count N] [--cadence-ms N] [--validity-ms N] [--subject ID] [--observer ID] [--fault-at N] [--coverage-collapse-at N] [--wire PATH]\n\n--count 0 runs until Ctrl-C. --wire writes length-prefixed compact v1 frames."
                );
                std::process::exit(0);
            }
            _ => return Err(AgentError::new(format!("unknown argument: {argument}"))),
        }
    }
    Ok(cli)
}

fn parse_u64(name: &str, value: String) -> Result<u64, AgentError> {
    value
        .parse()
        .map_err(|_| AgentError::new(format!("{name} requires an unsigned integer")))
}
