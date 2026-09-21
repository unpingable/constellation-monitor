use monitor_project_concerns::{
    AcquisitionLimits, collect_cancellable, discover, load_project, render_discovery,
    render_inventory,
};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

fn usage() -> ! {
    eprintln!(
        "usage:
  monitor-concerns discover ROOT [--json]
  monitor-concerns inspect PROJECT [--json]
  monitor-concerns validate PROJECT
  monitor-concerns collect PROJECT --trusted-root ROOT --allow-exec [--json] [--timeout-ms N] [--output-limit-bytes N]
  monitor-concerns workspace ROOT --trusted-root ROOT --allow-exec [--json]"
    );
    std::process::exit(2);
}

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|value| value == name)
}

fn value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|item| item == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn limits(args: &[String]) -> AcquisitionLimits {
    AcquisitionLimits {
        timeout: Duration::from_millis(
            value(args, "--timeout-ms")
                .and_then(|value| value.parse().ok())
                .unwrap_or(10_000),
        ),
        output_limit_bytes: value(args, "--output-limit-bytes")
            .and_then(|value| value.parse().ok())
            .unwrap_or(1024 * 1024),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first().map(String::as_str) else {
        usage();
    };
    let Some(path) = args.get(1).map(PathBuf::from) else {
        usage();
    };
    let json = flag(&args, "--json");
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&cancelled);
    if let Err(error) = ctrlc::set_handler(move || signal.store(true, Ordering::SeqCst)) {
        eprintln!("monitor-concerns: cannot install cancellation handler: {error}");
        std::process::exit(2);
    }
    let result: Result<(), Box<dyn std::error::Error>> = match command {
        "discover" => discover(&path)
            .map(|report| {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report).expect("serialize")
                    );
                } else {
                    println!("{}", render_discovery(&report));
                }
            })
            .map_err(Into::into),
        "inspect" => load_project(&path)
            .map(|(manifest, _, binding)| {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"manifest": manifest, "binding": binding})
                    );
                } else {
                    println!("project: {}", manifest.project);
                    println!("manifest: {}", manifest.schema);
                    println!("producer: {} ({})", binding.producer, binding.kind);
                    for concern in manifest.concerns {
                        println!("  {} required={}", concern.id, concern.required);
                    }
                }
            })
            .map_err(Into::into),
        "validate" => load_project(&path)
            .map(|(manifest, _, binding)| {
                println!(
                    "{} conforms: {} concerns, producer {}, output {}",
                    manifest.project,
                    manifest.concerns.len(),
                    binding.producer,
                    binding.output_schema
                );
            })
            .map_err(Into::into),
        "collect" => {
            let Some(trusted) = value(&args, "--trusted-root").map(PathBuf::from) else {
                usage();
            };
            collect_cancellable(
                &path,
                &trusted,
                flag(&args, "--allow-exec"),
                limits(&args),
                Arc::clone(&cancelled),
            )
            .map(|report| {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report).expect("serialize")
                    );
                } else {
                    println!("{}", render_inventory(&report));
                }
                if report.acquisition.disposition != "ACQUIRED_AND_VALIDATED" {
                    std::process::exit(3);
                }
            })
            .map_err(Into::into)
        }
        "workspace" => {
            let Some(trusted) = value(&args, "--trusted-root").map(PathBuf::from) else {
                usage();
            };
            discover(&path)
                .and_then(|discovery| {
                    let reports = discovery
                        .projects
                        .iter()
                        .map(|project| {
                            collect_cancellable(
                                &PathBuf::from(&project.repository),
                                &trusted,
                                flag(&args, "--allow-exec"),
                                limits(&args),
                                Arc::clone(&cancelled),
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&reports).expect("serialize")
                        );
                    } else {
                        for report in reports {
                            println!("{}", render_inventory(&report));
                        }
                    }
                    Ok(())
                })
                .map_err(Into::into)
        }
        _ => usage(),
    };
    if let Err(error) = result {
        eprintln!("monitor-concerns: {error}");
        std::process::exit(2);
    }
}
