#![forbid(unsafe_code)]
use std::{io::Read, path::Path};
fn run() -> Result<(), String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let resolver = std::env::args()
        .next()
        .and_then(|p| {
            std::path::PathBuf::from(p)
                .file_name()
                .map(|x| x.to_string_lossy().into_owned())
        })
        .as_deref()
        == Some("pulse-m2-support-resolver");
    if resolver {
        if !args.is_empty() {
            return Err("M2 resolver accepts no arguments".into());
        }
        args = vec![
            "resolve".into(),
            "--config".into(),
            std::env::var("PULSE_M2_SUPPORT_CONFIG")
                .map_err(|_| "PULSE_M2_SUPPORT_CONFIG is required")?,
        ];
    }
    if args.len() != 3 || args[1] != "--config" {
        return Err("usage: pulse-m2-support acquire|resolve --config ABSOLUTE_PATH".into());
    }
    let cfg = pulse_m2_support::load(Path::new(&args[2]))?;
    let output = match args[0].as_str() {
        "acquire" => serde_jcs::to_vec(&pulse_m2_support::acquire(&cfg)?),
        "resolve" => {
            let mut b = Vec::new();
            std::io::stdin()
                .take(65537)
                .read_to_end(&mut b)
                .map_err(|e| e.to_string())?;
            if b.len() > 65536 {
                return Err("query exceeds byte bound".into());
            }
            let q = serde_json::from_slice(&b).map_err(|e| e.to_string())?;
            serde_jcs::to_vec(&pulse_m2_support::resolve(&cfg, &q)?)
        }
        _ => return Err("unknown M2 support operation".into()),
    }
    .map_err(|e| e.to_string())?;
    println!("{}", String::from_utf8(output).map_err(|e| e.to_string())?);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(2)
    }
}
