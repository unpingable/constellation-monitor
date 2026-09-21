#![forbid(unsafe_code)]

use std::env;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use pulse_nq_load_support::{
    LoadSupportConfigV1, PresentEvidenceQueryV1, ingest, produce, resolve,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let executable = env::args_os()
        .next()
        .and_then(|value| PathBuf::from(value).file_name().map(|name| name.to_owned()))
        .and_then(|value| value.to_str().map(str::to_owned))
        .ok_or_else(|| "cannot determine executable basename".to_owned())?;
    let args: Vec<String> = env::args().skip(1).collect();
    match executable.as_str() {
        "pulse-load-pressure-producer" => role_command("produce", &args),
        "pulse-load-pressure-receiver" => role_command("ingest", &args),
        "pulse-support-resolver" => resolver_command(&args),
        "pulse-nq-load-support" => {
            let (role, rest) = args
                .split_first()
                .ok_or_else(|| "usage: pulse-nq-load-support produce|ingest ...".to_owned())?;
            role_command(role, rest)
        }
        _ => Err("unsupported executable role".into()),
    }
}

fn role_command(role: &str, args: &[String]) -> Result<(), String> {
    if args.len() != 4 || args[0] != "--config" || args[2] != "--acquisition-id" {
        return Err(format!(
            "usage: {role} --config ABSOLUTE_PATH --acquisition-id TOKEN"
        ));
    }
    let config_path = Path::new(&args[1]);
    if !config_path.is_absolute() {
        return Err("configuration path must be absolute".into());
    }
    let config = LoadSupportConfigV1::from_path(config_path)?;
    let identity = match role {
        "produce" => produce(&config, &args[3])?,
        "ingest" => ingest(&config, &args[3])?,
        _ => return Err("only the closed produce and ingest roles exist".into()),
    };
    println!("{identity}");
    Ok(())
}

fn resolver_command(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("pulse-support-resolver accepts no arguments".into());
    }
    let config_path = env::var_os("PULSE_LOAD_SUPPORT_CONFIG")
        .ok_or_else(|| "PULSE_LOAD_SUPPORT_CONFIG is required".to_owned())?;
    let config_path = PathBuf::from(config_path);
    if !config_path.is_absolute() {
        return Err("PULSE_LOAD_SUPPORT_CONFIG must be absolute".into());
    }
    let config = LoadSupportConfigV1::from_path(&config_path)?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(64 * 1_024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 64 * 1_024 {
        return Err("Nightshift support query exceeds the byte bound".into());
    }
    let query: PresentEvidenceQueryV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let support = resolve(&config, &query)?;
    let output = serde_jcs::to_vec(&support).map_err(|error| error.to_string())?;
    std::io::stdout()
        .write_all(&output)
        .map_err(|error| error.to_string())?;
    Ok(())
}
