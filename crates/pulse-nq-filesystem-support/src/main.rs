#![forbid(unsafe_code)]
use pulse_nq_filesystem_support::{
    self as filesystem, FilesystemRequestContext, FilesystemSupportConfigV1,
};
use pulse_nq_load_support::PresentEvidenceQueryV1;
use std::{
    io::{Read as _, Write as _},
    path::Path,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
fn run() -> Result<(), String> {
    if filesystem::build_info::write_if_requested("pulse-nq-filesystem-support")
        .map_err(|e| e.to_string())?
    {
        return Ok(());
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 3 && args[0] == "create-key" && args[1] == "--path" {
        println!("{}", filesystem::create_producer_key(Path::new(&args[2]))?);
        return Ok(());
    }
    let (role, config_path, request_path, acquisition) = if args.is_empty() {
        (
            "resolve".to_owned(),
            std::env::var("PULSE_FILESYSTEM_SUPPORT_CONFIG")
                .map_err(|_| "PULSE_FILESYSTEM_SUPPORT_CONFIG is required")?,
            std::env::var("PULSE_FILESYSTEM_SUPPORT_REQUEST")
                .map_err(|_| "PULSE_FILESYSTEM_SUPPORT_REQUEST is required for this invocation")?,
            None,
        )
    } else if (args.len() == 5 || args.len() == 7)
        && args[1] == "--config"
        && args[3] == "--request"
    {
        let acquisition = if args.len() == 7 && args[5] == "--acquisition-id" {
            Some(args[6].clone())
        } else if args.len() == 5 {
            None
        } else {
            return Err(usage().into());
        };
        (
            args[0].clone(),
            args[2].clone(),
            args[4].clone(),
            acquisition,
        )
    } else {
        return Err(usage().into());
    };
    let path = Path::new(&config_path);
    if !path.is_absolute() {
        return Err("absolute static filesystem configuration required".into());
    }
    let config = FilesystemSupportConfigV1::from_path(path)?;
    let context = FilesystemRequestContext::from_path(&config, Path::new(&request_path))?;
    match (role.as_str(), acquisition) {
        ("produce", Some(id)) => println!("{}", filesystem::produce(&config, &context, &id)?),
        ("ingest", Some(id)) => println!("{}", filesystem::ingest(&config, &context, &id)?),
        ("resolve", None) => {
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(65_537)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() > 65_536 {
                return Err("Nightshift filesystem query exceeds byte bound".into());
            }
            let query: PresentEvidenceQueryV1 =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            let support = filesystem::resolve(&config, &context, &query)?;
            std::io::stdout()
                .write_all(&serde_jcs::to_vec(&support).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        }
        _ => return Err(usage().into()),
    }
    Ok(())
}
fn usage() -> &'static str {
    "usage: pulse-nq-filesystem-support produce|ingest --config ABSOLUTE_PATH --request ABSOLUTE_PATH --acquisition-id TOKEN; resolve --config ABSOLUTE_PATH --request ABSOLUTE_PATH; create-key --path ABSOLUTE_PATH"
}
