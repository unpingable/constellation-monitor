#![forbid(unsafe_code)]

use pulse_nq_filesystem_support::{self as filesystem, FilesystemSupportConfigV1};
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
    if args.len() == 11
        && args[0] == "prepare"
        && args[1] == "--request"
        && args[3] == "--nq-config"
        && args[5] == "--instance"
        && args[7] == "--state"
        && args[9] == "--realization"
    {
        let request_id = filesystem::prepare(
            Path::new(&args[2]),
            Path::new(&args[4]),
            &args[6],
            Path::new(&args[8]),
            Path::new(&args[10]),
        )?;
        println!("{request_id}");
        return Ok(());
    }
    if args.len() == 3 && args[0] == "create-key" && args[1] == "--path" {
        let public = filesystem::create_producer_key(Path::new(&args[2]))?;
        println!("{public}");
        return Ok(());
    }
    if args.is_empty() || args.len() == 3 && args[0] == "resolve" && args[1] == "--config" {
        let path = if args.is_empty() {
            std::env::var("PULSE_FILESYSTEM_SUPPORT_CONFIG")
                .map_err(|_| "PULSE_FILESYSTEM_SUPPORT_CONFIG is required")?
        } else {
            args[2].clone()
        };
        let config = load(&path)?;
        let mut b = Vec::new();
        std::io::stdin()
            .take(65_537)
            .read_to_end(&mut b)
            .map_err(|e| e.to_string())?;
        if b.len() > 65_536 {
            return Err("Nightshift filesystem query exceeds byte bound".into());
        }
        let query: PresentEvidenceQueryV1 =
            serde_json::from_slice(&b).map_err(|e| e.to_string())?;
        let support = filesystem::resolve(&config, &query)?;
        std::io::stdout()
            .write_all(&serde_jcs::to_vec(&support).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    if args.len() == 5 && args[1] == "--config" && args[3] == "--acquisition-id" {
        let config = load(&args[2])?;
        let id = match args[0].as_str() {
            "produce" => filesystem::produce(&config, &args[4])?,
            "ingest" => filesystem::ingest(&config, &args[4])?,
            _ => return Err("filesystem support role must be produce or ingest".into()),
        };
        println!("{id}");
        return Ok(());
    }
    Err("usage: pulse-nq-filesystem-support prepare --request PATH --nq-config PATH --instance TOKEN --state PATH --realization PATH; produce|ingest --config ABSOLUTE_PATH --acquisition-id TOKEN; resolve --config ABSOLUTE_PATH; create-key --path ABSOLUTE_PATH".into())
}
fn load(text: &str) -> Result<FilesystemSupportConfigV1, String> {
    let path = Path::new(text);
    if !path.is_absolute() {
        return Err("absolute filesystem support configuration required".into());
    }
    FilesystemSupportConfigV1::from_path(path)
}
