use std::{
    env, fs,
    io::{self, Write as _},
    path::Path,
    process::ExitCode,
};

use constellation_status_projection::{
    RenderedStatusV1, StatusArtifactV1, read_current_artifact, render_status, stage_publication,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("constellation-status: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [command, artifact] if command == "validate" => {
            let artifact = decode_file(Path::new(artifact))?;
            println!("{}", artifact.artifact_id);
            Ok(())
        }
        [command, artifact, now, uncertainty] if command == "render" => {
            let artifact = decode_file(Path::new(artifact))?;
            let rendered = render_status(
                &artifact,
                parse_u64("now", now)?,
                parse_u64("uncertainty", uncertainty)?,
            )
            .map_err(|error| error.to_string())?;
            match rendered {
                RenderedStatusV1::Current { html }
                | RenderedStatusV1::StatusUnavailable { html } => println!("{html}"),
            }
            Ok(())
        }
        [command, root, artifact] if command == "publish" => {
            let artifact = decode_file(Path::new(artifact))?;
            let id = stage_publication(Path::new(root), &artifact)
                .and_then(constellation_status_projection::StagedPublication::commit)
                .map_err(|error| error.to_string())?;
            println!("{id}");
            Ok(())
        }
        [command, root] if command == "read-current" => {
            let artifact = read_current_artifact(Path::new(root))
                .map_err(|error| error.to_string())?;
            let bytes = artifact.canonical_bytes().map_err(|error| error.to_string())?;
            io::stdout()
                .lock()
                .write_all(&bytes)
                .map_err(|error| error.to_string())?;
            Ok(())
        }
        _ => Err("usage: constellation-status validate ARTIFACT | render ARTIFACT NOW_UNIX_MS UNCERTAINTY_MS | publish ROOT ARTIFACT | read-current ROOT".to_owned()),
    }
}

fn decode_file(path: &Path) -> Result<StatusArtifactV1, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    StatusArtifactV1::decode_canonical(&bytes).map_err(|error| error.to_string())
}

fn parse_u64(name: &str, value: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|error| format!("invalid {name}: {error}"))
}
