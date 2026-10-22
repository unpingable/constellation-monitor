#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::path::Path;

use constellation_host_posture::{
    HostPostureConfig, REACTOR_CUSTODY_EXIT_CODE, REACTOR_CUSTODY_LOST, build_information, enroll,
    example_config, preflight, prepare_qualification, run,
};

fn usage() -> ! {
    eprintln!(
        "usage: constellation-host-posture <--build-info|build-info|example-config|enroll CONFIG INITIAL_NQ_ARTIFACT|preflight CONFIG|prepare-qualification CONFIG CREATE_NEW_DIRECTORY|run CONFIG>"
    );
    std::process::exit(2);
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = env::args().collect::<Vec<_>>();
    match arguments.as_slice() {
        [_, command] if command == "--build-info" || command == "build-info" => {
            serde_json::to_writer(std::io::stdout().lock(), &build_information())?;
            println!();
        }
        [_, command] if command == "example-config" => {
            print!("{}", example_config());
        }
        [_, command, config] if command == "preflight" => {
            let config = HostPostureConfig::load(Path::new(config))?;
            preflight(&config)?;
            println!("preflight=ok");
        }
        [_, command, config] if command == "run" => {
            let config = HostPostureConfig::load(Path::new(config))?;
            if let Err(error) = run(&config) {
                // `run` has already published unknown, stopped the worker,
                // shut the reactor down and logged the condition.
                if error.code == REACTOR_CUSTODY_LOST {
                    std::process::exit(REACTOR_CUSTODY_EXIT_CODE);
                }
                return Err(error.into());
            }
        }
        [_, command, config, initial] if command == "enroll" => {
            let config = HostPostureConfig::load(Path::new(config))?;
            let digest = enroll(&config, Path::new(initial))?;
            println!("profile={digest} path={}", config.profile_path.display());
        }
        [_, command, config, output] if command == "prepare-qualification" => {
            let config = HostPostureConfig::load(Path::new(config))?;
            let certificate = prepare_qualification(&config, Path::new(output))?;
            println!("certificate={certificate} path={output}");
        }
        _ => usage(),
    }
    Ok(())
}
