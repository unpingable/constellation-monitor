#![forbid(unsafe_code)]

use std::env;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    match env::args().nth(1).as_deref() {
        Some("demo") => {
            let artifact = pulse_transport_canary::run_matched_custody_demo()?;
            println!("{}", serde_json::to_string_pretty(&artifact)?);
            Ok(())
        }
        Some("expiry-demo") => {
            let artifact = pulse_transport_canary::run_silence_expiry_demo()?;
            println!("{}", serde_json::to_string_pretty(&artifact)?);
            Ok(())
        }
        Some("restart-demo") => {
            let artifact = pulse_transport_canary::run_restart_custody_demo()?;
            println!("{}", serde_json::to_string_pretty(&artifact)?);
            Ok(())
        }
        Some("udp-loopback") => {
            let artifact = pulse_transport_canary::run_udp_loopback_probe(b"custody-canary-probe");
            println!("{}", serde_json::to_string_pretty(&artifact)?);
            Ok(())
        }
        Some("crash-child") => {
            let point = env::args().nth(2).ok_or("crash-child point is required")?;
            let path = env::args()
                .nth(3)
                .ok_or("crash-child ready path is required")?;
            pulse_transport_canary::run_crash_child(&point, std::path::Path::new(&path))?;
            Ok(())
        }
        Some("artifacts") => {
            let path = env::args().nth(2).ok_or("artifact directory is required")?;
            let set = pulse_transport_canary::write_campaign_artifacts(&path)?;
            println!("{}", serde_json::to_string_pretty(&set)?);
            Ok(())
        }
        _ => Err(
            "usage: pulse-transport-canary <demo|expiry-demo|restart-demo|udp-loopback|crash-child|artifacts>"
                .into(),
        ),
    }
}
