//! Embed the source commit and compiler identity for `--version` and
//! `--build-info`. `MONITOR_SOURCE_COMMIT` wins (release builds from a
//! `git archive` export set it); otherwise `git rev-parse HEAD`; otherwise
//! `unavailable`. Nothing is invented.

use std::process::Command;

fn output(program: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(program).args(arguments).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn main() {
    println!("cargo:rerun-if-env-changed=MONITOR_SOURCE_COMMIT");
    let commit = std::env::var("MONITOR_SOURCE_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_owned())
        .or_else(|| output("git", &["rev-parse", "HEAD"]))
        .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .unwrap_or_else(|| "unavailable".to_owned());
    println!("cargo:rustc-env=CONSTELLATION_ATTENTION_SOURCE_COMMIT={commit}");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let version = output(&rustc, &["--version"]).unwrap_or_else(|| "unavailable".to_owned());
    println!("cargo:rustc-env=CONSTELLATION_ATTENTION_RUSTC={version}");
}
