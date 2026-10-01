//! Closed-surface structural qualification.
//!
//! The rules are enforced natively here so they hold on any host. The
//! repository's shell check is also run, and absence of its required `rg`
//! executable is a qualification failure rather than a skipped check.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root")
}

fn sources(directory: &Path) -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    for entry in fs::read_dir(directory).expect("source directory") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            let text = fs::read_to_string(&path).expect("source text");
            files.push((path, text));
        }
    }
    files.sort();
    files
}

fn assert_absent(files: &[(PathBuf, String)], needles: &[&str], why: &str) {
    for (path, text) in files {
        for needle in needles {
            assert!(
                !text.contains(needle),
                "{}: contains `{needle}` ({why})",
                path.display()
            );
        }
    }
}

#[test]
fn correspondence_crate_has_a_closed_surface() {
    let root = repo_root();
    let src = root.join("crates/pulse-nq-load-correspondence/src");
    let files = sources(&src);
    let port = fs::read_to_string(src.join("nq_cli.rs")).expect("nq_cli.rs");
    assert!(
        port.contains("env_clear()"),
        "NQ port must clear the environment"
    );
    assert!(
        port.contains("executable_sha256") && port.contains("config_sha256"),
        "NQ port must pin executable and configuration digests"
    );
    assert!(
        port.contains("Stdio::null()"),
        "NQ port must give NQ no standard input"
    );
    assert!(
        port.contains("pub trait NqPort: sealed::Sealed"),
        "NQ port must be sealed against caller-defined command carriers"
    );
    for (path, text) in &files {
        if path.file_name().is_some_and(|name| name == "nq_cli.rs") {
            continue;
        }
        for needle in [
            "acquire-next-local",
            "replay-local-successor",
            "\"qualify\"",
        ] {
            assert!(
                !text.contains(needle),
                "{}: NQ command name outside the closed port",
                path.display()
            );
        }
    }
    assert_absent(
        &files,
        &[
            "/proc/loadavg",
            "available_parallelism",
            "/proc/stat",
            "/proc/meminfo",
            "/proc/sys",
            "hostname",
            "TcpStream",
            "UdpSocket",
            "reqwest",
            "curl",
        ],
        "host source or network surface",
    );
    assert_absent(
        &files,
        &[
            "\"execute\"",
            "\"import\"",
            "\"collect\"",
            "diagnostics execute",
            "diagnostics import",
        ],
        "NQ operation other than the closed three",
    );
    assert_absent(
        &files,
        &[
            "derive_state",
            "load_pressure_state",
            "normalized_load",
            "pulse_nq_load_support",
        ],
        "load-pressure recomputation or bridge reference",
    );
    assert_absent(
        &files,
        &[
            "WithinDeclaredBound",
            "OutsideDeclaredBound",
            "AuthenticationResultV1::Verified",
            "LivePresentSupportResponseV1::new",
            "current = true",
            "current: true",
        ],
        "signal assessment, authentication claim, or currentness fabrication",
    );
    // The verified value is process-local: no serde derive and no Clone.
    let verified = fs::read_to_string(src.join("verified.rs")).expect("verified.rs");
    assert!(!verified.contains("use serde"));
    assert!(!verified.contains("impl Clone for VerifiedCorrespondenceV1"));
    assert!(verified.contains("#[derive(Debug)]\npub struct VerifiedCorrespondenceV1"));
    assert!(verified.contains("sealed_at: Instant"));
}

#[test]
fn bridge_and_correspondence_remain_independent() {
    let root = repo_root();
    let bridge = sources(&root.join("crates/pulse-nq-load-support/src"));
    assert_absent(
        &bridge,
        &[
            "pulse_nq_load_correspondence",
            "pulse-nq-load-correspondence",
            "constellation_status_nq_load_pressure",
        ],
        "bridge must not reference the correspondence or consequence crate",
    );
    let bridge_manifest =
        fs::read_to_string(root.join("crates/pulse-nq-load-support/Cargo.toml")).unwrap();
    assert!(!bridge_manifest.contains("correspondence"));
    let correspondence_manifest =
        fs::read_to_string(root.join("crates/pulse-nq-load-correspondence/Cargo.toml")).unwrap();
    assert!(!correspondence_manifest.contains("pulse-nq-load-support"));
}

#[test]
fn consequence_adapter_has_no_acquisition_surface() {
    let root = repo_root();
    let files = sources(&root.join("crates/constellation-status-nq-load-pressure/src"));
    assert_absent(
        &files,
        &[
            "std::process",
            "Command::new",
            "/proc",
            "derive_state",
            "load_pressure_state",
            "normalized_load",
            "pulse_nq_load_support",
            "LivePresentSupportResponseV1::new",
        ],
        "consequence adapter must not acquire, recompute, or fabricate",
    );
}

#[test]
fn repository_structural_script_passes() {
    let root = repo_root();
    let script = root.join("scripts/check_exact_load_support_surface.sh");
    let text = fs::read_to_string(&script).expect("script");
    // The ratified bridge block is byte-identical to its pre-correspondence
    // form: these exact lines must still be present and unmodified.
    for line in [
        "rg -q 'const PROC_LOADAVG: &str = \"/proc/loadavg\"' \"$source_file\" || fail \"fixed load source missing\"",
        "rg -q 'NORMALIZED_LOAD_THRESHOLD_MILLIS: u32 = 2_000' \"$source_file\" || fail \"exact threshold missing\"",
        "rg -q 'SUPPORT_VALIDITY_MS: u64 = 300_000' \"$source_file\" || fail \"exact profile horizon missing\"",
        "echo \"exact-load-support: closed proposition-specific non-actuating surface\"",
    ] {
        assert!(text.contains(line), "bridge rule line changed: {line}");
    }
    let ripgrep = Command::new("rg")
        .arg("--version")
        .output()
        .expect("rg must be installed for the repository structural check");
    assert!(
        ripgrep.status.success(),
        "rg must be runnable for the repository structural check"
    );
    let output = Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        .output()
        .expect("run structural script");
    assert!(
        output.status.success(),
        "structural script failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
