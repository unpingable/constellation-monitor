//! The memory adapter has the same closed surface as the other adapters: it
//! never acquires, recomputes, fabricates, restates NQ's PSI parameters, or
//! maps another question.

use std::fs;
use std::path::Path;

#[test]
fn consequence_adapter_has_no_acquisition_surface() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in fs::read_dir(&src).expect("source directory") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("source text");
        for needle in [
            "std::process",
            "Command::new",
            "/proc",
            "/dev/disk",
            "std::fs",
            "mountinfo",
            "nix::",
            "libc::",
            "derive_state",
            "pulse_nq_load_support",
            "LivePresentSupportResponseV1::new",
            "HostLoadPressureV1",
            "HostFilesystemCapacityPressureV1",
            "avg10",
            "avg60",
            "avg300",
            "centipercent",
            "boot_age",
            "MemAvailable",
            "meminfo",
            "SwapFree",
            "SwapTotal",
            "10.00",
            "/proc/pressure",
        ] {
            assert!(
                !text.contains(needle),
                "{}: contains `{needle}` (adapter must not acquire, recompute, fabricate, or map another question)",
                path.display()
            );
        }
    }
}
