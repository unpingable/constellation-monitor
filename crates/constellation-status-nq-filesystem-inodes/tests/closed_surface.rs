//! The filesystem-inodes adapter has the same closed surface as the
//! load-pressure adapter: it never acquires, recomputes, or fabricates, and
//! never names an inode count or any other question of the table.

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
            "HostMemoryPressureStallV1",
            "SystemdUnitRequiredActiveV1",
            "statfs",
            "statvfs",
            "permille",
            "non-reserved",
            "f_files",
            "f_ffree",
            "f_favail",
            "inodes_total",
            "inodes_free",
            "inode count",
        ] {
            assert!(
                !text.contains(needle),
                "{}: contains `{needle}` (adapter must not acquire, recompute, fabricate, or map another question)",
                path.display()
            );
        }
    }
}
