//! Build reporting for a packaged host-posture helper.

#[path = "../../build-support/host-posture-helper/generator.rs"]
mod generator;

fn main() {
    generator::run();
    use sha2::{Digest as _, Sha256};
    println!("cargo:rerun-if-changed=../../Cargo.lock");
    let lock = std::fs::read("../../Cargo.lock").expect("read actual Monitor lock");
    let digest = format!("sha256:{:x}", Sha256::digest(lock));
    let generated = format!("pub const MONITOR_CARGO_LOCK_DIGEST: &str = {digest:?};\n");
    let out =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
    std::fs::write(out.join("filesystem_realization.rs"), generated).expect("write lock identity");
}
