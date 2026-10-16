//! Embed explicit source/build declarations and compiler metadata.

#[path = "../../build-support/remediation/generator.rs"]
mod generator;

fn main() {
    generator::run();
}
