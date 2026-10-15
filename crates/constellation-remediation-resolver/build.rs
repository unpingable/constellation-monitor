//! Embed only explicit builder declarations for remediation identity.

#[path = "../../build-support/remediation/generator.rs"]
mod generator;

fn main() {
    generator::run();
}
