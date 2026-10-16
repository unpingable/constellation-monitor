//! Build reporting for a packaged host-posture helper.

#[path = "../../build-support/host-posture-helper/generator.rs"]
mod generator;

fn main() {
    generator::run();
}
