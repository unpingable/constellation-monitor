//! Build identity printed by `--version` and `--build-info`.

use serde::Serialize;

use crate::registry::REGISTRY_VERSION;

/// The oldest NQ whose intent contract this build speaks (`response_class`).
pub const MINIMUM_NQ: &str = "0.2.2";
pub const BUILD_INFO_SCHEMA: &str = "constellation.attention_build_info.v1";

#[derive(Debug, Serialize)]
pub struct BuildInformation {
    pub schema: &'static str,
    pub name: &'static str,
    pub version: &'static str,
    /// `MONITOR_SOURCE_COMMIT`, else `git rev-parse HEAD` at build time,
    /// else `unavailable`.
    pub source_commit: &'static str,
    pub registry: &'static str,
    pub minimum_nq: &'static str,
    pub rustc: &'static str,
}

#[must_use]
pub const fn build_information() -> BuildInformation {
    BuildInformation {
        schema: BUILD_INFO_SCHEMA,
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        source_commit: env!("CONSTELLATION_ATTENTION_SOURCE_COMMIT"),
        registry: REGISTRY_VERSION,
        minimum_nq: MINIMUM_NQ,
        rustc: env!("CONSTELLATION_ATTENTION_RUSTC"),
    }
}

/// `constellation-attention <version> (<source commit>)`.
#[must_use]
pub fn version_line() -> String {
    let info = build_information();
    format!("{} {} ({})", info.name, info.version, info.source_commit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_info_parses_and_names_the_minimum_nq() {
        let text = serde_json::to_string(&build_information()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["minimum_nq"], "0.2.2");
        assert_eq!(value["name"], "constellation-attention");
        assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(value["registry"], REGISTRY_VERSION);
        let commit = value["source_commit"].as_str().unwrap();
        assert!(
            commit == "unavailable"
                || (commit.len() == 40 && commit.bytes().all(|byte| byte.is_ascii_hexdigit())),
            "{commit}"
        );
        assert!(
            value["rustc"].as_str().unwrap().starts_with("rustc ")
                || value["rustc"] == "unavailable"
        );
        assert!(version_line().starts_with("constellation-attention "));
    }
}
