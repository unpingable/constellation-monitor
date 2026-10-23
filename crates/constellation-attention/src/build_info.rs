//! Build identity printed by `--version` and `--build-info`.

use serde::Serialize;

use crate::registry::REGISTRY_VERSION;

include!(concat!(env!("OUT_DIR"), "/build_identity.rs"));

/// The oldest NQ whose intent contract this build speaks (`response_class`).
pub const MINIMUM_NQ: &str = "0.2.2";
pub const BUILD_INFO_SCHEMA: &str = "constellation.attention_build_info.v1";

/// Withhold non-HTTPS `runbook_url` from v2 intents while retaining the
/// inspection link; introduced in e314c94.
pub const RUNBOOK_URL_WITHHELD_FOR_HTTP: &str = "runbook_url_withheld_for_http";
/// Deliver a `local_file` page route as a v1 page-tier copy through
/// `deliver-local`; introduced in f7b74cc.
pub const LOCAL_PAGE_ROUTE_V1_COPY: &str = "local_page_route_v1_copy";
/// Keep bounded value-code warming informational without triggering or
/// resolving conditions, and preserve existing faults across upgrade grace;
/// introduced in f9fe6f2.
pub const VALUE_CODE_WARMING_INFORMATIONAL: &str = "value_code_warming_informational";
/// Record `exit_code`, `exit_class` and `first_error` on completed pass reports;
/// introduced in e314c94.
pub const REPORT_EXIT_FIELDS: &str = "report_exit_fields";
/// Accept HTTP runbook bases on literal loopback addresses with an explicit
/// port and path; introduced in 3ecf0bb.
pub const LOOPBACK_HTTP_RUNBOOKS: &str = "loopback_http_runbooks";
/// Reject invalid metric-alert definitions or site targets independently,
/// including shared targets, while evaluating admitted rules; introduced in 69eac29.
pub const METRIC_ALERT_ADMISSION_PER_RULE: &str = "metric_alert_admission_per_rule";
/// Interpret opted-in v1 value codes: code 1 proves presence even amid unknown
/// codes 2–5, which cannot establish recovery; introduced in a22f15e.
pub const VALUE_CODES_V1: &str = "value_codes_v1";
/// Installer-signalled grace for rule evaluation and acquisition after apply.
pub const RECONFIGURATION_GRACE: &str = "reconfiguration_grace";

/// Distinguish required delivery failure from input failure in completed reports.
pub const DELIVERY_EXIT_CODE: &str = "delivery_exit_code";

/// Reconcile retained routes, preserve delivery obligations, and close removed pages.
pub const ROUTE_CHANGE_RECONCILE: &str = "route_change_reconcile";

/// Supported behaviours. Published identifiers are never renamed or removed
/// without a build-info schema bump.
pub const CAPABILITIES: &[&str] = &[
    RUNBOOK_URL_WITHHELD_FOR_HTTP,
    LOCAL_PAGE_ROUTE_V1_COPY,
    VALUE_CODE_WARMING_INFORMATIONAL,
    REPORT_EXIT_FIELDS,
    LOOPBACK_HTTP_RUNBOOKS,
    METRIC_ALERT_ADMISSION_PER_RULE,
    VALUE_CODES_V1,
    RECONFIGURATION_GRACE,
    DELIVERY_EXIT_CODE,
    ROUTE_CHANGE_RECONCILE,
];

#[derive(Debug, Serialize)]
pub struct BuildInformation {
    pub schema: &'static str,
    pub name: &'static str,
    pub version: &'static str,
    /// Explicit `MONITOR_SOURCE_COMMIT`, else `unavailable`.
    pub source_commit: &'static str,
    pub registry: &'static str,
    pub minimum_nq: &'static str,
    pub rustc: &'static str,
    pub build_id: Option<&'static str>,
    pub target: &'static str,
    pub debug_assertions: bool,
    /// Additive v1 field; older producers may omit it.
    pub capabilities: &'static [&'static str],
}

#[must_use]
pub const fn build_information() -> BuildInformation {
    BuildInformation {
        schema: BUILD_INFO_SCHEMA,
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        source_commit: match SOURCE_COMMIT {
            Some(value) => value,
            None => "unavailable",
        },
        registry: REGISTRY_VERSION,
        minimum_nq: MINIMUM_NQ,
        rustc: match RUSTC {
            Some(value) => value,
            None => "unavailable",
        },
        build_id: BUILD_ID,
        target: TARGET,
        debug_assertions: cfg!(debug_assertions),
        capabilities: CAPABILITIES,
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
