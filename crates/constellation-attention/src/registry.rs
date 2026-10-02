//! The closed, versioned rule registry. Rules are compiled in; configuration
//! may only enable or disable a rule, change its one threshold, and choose
//! `page` or `notice` where the rule allows it. There are no user-defined rules.

use serde::Serialize;

/// Identity of this registry revision. Bump it whenever a rule's meaning changes.
pub const REGISTRY_VERSION: &str = "constellation.attention_registry.v1";

/// How long a cleared condition must stay clear before it is resolved.
pub const RESOLVE_CONFIRM_SECONDS: i64 = 120;

/// Minimum spacing between delivery retries for one condition and route.
pub const RESEND_INTERVAL_SECONDS: i64 = 900;
/// The longest run of unknown observations a persistence or confirmation
/// interval may contain: one 60 s pass interval plus timer jitter. A longer
/// unknown gap restarts the interval at the next definite observation.
pub const UNKNOWN_GAP_SECONDS: i64 = 90;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Page,
    Notice,
}

impl Class {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Page => "page",
            Self::Notice => "notice",
        }
    }
}

/// The kind of configured input a rule reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    HostPosture,
    NqStatus,
    Nightshift,
    SavedCheck,
    /// The evaluator's own view of whether its configured inputs are readable.
    Evaluator,
    /// Not deployed; the rule exists so the registry matches Cartography.
    NotDeployed,
}

/// What the rule's single tunable threshold bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdMeaning {
    /// The underlying state must persist continuously for longer than the threshold.
    Persistence,
    /// A source timestamp must be older than the threshold; the resulting
    /// condition must then persist for `fixed_persistence_seconds`.
    Age,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Rule {
    /// Registry anchor (the Cartography `RUNBOOKS.md` anchor where one exists).
    pub id: &'static str,
    pub version: u32,
    pub default_class: Class,
    /// Whether configuration may make the rule page. Only anchors NQ's v2
    /// PagerDuty contract accepts can page.
    pub page_allowed: bool,
    /// v2 severity when the rule pages.
    pub severity: &'static str,
    /// NQ v2 `condition.component`. `None` means "the component of the input"
    /// (only `evaluator-input-unavailable`).
    pub component: Option<&'static str>,
    pub input: InputKind,
    pub threshold_meaning: ThresholdMeaning,
    pub default_threshold_seconds: i64,
    /// Persistence after the age threshold for `Age` rules; zero otherwise.
    pub fixed_persistence_seconds: i64,
    pub runbook_anchor: &'static str,
    /// The document the anchor belongs to.
    pub runbook_document: &'static str,
    pub operator_response: &'static str,
    /// What the condition is, in one line.
    pub condition: &'static str,
    /// Present when the rule cannot run on this estate.
    pub disabled: Option<&'static str>,
}

const CARTOGRAPHY: &str = "cartography:architecture/beta-observability/docs/RUNBOOKS.md";
const MONITOR: &str = "constellation-monitor:docs/ATTENTION.md";

pub const RULES: [Rule; 10] = [
    Rule {
        id: "host-posture-unknown",
        version: 1,
        default_class: Class::Page,
        page_allowed: true,
        severity: "critical",
        component: Some("host_posture"),
        input: InputKind::HostPosture,
        threshold_meaning: ThresholdMeaning::Persistence,
        default_threshold_seconds: 600,
        fixed_persistence_seconds: 0,
        runbook_anchor: "host-posture-unknown",
        runbook_document: CARTOGRAPHY,
        operator_response: "Follow the runner's refusal code; unknown persisting means the cause will not clear itself (re-enroll on digest mismatch).",
        condition: "Projection aggregate_state is unknown, or CURRENT is stale (fresh_until passed).",
        disabled: None,
    },
    Rule {
        id: "host-disk",
        version: 1,
        default_class: Class::Notice,
        page_allowed: true,
        severity: "warning",
        component: Some("host_posture"),
        input: InputKind::HostPosture,
        threshold_meaning: ThresholdMeaning::Persistence,
        default_threshold_seconds: 900,
        fixed_persistence_seconds: 0,
        runbook_anchor: "host-disk",
        runbook_document: CARTOGRAPHY,
        operator_response: "Ordinary host operations: check the NQ store, host-posture state root, Nightshift stores and Classic backups first.",
        condition: "Current projection reports capacity pressure (degraded or worse) for this publication root.",
        disabled: None,
    },
    Rule {
        id: "nq-no-fresh-acquisition",
        version: 1,
        default_class: Class::Page,
        page_allowed: true,
        severity: "critical",
        component: Some("nq"),
        input: InputKind::HostPosture,
        threshold_meaning: ThresholdMeaning::Age,
        default_threshold_seconds: 600,
        fixed_persistence_seconds: 300,
        runbook_anchor: "nq-no-fresh-acquisition",
        runbook_document: CARTOGRAPHY,
        operator_response: "Read the runner journal for acquisition_refused; if the runner is down start it and watch two occurrences. Do not raise NQ timeouts.",
        condition: "The newest host-posture status object was generated longer ago than the threshold.",
        disabled: None,
    },
    Rule {
        id: "service-down",
        version: 1,
        default_class: Class::Page,
        page_allowed: true,
        severity: "critical",
        component: Some("service"),
        input: InputKind::NqStatus,
        threshold_meaning: ThresholdMeaning::Persistence,
        default_threshold_seconds: 180,
        fixed_persistence_seconds: 0,
        runbook_anchor: "service-down",
        runbook_document: CARTOGRAPHY,
        operator_response: "systemctl status <unit>; restart if failed; if it refuses to start read the preflight/identity errors.",
        condition: "NQ's current nq.systemd_unit v2 evaluation reports systemd_unit_not_active present for the unit.",
        disabled: None,
    },
    Rule {
        id: "memory-pressure",
        version: 1,
        default_class: Class::Notice,
        page_allowed: false,
        severity: "warning",
        component: Some("host_posture"),
        input: InputKind::NqStatus,
        threshold_meaning: ThresholdMeaning::Persistence,
        default_threshold_seconds: 600,
        fixed_persistence_seconds: 0,
        runbook_anchor: "memory-pressure",
        runbook_document: MONITOR,
        operator_response: "Check PSI (/proc/pressure/memory) and the largest resident processes; this is stall pressure, not memory used.",
        condition: "NQ's current nq.host_memory evaluation reports memory_pressure_stall present.",
        disabled: None,
    },
    Rule {
        id: "nightshift-recurrence-missing",
        version: 1,
        default_class: Class::Page,
        page_allowed: true,
        severity: "critical",
        component: Some("nightshift"),
        input: InputKind::Nightshift,
        threshold_meaning: ThresholdMeaning::Age,
        default_threshold_seconds: 1800,
        fixed_persistence_seconds: 300,
        runbook_anchor: "nightshift-recurrence-missing",
        runbook_document: CARTOGRAPHY,
        operator_response: "systemctl list-timers nightshift-*; start an inactive timer; slow ticks see nightshift-cycle-slow; NQ export refusals see the NQ runbooks.",
        condition: "The last closed Nightshift observation cycle is older than the threshold.",
        disabled: None,
    },
    Rule {
        id: "sqlite-health",
        version: 1,
        default_class: Class::Notice,
        page_allowed: false,
        severity: "warning",
        component: Some("nq"),
        input: InputKind::SavedCheck,
        threshold_meaning: ThresholdMeaning::Persistence,
        default_threshold_seconds: 600,
        fixed_persistence_seconds: 0,
        runbook_anchor: "sqlite-health",
        runbook_document: MONITOR,
        operator_response: "Inspect the saved check's retained result (nq saved-check result) and the named SQLite file; do not edit the store.",
        condition: "The newest retained NQ saved-check result for this reference failed.",
        disabled: None,
    },
    Rule {
        id: "evaluator-input-unavailable",
        version: 1,
        default_class: Class::Notice,
        page_allowed: false,
        severity: "warning",
        component: None,
        input: InputKind::Evaluator,
        threshold_meaning: ThresholdMeaning::Persistence,
        default_threshold_seconds: 300,
        fixed_persistence_seconds: 0,
        runbook_anchor: "evaluator-input-unavailable",
        runbook_document: MONITOR,
        operator_response: "Read report.json for the input's error; fix permissions, paths or the producing timer. Rules fed by the input hold their state meanwhile.",
        condition: "A configured input cannot be read, or its content is not current.",
        disabled: None,
    },
    Rule {
        id: "docket-unsettled",
        version: 1,
        default_class: Class::Page,
        page_allowed: true,
        severity: "critical",
        component: Some("docket"),
        input: InputKind::NotDeployed,
        threshold_meaning: ThresholdMeaning::Age,
        default_threshold_seconds: 3600,
        fixed_persistence_seconds: 300,
        runbook_anchor: "docket-unsettled",
        runbook_document: CARTOGRAPHY,
        operator_response: "Determine whether the executor is available or the observer never reported; follow the Docket reconciliation procedure.",
        condition: "Oldest accepted governed-loop attempt is older than the threshold.",
        disabled: Some("input not deployed"),
    },
    Rule {
        id: "ag-executor-unavailable",
        version: 1,
        default_class: Class::Page,
        page_allowed: true,
        severity: "critical",
        component: Some("ag"),
        input: InputKind::NotDeployed,
        threshold_meaning: ThresholdMeaning::Persistence,
        default_threshold_seconds: 300,
        fixed_persistence_seconds: 0,
        runbook_anchor: "ag-executor-unavailable",
        runbook_document: CARTOGRAPHY,
        operator_response: "Check the ag-effectd unit; restart only on a crash; intentional stops are acknowledged for the declared window.",
        condition: "AG effectd reports not ready.",
        disabled: Some("input not deployed"),
    },
];

#[must_use]
pub fn rule(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|rule| rule.id == id)
}

/// The rule anchors NQ 0.2.1 accepts in a v2 (`PagerDuty`) intent.
pub const NQ_V2_RULES: [&str; 17] = [
    "nq-no-fresh-acquisition",
    "host-posture-unknown",
    "nightshift-recurrence-missing",
    "docket-unsettled",
    "ag-executor-unavailable",
    "service-down",
    "host-disk",
    "nq-latency-near-bound",
    "nq-open-cost-growing",
    "nq-pending-acquisition",
    "host-posture-refusals",
    "host-posture-retention",
    "nightshift-evidence-stale",
    "nightshift-cycle-slow",
    "docket-reconciliation-lag",
    "ag-repeated-refusals",
    "build-identity",
];

/// The closed v2 component set.
pub const NQ_V2_COMPONENTS: [&str; 6] = [
    "nq",
    "host_posture",
    "nightshift",
    "docket",
    "ag",
    "service",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_capable_rules_are_nq_anchors() {
        for rule in RULES {
            assert_eq!(
                rule.page_allowed,
                NQ_V2_RULES.contains(&rule.id),
                "{} page_allowed must match NQ's anchor set",
                rule.id
            );
            if rule.default_class == Class::Page {
                assert!(rule.page_allowed, "{}", rule.id);
            }
            if let Some(component) = rule.component {
                assert!(NQ_V2_COMPONENTS.contains(&component), "{}", rule.id);
            }
            crate::condition::validate_token("rule", rule.id, 64).unwrap();
        }
    }

    #[test]
    fn rule_ids_are_unique() {
        let mut ids: Vec<_> = RULES.iter().map(|rule| rule.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), RULES.len());
    }
}
