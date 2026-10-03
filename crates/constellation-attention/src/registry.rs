//! The closed, versioned rule registry. Rules are compiled in; configuration
//! may only enable or disable a rule, change its one threshold, and choose
//! `page` or `notice` where the rule allows it. There are no user-defined rules.

use serde::Serialize;

/// Identity of this registry revision. Bump it whenever a rule's meaning changes.
pub const REGISTRY_VERSION: &str = "constellation.attention_registry.v4";

/// How long a cleared condition must stay clear before it is resolved.
pub const RESOLVE_CONFIRM_SECONDS: i64 = 120;

/// Minimum spacing between delivery retries for one condition and route.
pub const RESEND_INTERVAL_SECONDS: i64 = 900;
/// Spacing of `PagerDuty` resubmissions of a retained record that was not
/// accepted. NQ's runbook: retryable, resubmit after a pause. `PagerDuty`'s
/// dedup key makes the repeat idempotent at the destination.
pub const PAGE_RESEND_SECONDS: i64 = 120;
/// The longest run of unknown observations an interval absorbs: one 60 s
/// pass interval plus timer jitter. A longer run moves the start of the
/// persistence or confirmation interval forward by its length.
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

/// How a human should be reached for a rule, carried in every intent as
/// `response_class`. Closed; there is no default.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseClass {
    /// Worth knowing; nobody needs to act.
    Informational,
    /// A human should look when they can (notice routes).
    Attention,
    /// A human should interrupt what they are doing (`PagerDuty`).
    Page,
}

impl ResponseClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Attention => "attention",
            Self::Page => "page",
        }
    }
}

/// What happens between "the condition persisted past its bound" and "a
/// human is paged" (cartography #55). Closed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponsePolicy {
    /// Notify and page on the rule's normal schedule. Every rule's default.
    #[default]
    ObserveOnly,
    /// For a configured remediation target of a page rule: the notice goes
    /// out on schedule, the page waits for the remediation window and is
    /// never sent if the condition clears inside it.
    AutoRemediateThenPage,
}

impl ResponsePolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObserveOnly => "observe_only",
            Self::AutoRemediateThenPage => "auto_remediate_then_page",
        }
    }
}

/// Rules that may carry `auto_remediate_then_page` targets (v1: only
/// `service-down`). Each must be a page rule.
pub const REMEDIATION_RULES: [&str; 1] = ["service-down"];

/// The kind of configured input a rule reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    HostPosture,
    NqStatus,
    /// Either a host-posture input or the NQ status input (`host-disk`).
    HostPostureOrNqStatus,
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

/// A registry rule. Every field is required and `Rule` has no `Default`:
/// a rule cannot be constructed without an explicit `response_class`.
///
/// ```compile_fail
/// use constellation_attention::registry::{Class, InputKind, ResponsePolicy, Rule, ThresholdMeaning};
/// let rule = Rule {
///     id: "x", version: 1, default_class: Class::Notice, page_allowed: false,
///     // no response_class
///     operator_action: "", escalation_reason: "",
///     response_policy: ResponsePolicy::ObserveOnly, severity: "warning",
///     component: Some("nq"), input: InputKind::NqStatus,
///     threshold_meaning: ThresholdMeaning::Persistence, default_threshold_seconds: 60,
///     fixed_persistence_seconds: 0, runbook_anchor: "x", runbook_document: "x",
///     operator_response: "x", condition: "x", disabled: None,
/// };
/// ```
///
/// ```
/// use constellation_attention::registry::{
///     Class, InputKind, ResponseClass, ResponsePolicy, Rule, ThresholdMeaning,
/// };
/// let rule = Rule {
///     id: "x", version: 1, default_class: Class::Notice, page_allowed: false,
///     response_class: ResponseClass::Attention,
///     operator_action: "", escalation_reason: "",
///     response_policy: ResponsePolicy::ObserveOnly, severity: "warning",
///     component: Some("nq"), input: InputKind::NqStatus,
///     threshold_meaning: ThresholdMeaning::Persistence, default_threshold_seconds: 60,
///     fixed_persistence_seconds: 0, runbook_anchor: "x", runbook_document: "x",
///     operator_response: "x", condition: "x", disabled: None,
/// };
/// assert_eq!(rule.response_class.as_str(), "attention");
/// ```
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Rule {
    /// Registry anchor (the Cartography `RUNBOOKS.md` anchor where one exists).
    pub id: &'static str,
    pub version: u32,
    pub default_class: Class,
    /// Whether NQ's v2 `PagerDuty` contract accepts this anchor at all.
    pub page_allowed: bool,
    /// Page eligibility, decided here and explicit per rule: only a rule
    /// whose response class is `page` can reach a `PagerDuty` route.
    pub response_class: ResponseClass,
    /// Page rules: what the human does when paged.
    pub operator_action: &'static str,
    /// Page rules: why persistence beyond the bound is worth an interruption.
    pub escalation_reason: &'static str,
    /// The registry default; configuration may set `auto_remediate_then_page`
    /// for named targets of a rule in [`REMEDIATION_RULES`] only.
    pub response_policy: ResponsePolicy,
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
        response_class: ResponseClass::Page,
        operator_action: "Read the runner's refusal code in its journal and fix the cause it names (re-enroll on digest mismatch); the projection cannot recover by itself.",
        escalation_reason: "Unknown or stale for more than 600 s: the projection has stopped saying anything about disk pressure, so a full disk would go unseen.",
        response_policy: ResponsePolicy::ObserveOnly,
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
        version: 3,
        default_class: Class::Notice,
        page_allowed: true,
        response_class: ResponseClass::Attention,
        operator_action: "",
        escalation_reason: "",
        response_policy: ResponsePolicy::ObserveOnly,
        severity: "warning",
        component: Some("host_posture"),
        input: InputKind::HostPostureOrNqStatus,
        threshold_meaning: ThresholdMeaning::Persistence,
        default_threshold_seconds: 900,
        fixed_persistence_seconds: 0,
        runbook_anchor: "host-disk",
        runbook_document: CARTOGRAPHY,
        operator_response: "Ordinary host operations: check the NQ store, host-posture state root, Nightshift stores and Classic backups first.",
        condition: "Capacity pressure: the current host-posture projection is degraded or worse for this publication root, or an NQ filesystem capacity watcher reports filesystem_capacity_pressure present.",
        disabled: None,
    },
    Rule {
        id: "nq-no-fresh-acquisition",
        version: 1,
        default_class: Class::Page,
        page_allowed: true,
        response_class: ResponseClass::Page,
        operator_action: "Read the runner journal for acquisition_refused; if the runner is down start it and watch two occurrences.",
        escalation_reason: "No status object generated for more than 600 s, then 300 s more: the host-posture runner has stopped and nothing is being observed.",
        response_policy: ResponsePolicy::ObserveOnly,
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
        response_class: ResponseClass::Page,
        operator_action: "systemctl status <unit>; restart it if failed; if it refuses to start read its preflight and identity errors.",
        escalation_reason: "The unit is not active for more than 180 s: past a restart or reload window, the service is down until someone acts.",
        response_policy: ResponsePolicy::ObserveOnly,
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
        response_class: ResponseClass::Attention,
        operator_action: "",
        escalation_reason: "",
        response_policy: ResponsePolicy::ObserveOnly,
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
        response_class: ResponseClass::Page,
        operator_action: "systemctl list-timers 'nightshift-*'; start an inactive timer; slow ticks see nightshift-cycle-slow.",
        escalation_reason: "No closed observation cycle for more than 1800 s, then 300 s more: the recurring observation has stopped and evidence is going stale.",
        response_policy: ResponsePolicy::ObserveOnly,
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
        response_class: ResponseClass::Attention,
        operator_action: "",
        escalation_reason: "",
        response_policy: ResponsePolicy::ObserveOnly,
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
        response_class: ResponseClass::Attention,
        operator_action: "",
        escalation_reason: "",
        response_policy: ResponsePolicy::ObserveOnly,
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
        response_class: ResponseClass::Page,
        operator_action: "Determine whether the executor is available or the observer never reported, then follow the Docket reconciliation procedure.",
        escalation_reason: "The oldest accepted governed-loop attempt is older than 3600 s, then 300 s more: work is stuck unsettled.",
        response_policy: ResponsePolicy::ObserveOnly,
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
        response_class: ResponseClass::Page,
        operator_action: "Check the ag-effectd unit; restart it only on a crash; an intentional stop is acknowledged for its declared window.",
        escalation_reason: "AG effectd not ready for more than 300 s: governed actions cannot execute.",
        response_policy: ResponsePolicy::ObserveOnly,
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

    /// The page set is explicit and closed; each page rule says what the
    /// human does and why its persistence is worth an interruption.
    #[test]
    fn page_eligibility_is_explicit_per_rule() {
        let pages: Vec<&str> = RULES
            .iter()
            .filter(|rule| rule.response_class == ResponseClass::Page)
            .map(|rule| rule.id)
            .collect();
        assert_eq!(
            pages,
            [
                "host-posture-unknown",
                "nq-no-fresh-acquisition",
                "service-down",
                "nightshift-recurrence-missing",
                "docket-unsettled",
                "ag-executor-unavailable",
            ]
        );
        for rule in RULES {
            if rule.response_class == ResponseClass::Page {
                assert!(rule.page_allowed, "{}", rule.id);
                assert_eq!(rule.default_class, Class::Page, "{}", rule.id);
                assert!(!rule.operator_action.is_empty(), "{}", rule.id);
                assert!(!rule.escalation_reason.is_empty(), "{}", rule.id);
            } else {
                assert_eq!(rule.default_class, Class::Notice, "{}", rule.id);
            }
        }
    }

    #[test]
    fn every_rule_observes_only_by_default_and_remediation_rules_page() {
        for rule in RULES {
            assert_eq!(
                rule.response_policy,
                ResponsePolicy::ObserveOnly,
                "{}",
                rule.id
            );
        }
        for id in REMEDIATION_RULES {
            assert_eq!(super::rule(id).unwrap().response_class, ResponseClass::Page);
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
