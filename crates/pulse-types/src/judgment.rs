use serde::{Deserialize, Serialize};

use crate::{
    ConsumerId, ContradictionId, DiagnosticReceiptId, DigestV1, EvidenceWindowId,
    PolicyGenerationId, SCHEMA_VERSION_V1, SubjectScopeV1, TransitionId,
};

pub const INCOMPLETE_COVERAGE_EXPLANATION: &str = "No violating observation is currently known, but coverage is incomplete and reliance is therefore UNKNOWN.";
pub const NO_MUTATION_NONCLAIM: &str =
    "This judgment grants no authority to execute, repair, or mutate anything.";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JudgmentCategoryV1 {
    Current,
    Degraded,
    Suspect,
    Unknown,
    Contradicted,
}

impl JudgmentCategoryV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "CURRENT",
            Self::Degraded => "DEGRADED",
            Self::Suspect => "SUSPECT",
            Self::Unknown => "UNKNOWN",
            Self::Contradicted => "CONTRADICTED",
        }
    }

    #[must_use]
    pub const fn supports_present_reliance(self) -> bool {
        matches!(self, Self::Current)
    }
}

impl std::fmt::Display for JudgmentCategoryV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessDimensionV1 {
    Current,
    Mixed,
    Expired,
    NoEvidence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SequenceContinuityDimensionV1 {
    FirstSeen,
    Continuous,
    Gapped,
    Restarted,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserverAvailabilityDimensionV1 {
    Available,
    Partial,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossObserverCoherenceDimensionV1 {
    Coherent,
    Disagreement,
    Insufficient,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageDimensionV1 {
    Complete,
    Partial,
    Absent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceDimensionV1 {
    Verified,
    Degraded,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportDimensionV1 {
    Normal,
    Degraded,
    Blind,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectSignalConsistencyDimensionV1 {
    Consistent,
    Violation,
    Contradictory,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfidenceDimensionsV1 {
    pub freshness: FreshnessDimensionV1,
    pub sequence_continuity: SequenceContinuityDimensionV1,
    pub observer_availability: ObserverAvailabilityDimensionV1,
    pub cross_observer_coherence: CrossObserverCoherenceDimensionV1,
    pub coverage: CoverageDimensionV1,
    pub provenance: ProvenanceDimensionV1,
    pub transport: TransportDimensionV1,
    pub subject_signal_consistency: SubjectSignalConsistencyDimensionV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageCountV1 {
    pub tag: String,
    pub active_observers: u32,
    pub expired_observers: u32,
    pub required_observers: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageSummaryV1 {
    pub required: Vec<String>,
    pub active: Vec<String>,
    pub missing: Vec<String>,
    pub expired: Vec<String>,
    pub active_observers: u32,
    pub required_observers: u32,
    pub per_tag: Vec<CoverageCountV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JudgmentReasonV1 {
    pub code: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JudgmentExplanationV1 {
    pub summary: String,
    pub reasons: Vec<JudgmentReasonV1>,
    pub claims: Vec<String>,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationAuthorityV1 {
    None,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum EscalationStateV1 {
    NotRequested,
    Requested {
        request_id: String,
    },
    Accepted {
        request_id: String,
    },
    Refused {
        request_id: String,
        reason: String,
    },
    Narrowed {
        request_id: String,
    },
    Deferred {
        request_id: String,
    },
    Completed {
        request_id: String,
        receipt_id: DiagnosticReceiptId,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PresentStateJudgmentV1 {
    pub schema_version: u16,
    pub subject_scope: SubjectScopeV1,
    pub consumer: ConsumerId,
    pub policy_generation: PolicyGenerationId,
    pub coverage: CoverageSummaryV1,
    pub evaluated_at_monotonic_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub positive_support_expires_at_monotonic_ms: Option<u64>,
    pub receiver_clock_id: String,
    pub evidence_window_id: EvidenceWindowId,
    pub category: JudgmentCategoryV1,
    pub dimensions: ConfidenceDimensionsV1,
    pub explanation: JudgmentExplanationV1,
    pub escalation: EscalationStateV1,
    pub mutation_authority: MutationAuthorityV1,
}

impl PresentStateJudgmentV1 {
    #[must_use]
    pub fn supports_present_reliance(&self) -> bool {
        self.category.supports_present_reliance()
    }

    #[must_use]
    pub const fn grants_mutation_authority(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JudgmentTransitionV1 {
    pub schema_version: u16,
    pub transition_id: TransitionId,
    pub subject_scope: SubjectScopeV1,
    pub consumer: ConsumerId,
    pub policy_generation: PolicyGenerationId,
    pub at_monotonic_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<JudgmentCategoryV1>,
    pub to: JudgmentCategoryV1,
    pub prior_evidence_window: Option<EvidenceWindowId>,
    pub evidence_window: EvidenceWindowId,
    pub reason_codes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContradictionStatusV1 {
    Active,
    Resolved {
        resolver: String,
        resolved_at_monotonic_ms: u64,
        rule: String,
        explanation: String,
    },
    Superseded {
        superseding_record: ContradictionId,
        at_monotonic_ms: u64,
        rule: String,
    },
    ExpiredUnderNamedRule {
        at_monotonic_ms: u64,
        rule: String,
    },
    InapplicableBySubjectReplacement {
        prior_subject_incarnation: crate::IncarnationId,
        replacement_subject_incarnation: crate::IncarnationId,
        at_monotonic_ms: u64,
        rule: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContradictionRecordV1 {
    pub schema_version: u16,
    pub contradiction_id: ContradictionId,
    pub subject_scope: SubjectScopeV1,
    pub policy_generation: PolicyGenerationId,
    pub signal: String,
    pub first_observed_at_monotonic_ms: u64,
    pub evidence_refs: Vec<String>,
    pub incompatible_statements: Vec<String>,
    pub status: ContradictionStatusV1,
}

impl ContradictionRecordV1 {
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, ContradictionStatusV1::Active)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentalMetricsV1 {
    pub schema_version: u16,
    pub pulse_to_evaluation_latency_ms: u64,
    pub maximum_stale_positive_duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_to_unknown_latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_to_contradicted_latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_to_escalation_latency_ms: Option<u64>,
    pub false_escalation_count: u64,
    pub active_coverage: u32,
    pub expired_coverage: u32,
    pub dropped_stale_pulse_count: u64,
    pub duplicate_count: u64,
    pub sequence_gap_count: u64,
    pub escalation_deduplication_count: u64,
    pub monitor_input_drop_count: u64,
}

impl ExperimentalMetricsV1 {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            schema_version: SCHEMA_VERSION_V1,
            pulse_to_evaluation_latency_ms: 0,
            maximum_stale_positive_duration_ms: 0,
            failure_to_unknown_latency_ms: None,
            failure_to_contradicted_latency_ms: None,
            failure_to_escalation_latency_ms: None,
            false_escalation_count: 0,
            active_coverage: 0,
            expired_coverage: 0,
            dropped_stale_pulse_count: 0,
            duplicate_count: 0,
            sequence_gap_count: 0,
            escalation_deduplication_count: 0,
            monitor_input_drop_count: 0,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticEvidenceReferenceV1 {
    pub receipt_id: DiagnosticReceiptId,
    pub result_digest: DigestV1,
    pub recorded_at_monotonic_ms: u64,
    pub applicable_until_monotonic_ms: u64,
    pub nonclaims: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_current_supports_present_reliance() {
        for category in [
            JudgmentCategoryV1::Degraded,
            JudgmentCategoryV1::Suspect,
            JudgmentCategoryV1::Unknown,
            JudgmentCategoryV1::Contradicted,
        ] {
            assert!(!category.supports_present_reliance());
        }
        assert!(JudgmentCategoryV1::Current.supports_present_reliance());
    }
}
