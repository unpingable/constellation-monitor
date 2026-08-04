use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    BridgeId, ClockId, ConsumerId, DiagnosticReceiptId, DiagnosticRunId, DigestV1,
    EscalationRequestId, ObservationPolicyGenerationId, PolicyGenerationId, SCHEMA_VERSION_V1,
    SubjectScopeV1, TransitionId, digest_parts,
};

pub const ESCALATION_NONCLAIMS: [&str; 4] = [
    "This request is not diagnostic evidence.",
    "This request grants no execution or mutation authority.",
    "Acceptance authorizes only the named bounded observation profile in the local bridge.",
    "Diagnostic completion does not establish subject health or indefinite reliance.",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticProfileIdV1 {
    pub name: String,
    pub version: u16,
    pub semantic_digest: DigestV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationTriggerClassV1 {
    FreshnessLost,
    CoverageCollapse,
    ObserverDisagreement,
    ContradictionRetained,
    SubjectBoundViolated,
    ProvenanceFailed,
    TransportBlind,
    SequenceDiscontinuity,
}

impl EscalationTriggerClassV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FreshnessLost => "freshness_lost",
            Self::CoverageCollapse => "coverage_collapse",
            Self::ObserverDisagreement => "observer_disagreement",
            Self::ContradictionRetained => "contradiction_retained",
            Self::SubjectBoundViolated => "subject_bound_violated",
            Self::ProvenanceFailed => "provenance_failed",
            Self::TransportBlind => "transport_blind",
            Self::SequenceDiscontinuity => "sequence_discontinuity",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticBoundsV1 {
    pub maximum_runtime_ms: u64,
    pub maximum_output_bytes: u64,
    pub maximum_observations: u32,
}

impl DiagnosticBoundsV1 {
    #[must_use]
    pub const fn is_nonzero(self) -> bool {
        self.maximum_runtime_ms > 0
            && self.maximum_output_bytes > 0
            && self.maximum_observations > 0
    }

    #[must_use]
    pub const fn fits_within(self, limit: Self) -> bool {
        self.maximum_runtime_ms <= limit.maximum_runtime_ms
            && self.maximum_output_bytes <= limit.maximum_output_bytes
            && self.maximum_observations <= limit.maximum_observations
    }

    #[must_use]
    pub const fn narrowed_to(self, limit: Self) -> Self {
        Self {
            maximum_runtime_ms: if self.maximum_runtime_ms < limit.maximum_runtime_ms {
                self.maximum_runtime_ms
            } else {
                limit.maximum_runtime_ms
            },
            maximum_output_bytes: if self.maximum_output_bytes < limit.maximum_output_bytes {
                self.maximum_output_bytes
            } else {
                limit.maximum_output_bytes
            },
            maximum_observations: if self.maximum_observations < limit.maximum_observations {
                self.maximum_observations
            } else {
                limit.maximum_observations
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticEscalationRequestV1 {
    pub schema_version: u16,
    pub request_id: EscalationRequestId,
    pub subject_scope: SubjectScopeV1,
    pub consumer: ConsumerId,
    pub trigger_class: EscalationTriggerClassV1,
    pub evidence_window_digest: DigestV1,
    pub policy_generation: PolicyGenerationId,
    pub observation_policy_generation: ObservationPolicyGenerationId,
    pub diagnostic_profile: DiagnosticProfileIdV1,
    pub bounds: DiagnosticBoundsV1,
    pub clock_id: ClockId,
    pub created_at_monotonic_ms: u64,
    pub expires_at_monotonic_ms: u64,
    pub deduplication_key: DigestV1,
    pub causal_transition_id: TransitionId,
    pub nonclaims: Vec<String>,
}

impl DiagnosticEscalationRequestV1 {
    #[must_use]
    pub fn compute_deduplication_key(&self) -> DigestV1 {
        digest_parts(
            "diagnostic.escalation.dedup.v1",
            &[
                self.subject_scope.subject.as_str().as_bytes(),
                self.subject_scope.subject_incarnation.as_str().as_bytes(),
                self.subject_scope.scope.as_bytes(),
                self.consumer.as_str().as_bytes(),
                self.policy_generation.as_str().as_bytes(),
                self.observation_policy_generation.as_str().as_bytes(),
                self.trigger_class.as_str().as_bytes(),
                self.diagnostic_profile.name.as_bytes(),
                &self.diagnostic_profile.version.to_be_bytes(),
                self.diagnostic_profile.semantic_digest.as_str().as_bytes(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), EscalationError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(EscalationError::new(
                "unsupported_schema",
                "request schema is unsupported",
            ));
        }
        self.request_id
            .validate()
            .map_err(|_| EscalationError::new("invalid_identity", "invalid request identity"))?;
        self.subject_scope
            .validate()
            .map_err(|_| EscalationError::new("invalid_scope", "invalid subject scope"))?;
        self.consumer
            .validate()
            .map_err(|_| EscalationError::new("invalid_identity", "invalid consumer identity"))?;
        self.policy_generation
            .validate()
            .map_err(|_| EscalationError::new("invalid_identity", "invalid policy generation"))?;
        self.observation_policy_generation.validate().map_err(|_| {
            EscalationError::new("invalid_identity", "invalid observation-policy generation")
        })?;
        self.clock_id
            .validate()
            .map_err(|_| EscalationError::new("invalid_identity", "invalid clock identity"))?;
        self.causal_transition_id
            .validate()
            .map_err(|_| EscalationError::new("invalid_identity", "invalid transition identity"))?;
        self.evidence_window_digest.validate().map_err(|_| {
            EscalationError::new("invalid_digest", "invalid evidence window digest")
        })?;
        self.diagnostic_profile
            .semantic_digest
            .validate()
            .map_err(|_| EscalationError::new("invalid_digest", "invalid profile digest"))?;
        if self.diagnostic_profile.name.is_empty() || self.diagnostic_profile.version == 0 {
            return Err(EscalationError::new(
                "invalid_profile",
                "profile identity is incomplete",
            ));
        }
        if !self.bounds.is_nonzero() {
            return Err(EscalationError::new(
                "invalid_bounds",
                "every diagnostic bound must be nonzero",
            ));
        }
        if self.expires_at_monotonic_ms <= self.created_at_monotonic_ms {
            return Err(EscalationError::new(
                "invalid_expiry",
                "expiry must be later than creation",
            ));
        }
        if self.compute_deduplication_key() != self.deduplication_key {
            return Err(EscalationError::new(
                "deduplication_mismatch",
                "deduplication key does not match its semantic transcript",
            ));
        }
        if self.nonclaims
            != ESCALATION_NONCLAIMS
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        {
            return Err(EscalationError::new(
                "nonclaim_mismatch",
                "request nonclaims are not the fixed v1 set",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
pub enum EscalationDispositionKindV1 {
    Accept {
        admitted_bounds: DiagnosticBoundsV1,
    },
    Refuse {
        code: String,
        detail: String,
    },
    Narrow {
        allowed_profile: DiagnosticProfileIdV1,
        allowed_bounds: DiagnosticBoundsV1,
        detail: String,
    },
    Defer {
        code: String,
        detail: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EscalationDispositionV1 {
    pub schema_version: u16,
    pub request_id: EscalationRequestId,
    pub bridge_id: BridgeId,
    pub clock_id: ClockId,
    pub decided_at_monotonic_ms: u64,
    pub kind: EscalationDispositionKindV1,
    pub mutation_authority: crate::MutationAuthorityV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticReceiptStatusV1 {
    Completed,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticResultEntryV1 {
    pub name: String,
    pub value: String,
    pub interpretation: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MockDiagnosticReceiptV1 {
    pub schema_version: u16,
    pub receipt_id: DiagnosticReceiptId,
    pub run_id: DiagnosticRunId,
    pub request_id: EscalationRequestId,
    pub causal_transition_id: TransitionId,
    pub deduplication_key: DigestV1,
    pub evidence_window_digest: DigestV1,
    pub subject_scope: SubjectScopeV1,
    pub consumer: ConsumerId,
    pub policy_generation: PolicyGenerationId,
    pub observation_policy_generation: ObservationPolicyGenerationId,
    pub diagnostic_profile: DiagnosticProfileIdV1,
    pub bridge_id: BridgeId,
    pub clock_id: ClockId,
    pub started_at_monotonic_ms: u64,
    pub completed_at_monotonic_ms: u64,
    pub applicable_until_monotonic_ms: u64,
    pub status: DiagnosticReceiptStatusV1,
    pub results: Vec<DiagnosticResultEntryV1>,
    pub observed_coverage: Vec<String>,
    pub result_digest: DigestV1,
    pub nonclaims: Vec<String>,
    pub mutation_authority: crate::MutationAuthorityV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscalationError {
    pub code: &'static str,
    pub detail: &'static str,
}

impl EscalationError {
    pub const fn new(code: &'static str, detail: &'static str) -> Self {
        Self { code, detail }
    }
}

impl fmt::Display for EscalationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for EscalationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IncarnationId, SubjectId};

    #[test]
    fn deduplication_ignores_occurrence_time_but_binds_policy() {
        let profile_digest = digest_parts("profile", &[b"local.readonly.summary/v1"]);
        let mut request = DiagnosticEscalationRequestV1 {
            schema_version: SCHEMA_VERSION_V1,
            request_id: EscalationRequestId::new("request:1"),
            subject_scope: SubjectScopeV1 {
                subject: SubjectId::new("host:a"),
                subject_incarnation: IncarnationId::new("boot:1"),
                scope: "host".to_owned(),
            },
            consumer: ConsumerId::new("display:v1"),
            trigger_class: EscalationTriggerClassV1::CoverageCollapse,
            evidence_window_digest: digest_parts("window", &[b"one"]),
            policy_generation: PolicyGenerationId::new("policy:1"),
            observation_policy_generation: ObservationPolicyGenerationId::new(
                "observation-policy:1",
            ),
            diagnostic_profile: DiagnosticProfileIdV1 {
                name: "local.readonly.summary".to_owned(),
                version: 1,
                semantic_digest: profile_digest,
            },
            bounds: DiagnosticBoundsV1 {
                maximum_runtime_ms: 50,
                maximum_output_bytes: 1_024,
                maximum_observations: 4,
            },
            clock_id: ClockId::new("clock:1"),
            created_at_monotonic_ms: 10,
            expires_at_monotonic_ms: 100,
            deduplication_key: digest_parts("placeholder", &[]),
            causal_transition_id: TransitionId::new("transition:1"),
            nonclaims: ESCALATION_NONCLAIMS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        };
        request.deduplication_key = request.compute_deduplication_key();
        request.validate().expect("request is valid");
        let first = request.deduplication_key.clone();
        request.created_at_monotonic_ms += 1;
        request.expires_at_monotonic_ms += 1;
        request.request_id = EscalationRequestId::new("request:2");
        assert_eq!(request.compute_deduplication_key(), first);
        request.policy_generation = PolicyGenerationId::new("policy:2");
        assert_ne!(request.compute_deduplication_key(), first);
        request.policy_generation = PolicyGenerationId::new("policy:1");
        request.observation_policy_generation =
            ObservationPolicyGenerationId::new("observation-policy:2");
        assert_ne!(request.compute_deduplication_key(), first);
    }
}
