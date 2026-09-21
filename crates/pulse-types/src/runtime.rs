use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    ConsumerId, ConsumerProfileGenerationId, ContextActivationId, ContradictionId,
    ContradictionRecordV1, CoverageSummaryV1, DigestV1, EscalationStateV1,
    EvaluatorSemanticGenerationId, EvidenceWindowId, IncarnationId, JudgmentCategoryV1,
    MockDiagnosticReceiptV1, MutationAuthorityV1, ObservationPolicyGenerationId,
    ObserverSetGenerationId, PolicyGenerationId, QualifiedGenerationBindingV1,
    RemoteObservationCustodyReferenceV1, RuntimeRefusalId, SCHEMA_VERSION_V1, SparseDurableEventV1,
    SubjectScopeV1, SupportCertificateId, digest_parts,
};

pub const MAX_CERTIFICATE_EVIDENCE_REFS: usize = 64;
pub const MAX_CERTIFICATE_MISSING_PREMISES: usize = 64;
pub const MAX_CERTIFICATE_CONTRADICTIONS: usize = 64;

/// Every semantic input whose change invalidates an existing reliance result.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelianceContextV1 {
    pub schema_version: u16,
    pub activation_id: ContextActivationId,
    pub reliance_policy_generation: PolicyGenerationId,
    pub reliance_policy_semantic_digest: DigestV1,
    pub consumer_profile_generation: ConsumerProfileGenerationId,
    pub evaluator_semantic_generation: EvaluatorSemanticGenerationId,
    pub observer_set_generation: ObserverSetGenerationId,
    pub observation_policy_generation: ObservationPolicyGenerationId,
}

impl RelianceContextV1 {
    pub fn validate(&self) -> Result<(), RuntimeTypeError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(RuntimeTypeError::new(
                "unsupported_schema",
                "reliance context schema is unsupported",
            ));
        }
        self.activation_id
            .validate()
            .map_err(|_| RuntimeTypeError::identity("activation_id"))?;
        self.reliance_policy_generation
            .validate()
            .map_err(|_| RuntimeTypeError::identity("reliance_policy_generation"))?;
        self.reliance_policy_semantic_digest
            .validate()
            .map_err(|_| RuntimeTypeError::new("invalid_digest", "invalid policy digest"))?;
        self.consumer_profile_generation
            .validate()
            .map_err(|_| RuntimeTypeError::identity("consumer_profile_generation"))?;
        self.evaluator_semantic_generation
            .validate()
            .map_err(|_| RuntimeTypeError::identity("evaluator_semantic_generation"))?;
        self.observer_set_generation
            .validate()
            .map_err(|_| RuntimeTypeError::identity("observer_set_generation"))?;
        self.observation_policy_generation
            .validate()
            .map_err(|_| RuntimeTypeError::identity("observation_policy_generation"))?;
        Ok(())
    }

    #[must_use]
    pub fn identity_digest(&self) -> DigestV1 {
        digest_parts(
            "reliance.context.v1",
            &[
                self.activation_id.as_str().as_bytes(),
                self.reliance_policy_generation.as_str().as_bytes(),
                self.reliance_policy_semantic_digest.as_str().as_bytes(),
                self.consumer_profile_generation.as_str().as_bytes(),
                self.evaluator_semantic_generation.as_str().as_bytes(),
                self.observer_set_generation.as_str().as_bytes(),
                self.observation_policy_generation.as_str().as_bytes(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationTransitionCauseV1 {
    InitialActivation,
    ReliancePolicyChanged,
    ConsumerProfileChanged,
    EvaluatorSemanticsChanged,
    ObserverSetChanged,
    ObservationPolicyChanged,
    EquivalentBodyNewGeneration,
    PolicyRollback,
    AbaReactivation,
    SubjectIncarnationChanged,
    ReceiverRestarted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelianceContextTransitionV1 {
    pub schema_version: u16,
    pub subject_scope: SubjectScopeV1,
    pub consumer: ConsumerId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_context: Option<RelianceContextV1>,
    pub new_context: RelianceContextV1,
    pub cause: GenerationTransitionCauseV1,
    pub at_monotonic_ms: u64,
    pub standing_inherited: bool,
}

/// Bounded explanation of one current evaluation occurrence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelianceSupportCertificateV1 {
    pub schema_version: u16,
    pub certificate_id: SupportCertificateId,
    pub consumer: ConsumerId,
    pub subject_scope: SubjectScopeV1,
    pub context: RelianceContextV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualified_generation: Option<QualifiedGenerationBindingV1>,
    pub evaluated_at_monotonic_ms: u64,
    pub receiver_clock_id: String,
    pub judgment: JudgmentCategoryV1,
    pub evidence_window_id: EvidenceWindowId,
    pub supporting_evidence_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_observation_custody: Vec<RemoteObservationCustodyReferenceV1>,
    pub missing_premises: Vec<String>,
    pub applicable_contradictions: Vec<ContradictionId>,
    pub coverage: CoverageSummaryV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub earliest_support_expiry_monotonic_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_scheduled_reevaluation_monotonic_ms: Option<u64>,
    pub escalation: EscalationStateV1,
    pub mutation_authority: MutationAuthorityV1,
}

impl RelianceSupportCertificateV1 {
    #[must_use]
    pub fn compute_id(&self) -> SupportCertificateId {
        let context_digest = self.context.identity_digest();
        let mut owned = vec![
            self.consumer.as_str().as_bytes().to_vec(),
            self.subject_scope.subject.as_str().as_bytes().to_vec(),
            self.subject_scope
                .subject_incarnation
                .as_str()
                .as_bytes()
                .to_vec(),
            self.subject_scope.scope.as_bytes().to_vec(),
            context_digest.as_str().as_bytes().to_vec(),
            self.qualified_generation.as_ref().map_or_else(
                || b"qualified-generation:none".to_vec(),
                |binding| binding.identity_digest().as_str().as_bytes().to_vec(),
            ),
            self.evaluated_at_monotonic_ms.to_be_bytes().to_vec(),
            self.receiver_clock_id.as_bytes().to_vec(),
            self.judgment.as_str().as_bytes().to_vec(),
            self.evidence_window_id.as_str().as_bytes().to_vec(),
            self.earliest_support_expiry_monotonic_ms
                .unwrap_or(u64::MAX)
                .to_be_bytes()
                .to_vec(),
            self.next_scheduled_reevaluation_monotonic_ms
                .unwrap_or(u64::MAX)
                .to_be_bytes()
                .to_vec(),
            escalation_transcript(&self.escalation).into_bytes(),
            b"mutation-authority:none".to_vec(),
        ];
        for evidence in &self.supporting_evidence_ids {
            owned.push(b"evidence".to_vec());
            owned.push(evidence.as_bytes().to_vec());
        }
        for custody in &self.remote_observation_custody {
            owned.push(b"remote-custody".to_vec());
            owned.push(custody.identity_digest().as_str().as_bytes().to_vec());
        }
        for premise in &self.missing_premises {
            owned.push(b"missing".to_vec());
            owned.push(premise.as_bytes().to_vec());
        }
        for contradiction in &self.applicable_contradictions {
            owned.push(b"contradiction".to_vec());
            owned.push(contradiction.as_str().as_bytes().to_vec());
        }
        for tag in &self.coverage.required {
            owned.push(b"coverage-required".to_vec());
            owned.push(tag.as_bytes().to_vec());
        }
        for tag in &self.coverage.active {
            owned.push(b"coverage-active".to_vec());
            owned.push(tag.as_bytes().to_vec());
        }
        for tag in &self.coverage.missing {
            owned.push(b"coverage-missing".to_vec());
            owned.push(tag.as_bytes().to_vec());
        }
        for tag in &self.coverage.expired {
            owned.push(b"coverage-expired".to_vec());
            owned.push(tag.as_bytes().to_vec());
        }
        owned.push(self.coverage.active_observers.to_be_bytes().to_vec());
        owned.push(self.coverage.required_observers.to_be_bytes().to_vec());
        for count in &self.coverage.per_tag {
            owned.push(count.tag.as_bytes().to_vec());
            owned.push(count.active_observers.to_be_bytes().to_vec());
            owned.push(count.expired_observers.to_be_bytes().to_vec());
            owned.push(count.required_observers.to_be_bytes().to_vec());
        }
        let parts = owned.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let digest = digest_parts("reliance.support-certificate.v1", &parts);
        SupportCertificateId::new(format!(
            "support:{}",
            digest.as_str().trim_start_matches("sha256:")
        ))
    }

    pub fn validate(&self) -> Result<(), RuntimeTypeError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(RuntimeTypeError::new(
                "unsupported_schema",
                "support certificate schema is unsupported",
            ));
        }
        self.certificate_id
            .validate()
            .map_err(|_| RuntimeTypeError::identity("certificate_id"))?;
        self.consumer
            .validate()
            .map_err(|_| RuntimeTypeError::identity("consumer"))?;
        self.subject_scope
            .validate()
            .map_err(|_| RuntimeTypeError::identity("subject_scope"))?;
        self.context.validate()?;
        if let Some(binding) = &self.qualified_generation {
            binding
                .validate()
                .map_err(|error| RuntimeTypeError::new(error.code, "invalid qualified binding"))?;
            if binding.generation_set.subject != self.subject_scope.subject
                || binding.generation_set.consumer != self.consumer
                || !binding.generation_set.matches_context(&self.context)
            {
                return Err(RuntimeTypeError::new(
                    "qualified_binding_mismatch",
                    "qualified generation binding does not match the certificate context",
                ));
            }
        }
        if self.supporting_evidence_ids.len() > MAX_CERTIFICATE_EVIDENCE_REFS
            || self.remote_observation_custody.len() > MAX_CERTIFICATE_EVIDENCE_REFS
            || self.missing_premises.len() > MAX_CERTIFICATE_MISSING_PREMISES
            || self.applicable_contradictions.len() > MAX_CERTIFICATE_CONTRADICTIONS
        {
            return Err(RuntimeTypeError::new(
                "bound_exceeded",
                "support certificate collection exceeds its v1 bound",
            ));
        }
        if !strictly_sorted(&self.supporting_evidence_ids)
            || !self
                .remote_observation_custody
                .windows(2)
                .all(|pair| pair[0].identity_digest() < pair[1].identity_digest())
            || !strictly_sorted(&self.missing_premises)
            || !strictly_sorted(&self.applicable_contradictions)
        {
            return Err(RuntimeTypeError::new(
                "noncanonical_collection",
                "support certificate collections must be sorted and unique",
            ));
        }
        for custody in &self.remote_observation_custody {
            custody.validate().map_err(|error| {
                RuntimeTypeError::new(error.code, "invalid remote observation custody")
            })?;
            if custody.subject_scope != self.subject_scope
                || !self
                    .supporting_evidence_ids
                    .contains(&custody.supporting_evidence_id)
            {
                return Err(RuntimeTypeError::new(
                    "remote_custody_mismatch",
                    "remote custody does not identify supporting evidence for this subject",
                ));
            }
            // The receiver-boundary activation and this consumer's evaluator
            // activation are separately named qualified contexts. They may be
            // different exact manifests/receipts inside one process; treating
            // them as equal would collapse receiver admission into consumer
            // reliance and would break consumer-indexed semantics.
        }
        if self.judgment == JudgmentCategoryV1::Current {
            if self.qualified_generation.is_none()
                || self.earliest_support_expiry_monotonic_ms.is_none()
                || self.next_scheduled_reevaluation_monotonic_ms
                    != self.earliest_support_expiry_monotonic_ms
                || self
                    .earliest_support_expiry_monotonic_ms
                    .is_some_and(|deadline| deadline <= self.evaluated_at_monotonic_ms)
                || !self.missing_premises.is_empty()
                || !self.applicable_contradictions.is_empty()
                || !self.coverage.missing.is_empty()
            {
                return Err(RuntimeTypeError::new(
                    "invalid_current_support",
                    "CURRENT certificate must bind qualified generation, complete premises, and a future exact support expiry",
                ));
            }
        } else if self.earliest_support_expiry_monotonic_ms.is_some()
            || self.next_scheduled_reevaluation_monotonic_ms.is_some()
        {
            return Err(RuntimeTypeError::new(
                "invalid_deadline",
                "non-current certificate cannot carry a positive support deadline",
            ));
        }
        if self.certificate_id != self.compute_id() {
            return Err(RuntimeTypeError::new(
                "identity_mismatch",
                "support certificate identity does not match its transcript",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeRefusalClassV1 {
    SubjectCapacity,
    ConsumerCapacity,
    ObserverCapacity,
    ReceiverStreamCapacity,
    IncarnationHistoryCapacity,
    PendingQueueCapacity,
    ScheduledDeadlineCapacity,
    ContextHistoryCapacity,
    EscalationCapacity,
    CertificateCapacity,
    SparseHistoryCapacity,
    ReceiptHistoryCapacity,
    ClockRegression,
    InvalidBinding,
    ReusedActivation,
    HistoricalStateInvalid,
    RuntimeBlind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRefusalV1 {
    pub schema_version: u16,
    pub refusal_id: RuntimeRefusalId,
    pub class: RuntimeRefusalClassV1,
    pub at_monotonic_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<crate::SubjectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumer: Option<ConsumerId>,
    pub configured_bound: u64,
    pub observed_count: u64,
    pub detail: String,
    pub current_preserved: bool,
    pub mutation_authority: MutationAuthorityV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContradictionApplicabilityV1 {
    Applicable {
        subject_incarnation: IncarnationId,
        blocks_reliance: bool,
    },
    InapplicableBySubjectReplacement {
        prior_subject_incarnation: IncarnationId,
        replacement_subject_incarnation: IncarnationId,
        at_monotonic_ms: u64,
        rule: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContradictionCustodyV1 {
    pub schema_version: u16,
    pub consumer: ConsumerId,
    pub contradiction: ContradictionRecordV1,
    pub applicability: ContradictionApplicabilityV1,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeMetricsV1 {
    pub schema_version: u16,
    pub expected_support_expiry_monotonic_ms: Option<u64>,
    pub actual_reevaluation_monotonic_ms: Option<u64>,
    pub maximum_stale_positive_duration_ms: u64,
    pub policy_transition_withdrawal_latency_ms: u64,
    pub scheduler_lateness_ms: u64,
    pub queue_refusal_count: u64,
    pub subject_refusal_count: u64,
    pub observer_refusal_count: u64,
    pub receiver_stream_refusal_count: u64,
    pub deadline_refusal_count: u64,
    pub context_refusal_count: u64,
    pub sparse_history_refusal_count: u64,
    pub duplicate_escalation_count: u64,
    pub recovered_sparse_record_count: u64,
    pub recovered_receipt_count: u64,
}

impl RuntimeMetricsV1 {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            schema_version: SCHEMA_VERSION_V1,
            expected_support_expiry_monotonic_ms: None,
            actual_reevaluation_monotonic_ms: None,
            maximum_stale_positive_duration_ms: 0,
            policy_transition_withdrawal_latency_ms: 0,
            scheduler_lateness_ms: 0,
            queue_refusal_count: 0,
            subject_refusal_count: 0,
            observer_refusal_count: 0,
            receiver_stream_refusal_count: 0,
            deadline_refusal_count: 0,
            context_refusal_count: 0,
            sparse_history_refusal_count: 0,
            duplicate_escalation_count: 0,
            recovered_sparse_record_count: 0,
            recovered_receipt_count: 0,
        }
    }
}

/// History-only restart material. Sparse events may contain a certificate
/// that was CURRENT historically, but the structure contains no authoritative
/// current projection, hot pulse, receiver lineage, or scheduled deadline.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeHistoricalStateV1 {
    pub schema_version: u16,
    pub sparse_events: Vec<SparseDurableEventV1>,
    pub contradictions: Vec<ContradictionCustodyV1>,
    pub diagnostic_receipts: Vec<MockDiagnosticReceiptV1>,
    pub nonclaims: Vec<String>,
}

impl RuntimeHistoricalStateV1 {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema_version: SCHEMA_VERSION_V1,
            sparse_events: Vec::new(),
            contradictions: Vec::new(),
            diagnostic_receipts: Vec::new(),
            nonclaims: history_nonclaims(),
        }
    }

    pub fn validate(&self) -> Result<(), RuntimeTypeError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(RuntimeTypeError::new(
                "unsupported_schema",
                "historical state schema is unsupported",
            ));
        }
        if self.nonclaims != history_nonclaims() {
            return Err(RuntimeTypeError::new(
                "nonclaim_mismatch",
                "historical state nonclaims are not the fixed v1 set",
            ));
        }
        Ok(())
    }
}

#[must_use]
pub fn history_nonclaims() -> Vec<String> {
    vec![
        "Historical records do not reconstruct current reliance.".to_owned(),
        "Restart does not recover hot pulse evidence or scheduled standing.".to_owned(),
        "Diagnostic receipts do not resolve contradictions or grant mutation authority.".to_owned(),
    ]
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeTypeError {
    pub code: &'static str,
    pub detail: &'static str,
}

impl RuntimeTypeError {
    pub const fn new(code: &'static str, detail: &'static str) -> Self {
        Self { code, detail }
    }

    const fn identity(field: &'static str) -> Self {
        Self::new("invalid_identity", field)
    }
}

impl fmt::Display for RuntimeTypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for RuntimeTypeError {}

fn strictly_sorted<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|pair| pair[0] < pair[1])
}

fn escalation_transcript(state: &EscalationStateV1) -> String {
    match state {
        EscalationStateV1::NotRequested => "not_requested".to_owned(),
        EscalationStateV1::Requested { request_id } => format!("requested:{request_id}"),
        EscalationStateV1::Accepted { request_id } => format!("accepted:{request_id}"),
        EscalationStateV1::Refused { request_id, reason } => {
            format!("refused:{request_id}:{reason}")
        }
        EscalationStateV1::Narrowed { request_id } => format!("narrowed:{request_id}"),
        EscalationStateV1::Deferred { request_id } => format!("deferred:{request_id}"),
        EscalationStateV1::Completed {
            request_id,
            receipt_id,
        } => format!("completed:{request_id}:{receipt_id}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthorityGrantsV1, ClockId, CoverageSummaryV1, EscalationStateV1, QualifiedGenerationSetV1,
        SubjectId, digest_parts,
    };

    fn context(activation: &str, generation: &str) -> RelianceContextV1 {
        RelianceContextV1 {
            schema_version: SCHEMA_VERSION_V1,
            activation_id: ContextActivationId::new(activation),
            reliance_policy_generation: PolicyGenerationId::new(generation),
            reliance_policy_semantic_digest: digest_parts("policy", &[b"same-body"]),
            consumer_profile_generation: ConsumerProfileGenerationId::new("consumer-profile:1"),
            evaluator_semantic_generation: EvaluatorSemanticGenerationId::new("evaluator:1"),
            observer_set_generation: ObserverSetGenerationId::new("observer-set:1"),
            observation_policy_generation: ObservationPolicyGenerationId::new(
                "observation-policy:1",
            ),
        }
    }

    #[test]
    fn equal_policy_content_does_not_make_context_identity_equal() {
        let first = context("activation:1", "policy:1");
        let second = context("activation:2", "policy:2");
        assert_eq!(
            first.reliance_policy_semantic_digest,
            second.reliance_policy_semantic_digest
        );
        assert_ne!(first.identity_digest(), second.identity_digest());
    }

    #[test]
    fn current_certificate_requires_exact_scheduled_expiry() {
        let exact_context = context("activation:1", "policy:1");
        let mut certificate = RelianceSupportCertificateV1 {
            schema_version: SCHEMA_VERSION_V1,
            certificate_id: SupportCertificateId::new("pending"),
            consumer: ConsumerId::new("consumer:a"),
            subject_scope: SubjectScopeV1 {
                subject: SubjectId::new("subject:a"),
                subject_incarnation: IncarnationId::new("subject-incarnation:1"),
                scope: "host".to_owned(),
            },
            context: exact_context.clone(),
            qualified_generation: Some(QualifiedGenerationBindingV1 {
                schema_version: SCHEMA_VERSION_V1,
                manifest_digest: digest_parts("manifest", &[b"one"]),
                qualification_certificate_digest: digest_parts("certificate", &[b"one"]),
                activation_receipt_digest: digest_parts("receipt", &[b"one"]),
                activation_occurrence_id: IncarnationId::new("activation-occurrence:one"),
                process_epoch_id: IncarnationId::new("process-epoch:one"),
                generation_set: QualifiedGenerationSetV1::from_context(
                    SubjectId::new("subject:a"),
                    ConsumerId::new("consumer:a"),
                    &exact_context,
                ),
                authority_grants: AuthorityGrantsV1::none(),
            }),
            evaluated_at_monotonic_ms: 10,
            receiver_clock_id: ClockId::new("clock:1").to_string(),
            judgment: JudgmentCategoryV1::Current,
            evidence_window_id: EvidenceWindowId::new("window:1"),
            supporting_evidence_ids: vec!["evidence:1".to_owned()],
            remote_observation_custody: Vec::new(),
            missing_premises: Vec::new(),
            applicable_contradictions: Vec::new(),
            coverage: CoverageSummaryV1 {
                required: vec!["load".to_owned()],
                active: vec!["load".to_owned()],
                missing: Vec::new(),
                expired: Vec::new(),
                active_observers: 1,
                required_observers: 1,
                per_tag: Vec::new(),
            },
            earliest_support_expiry_monotonic_ms: Some(20),
            next_scheduled_reevaluation_monotonic_ms: Some(20),
            escalation: EscalationStateV1::NotRequested,
            mutation_authority: MutationAuthorityV1::None,
        };
        certificate.certificate_id = certificate.compute_id();
        certificate.validate().expect("certificate is exact");
        certificate.next_scheduled_reevaluation_monotonic_ms = Some(21);
        assert!(certificate.validate().is_err());
    }
}
