#![allow(dead_code)]

use constellation_status_projection::{
    AudienceClassV1, AvailabilityV1, ComponentOutputFieldV1, ComponentPolicyV1,
    DependencyBehaviorV1, DependencyEdgeV1, DependencyEffectV1, DependencyKindV1,
    DisclosurePolicyV1, FactRequirementV1, ImpactV1, LiveQueryAnchorV1, LiveSupportObservationV1,
    LiveSupportSelectorV1, OutputComponentV1, PROJECTION_POLICY_SCHEMA_V1, ProjectionPolicyV1,
    SOURCE_FACT_SCHEMA_V1, SafeReasonV1, SourceFactClassV1, SourceFactV1,
};
use pulse_types::{
    AuthorityGrantsV1, ClockId, ConsumerId, ConsumerProfileGenerationId, ContextActivationId,
    CoverageSummaryV1, EscalationStateV1, EvaluatorSemanticGenerationId, EvidenceWindowId,
    IncarnationId, JudgmentCategoryV1, LIVE_PRESENT_SUPPORT_REQUEST_SCHEMA_V1,
    LivePresentSupportDispositionV1, LivePresentSupportNonce, LivePresentSupportRequestV1,
    LivePresentSupportResponseV1, ObservationPolicyGenerationId, ObserverSetGenerationId,
    PolicyGenerationId, QualifiedGenerationBindingV1, QualifiedGenerationSetV1, ReceiverId,
    RelianceContextV1, RelianceSupportCertificateV1, SCHEMA_VERSION_V1, SubjectId, SubjectScopeV1,
    SupportCertificateId, digest_parts,
};

pub const DIGEST_A: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

pub fn policy(public: bool) -> ProjectionPolicyV1 {
    let disclosure = DisclosurePolicyV1 {
        audience: if public {
            AudienceClassV1::Public
        } else {
            AudienceClassV1::Operator
        },
        component_fields: vec![
            ComponentOutputFieldV1::DisplayName,
            ComponentOutputFieldV1::State,
            ComponentOutputFieldV1::Mode,
            ComponentOutputFieldV1::Reason,
        ],
        safe_reasons: vec![
            reason(
                constellation_status_projection::ProjectedStateV1::Healthy,
                "All required observations are current.",
            ),
            reason(
                constellation_status_projection::ProjectedStateV1::Degraded,
                "Service is impaired.",
            ),
            reason(
                constellation_status_projection::ProjectedStateV1::PartialOutage,
                "Some service is unavailable.",
            ),
            reason(
                constellation_status_projection::ProjectedStateV1::MajorOutage,
                "Service is unavailable.",
            ),
            reason(
                constellation_status_projection::ProjectedStateV1::Unknown,
                "Current status is unavailable.",
            ),
        ],
        include_basis_digest: !public,
        include_observation_window: false,
    };
    ProjectionPolicyV1 {
        schema: PROJECTION_POLICY_SCHEMA_V1.to_owned(),
        projection_id: if public {
            "synthetic-public-reduction"
        } else {
            "synthetic-operator-reduction"
        }
        .to_owned(),
        generation: "synthetic-1".to_owned(),
        root_component: "synthetic.service".to_owned(),
        maximum_age_ms: 60_000,
        admitted_clock_uncertainty_ms: 250,
        timestamp_granularity_ms: 1_000,
        components: vec![
            ComponentPolicyV1 {
                key: "synthetic.dependency".to_owned(),
                output: (!public).then(|| OutputComponentV1 {
                    id: "subordinate".to_owned(),
                    display_name: "Synthetic dependency".to_owned(),
                }),
                required_facts: vec![requirement("fact.synthetic.dependency")],
                maintenance_assertion_ids: Vec::new(),
            },
            ComponentPolicyV1 {
                key: "synthetic.service".to_owned(),
                output: Some(OutputComponentV1 {
                    id: "service".to_owned(),
                    display_name: "Synthetic service".to_owned(),
                }),
                required_facts: vec![requirement("fact.synthetic.service")],
                maintenance_assertion_ids: vec!["maintenance.synthetic.service".to_owned()],
            },
        ],
        dependencies: vec![DependencyEdgeV1 {
            parent: "synthetic.service".to_owned(),
            dependency: "synthetic.dependency".to_owned(),
            kind: DependencyKindV1::Hard,
            behavior: DependencyBehaviorV1 {
                on_unavailable: DependencyEffectV1::MajorOutage,
                on_degraded: DependencyEffectV1::Degrade,
                on_partial: DependencyEffectV1::PartialOutage,
                on_unknown: DependencyEffectV1::Unknown,
            },
        }],
        disclosure,
    }
}

pub fn requirement(fact_id: &str) -> FactRequirementV1 {
    FactRequirementV1 {
        fact_id: fact_id.to_owned(),
        owner: "synthetic-fixture".to_owned(),
        native_schema: "synthetic.status_fact.v1".to_owned(),
        class: SourceFactClassV1::DerivedAdmitted,
        live_support: support_selector(),
    }
}

fn support_selector() -> LiveSupportSelectorV1 {
    let context = support_context();
    let consumer = support_consumer();
    let subject_scope = support_subject_scope();
    let binding = support_binding(&context, &consumer, &subject_scope);
    LiveSupportSelectorV1 {
        consumer: consumer.as_str().to_owned(),
        subject: subject_scope.subject.as_str().to_owned(),
        subject_incarnation: subject_scope.subject_incarnation.as_str().to_owned(),
        scope: subject_scope.scope,
        reliance_context_digest: context.identity_digest().as_str().to_owned(),
        qualified_generation_digest: binding.identity_digest().as_str().to_owned(),
        receiver: "receiver:status-projection".to_owned(),
        receiver_incarnation: "receiver-incarnation:status-projection".to_owned(),
        receiver_epoch_id: "receiver-epoch:status-projection".to_owned(),
        receiver_clock_id: "clock:status-projection".to_owned(),
    }
}

fn reason(state: constellation_status_projection::ProjectedStateV1, text: &str) -> SafeReasonV1 {
    SafeReasonV1 {
        state,
        text: text.to_owned(),
    }
}

pub fn fact(
    id: &str,
    subject: &str,
    evidence: &str,
    availability: AvailabilityV1,
    impact: ImpactV1,
) -> SourceFactV1 {
    SourceFactV1 {
        schema: SOURCE_FACT_SCHEMA_V1.to_owned(),
        fact_id: id.to_owned(),
        subject_key: subject.to_owned(),
        owner: "synthetic-fixture".to_owned(),
        native_schema: "synthetic.status_fact.v1".to_owned(),
        native_record_id: format!("native.{id}"),
        class: SourceFactClassV1::DerivedAdmitted,
        evidence_id: evidence.to_owned(),
        availability,
        impact,
        reason_code: "qualified-state".to_owned(),
        basis_digest: DIGEST_A.to_owned(),
        observed_at_unix_ms: Some(1_900_000_000_000),
    }
}

pub fn live_support(
    evidence: &str,
    remaining_ms: u64,
    elapsed_ms: u64,
) -> LiveSupportObservationV1 {
    try_live_support(evidence, remaining_ms, elapsed_ms)
        .expect("valid synthetic live-support exchange")
}

pub fn try_live_support(
    evidence: &str,
    remaining_ms: u64,
    elapsed_ms: u64,
) -> Result<LiveSupportObservationV1, constellation_status_projection::ProjectionError> {
    let context = support_context();
    let consumer = support_consumer();
    let subject_scope = support_subject_scope();
    let qualified_generation = support_binding(&context, &consumer, &subject_scope);
    let measured_at = 10_000;
    let mut certificate = RelianceSupportCertificateV1 {
        schema_version: SCHEMA_VERSION_V1,
        certificate_id: SupportCertificateId::new("pending"),
        consumer: consumer.clone(),
        subject_scope: subject_scope.clone(),
        context: context.clone(),
        qualified_generation: Some(qualified_generation.clone()),
        evaluated_at_monotonic_ms: measured_at,
        receiver_clock_id: "clock:status-projection".to_owned(),
        judgment: JudgmentCategoryV1::Current,
        evidence_window_id: EvidenceWindowId::new("window:status-projection"),
        supporting_evidence_ids: vec![evidence.to_owned()],
        remote_observation_custody: Vec::new(),
        missing_premises: Vec::new(),
        applicable_contradictions: Vec::new(),
        coverage: CoverageSummaryV1 {
            required: vec!["service".to_owned()],
            active: vec!["service".to_owned()],
            missing: Vec::new(),
            expired: Vec::new(),
            active_observers: 1,
            required_observers: 1,
            per_tag: Vec::new(),
        },
        earliest_support_expiry_monotonic_ms: Some(measured_at + remaining_ms + 1),
        next_scheduled_reevaluation_monotonic_ms: Some(measured_at + remaining_ms + 1),
        escalation: EscalationStateV1::NotRequested,
        mutation_authority: pulse_types::MutationAuthorityV1::None,
    };
    certificate.certificate_id = certificate.compute_id();
    let request = LivePresentSupportRequestV1 {
        schema: LIVE_PRESENT_SUPPORT_REQUEST_SCHEMA_V1.to_owned(),
        request_nonce: LivePresentSupportNonce::new(format!("nonce:{evidence}")),
        consumer,
        subject_scope,
        reliance_context_digest: context.identity_digest(),
        reliance_context: context,
        support_certificate_id: certificate.certificate_id.clone(),
        evidence_window_id: certificate.evidence_window_id.clone(),
        qualified_generation_digest: qualified_generation.identity_digest(),
        receiver: ReceiverId::new("receiver:status-projection"),
        receiver_incarnation: IncarnationId::new("receiver-incarnation:status-projection"),
        receiver_epoch_id: IncarnationId::new("receiver-epoch:status-projection"),
        receiver_clock_id: ClockId::new("clock:status-projection"),
    };
    let anchor = LiveQueryAnchorV1::begin(&request)?;
    let response = LivePresentSupportResponseV1::new(
        request.clone(),
        request.receiver.clone(),
        request.receiver_incarnation.clone(),
        request.receiver_epoch_id.clone(),
        request.receiver_clock_id.clone(),
        "std::time::Instant/process-local".to_owned(),
        measured_at,
        LivePresentSupportDispositionV1::SupportedCurrent,
        Some(remaining_ms),
    );
    if elapsed_ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(elapsed_ms));
    }
    anchor.admit(&request, &response, &certificate, evidence, 120_000)
}

fn support_context() -> RelianceContextV1 {
    RelianceContextV1 {
        schema_version: SCHEMA_VERSION_V1,
        activation_id: ContextActivationId::new("activation:status-projection"),
        reliance_policy_generation: PolicyGenerationId::new("policy:status-projection"),
        reliance_policy_semantic_digest: digest_parts("policy", &[b"status-projection"]),
        consumer_profile_generation: ConsumerProfileGenerationId::new("profile:status-projection"),
        evaluator_semantic_generation: EvaluatorSemanticGenerationId::new(
            "evaluator:status-projection",
        ),
        observer_set_generation: ObserverSetGenerationId::new("observers:status-projection"),
        observation_policy_generation: ObservationPolicyGenerationId::new(
            "observation-policy:status-projection",
        ),
    }
}

fn support_consumer() -> ConsumerId {
    ConsumerId::new("consumer:status-projector")
}

fn support_subject_scope() -> SubjectScopeV1 {
    SubjectScopeV1 {
        subject: SubjectId::new("subject:synthetic-service"),
        subject_incarnation: IncarnationId::new("subject-incarnation:synthetic-1"),
        scope: "status-projection".to_owned(),
    }
}

fn support_binding(
    context: &RelianceContextV1,
    consumer: &ConsumerId,
    subject_scope: &SubjectScopeV1,
) -> QualifiedGenerationBindingV1 {
    QualifiedGenerationBindingV1 {
        schema_version: SCHEMA_VERSION_V1,
        manifest_digest: digest_parts("manifest", &[b"status-projection"]),
        qualification_certificate_digest: digest_parts("qualification", &[b"status-projection"]),
        activation_receipt_digest: digest_parts("activation", &[b"status-projection"]),
        activation_occurrence_id: IncarnationId::new("activation-occurrence:status-projection"),
        process_epoch_id: IncarnationId::new("process-epoch:status-projection"),
        generation_set: QualifiedGenerationSetV1::from_context(
            subject_scope.subject.clone(),
            consumer.clone(),
            context,
        ),
        authority_grants: AuthorityGrantsV1::none(),
    }
}
