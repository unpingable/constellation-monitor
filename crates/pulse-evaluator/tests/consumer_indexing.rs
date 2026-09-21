use std::collections::BTreeMap;

use pulse_evaluator::{Evaluator, ReceiverTracker, ReliancePolicyV1};
use pulse_types::{
    AuthenticationFieldV1, AuthenticationResultV1, BoundedSignalValueV1, ClockId, ConsumerId,
    CoverageDescriptorV1, IncarnationId, JudgmentCategoryV1, MutationAuthorityV1,
    ObservationPolicyGenerationId, ObservationProfileIdV1, ObserverId, PolicyGenerationId,
    PulseFrameV1, ReceivedPulseV1, ReceiverId, SCHEMA_VERSION_V1, SequenceContinuityDimensionV1,
    SignalAssessmentV1, SubjectId, TransportDimensionV1, digest_parts,
};

fn profile() -> ObservationProfileIdV1 {
    ObservationProfileIdV1 {
        name: "profile:consumer-indexing".to_owned(),
        version: 1,
        semantic_digest: digest_parts("profile.v1", &[b"load", b"memory"]),
    }
}

fn policy(consumer: &str, generation: &str, minimum_observers: u32) -> ReliancePolicyV1 {
    ReliancePolicyV1 {
        schema_version: SCHEMA_VERSION_V1,
        subject: SubjectId::new("subject:consumer-indexing"),
        scope: "host".to_owned(),
        consumer: ConsumerId::new(consumer),
        generation: PolicyGenerationId::new(generation),
        observation_policy_generation: ObservationPolicyGenerationId::new("policy:display-v1"),
        observation_profile: profile(),
        required_coverage: vec!["load".to_owned(), "memory".to_owned()],
        minimum_observers,
        maximum_validity_ms: 100,
        require_verified_authentication: false,
        coherence_tolerances: BTreeMap::new(),
        observer_failure_domains: BTreeMap::new(),
        escalation: None,
    }
}

fn frame() -> PulseFrameV1 {
    PulseFrameV1 {
        schema_version: SCHEMA_VERSION_V1,
        subject: SubjectId::new("subject:consumer-indexing"),
        subject_incarnation: IncarnationId::new("subject-incarnation:one"),
        observer: ObserverId::new("observer:one"),
        observer_incarnation: IncarnationId::new("observer-incarnation:one"),
        sequence: 1,
        observer_monotonic_ns: 0,
        validity_ms: 100,
        profile: profile(),
        observation_policy_generation: ObservationPolicyGenerationId::new("policy:display-v1"),
        coverage: CoverageDescriptorV1 {
            expected: vec!["load".to_owned(), "memory".to_owned()],
            observed: vec!["load".to_owned(), "memory".to_owned()],
        },
        signals: vec![
            BoundedSignalValueV1 {
                name: "load_ratio".to_owned(),
                value: 0.2,
                unit: "ratio".to_owned(),
                assessment: SignalAssessmentV1::WithinDeclaredBound,
            },
            BoundedSignalValueV1 {
                name: "memory_ratio".to_owned(),
                value: 0.4,
                unit: "ratio".to_owned(),
                assessment: SignalAssessmentV1::WithinDeclaredBound,
            },
        ],
        observation_digest: digest_parts("placeholder", &[]),
        authentication: AuthenticationFieldV1::Placeholder {
            disclosure: "test-only unauthenticated occurrence".to_owned(),
        },
    }
    .seal()
}

#[test]
fn identical_observation_can_support_different_consumer_judgments() {
    let receiver_id = ReceiverId::new("receiver:consumer-indexing");
    let receiver_incarnation = IncarnationId::new("receiver-incarnation:one");
    let clock_id = ClockId::new("clock:one");
    let subject_incarnation = IncarnationId::new("subject-incarnation:one");
    let mut tracker = ReceiverTracker::new(
        receiver_id.clone(),
        receiver_incarnation.clone(),
        clock_id.clone(),
    );
    let frame = frame();
    let annotation = tracker
        .annotate(
            &frame,
            0,
            "test-loopback",
            Some(0),
            AuthenticationResultV1::Unauthenticated {
                disclosure: "test placeholder".to_owned(),
            },
        )
        .expect("valid frame is annotated");
    let evidence = ReceivedPulseV1 {
        frame,
        receiver: annotation,
    };

    let mut display = Evaluator::new(
        policy("consumer:capacity-display/v1", "policy:display-v1", 1),
        receiver_id.clone(),
        receiver_incarnation.clone(),
        clock_id.clone(),
        subject_incarnation.clone(),
    )
    .expect("display policy is valid");
    let mut destructive_preflight = Evaluator::new(
        policy(
            "consumer:destructive-automation-preflight/v1",
            "policy:display-v1",
            2,
        ),
        receiver_id,
        receiver_incarnation,
        clock_id,
        subject_incarnation,
    )
    .expect("preflight policy is valid");

    let display_judgment = display
        .ingest(evidence.clone(), 17)
        .expect("display evaluation succeeds")
        .judgment;
    let preflight_judgment = destructive_preflight
        .ingest(evidence, 17)
        .expect("preflight evaluation succeeds")
        .judgment;

    assert_eq!(display_judgment.category, JudgmentCategoryV1::Current);
    assert_eq!(
        display_judgment.positive_support_expires_at_monotonic_ms,
        Some(100)
    );
    assert_eq!(
        display_judgment.dimensions.sequence_continuity,
        SequenceContinuityDimensionV1::FirstSeen
    );
    assert_eq!(preflight_judgment.category, JudgmentCategoryV1::Unknown);
    assert_eq!(
        preflight_judgment.positive_support_expires_at_monotonic_ms,
        None
    );
    assert_ne!(display_judgment.consumer, preflight_judgment.consumer);
    assert!(
        preflight_judgment
            .coverage
            .missing
            .iter()
            .any(|tag| tag == "load")
    );
    assert_eq!(
        display_judgment.mutation_authority,
        MutationAuthorityV1::None
    );
    assert_eq!(
        preflight_judgment.mutation_authority,
        MutationAuthorityV1::None
    );
    assert_eq!(display.metrics().pulse_to_evaluation_latency_ms, 17);
    assert_eq!(
        destructive_preflight
            .metrics()
            .pulse_to_evaluation_latency_ms,
        17
    );

    let regressed = display
        .tick(16)
        .expect("clock regression produces a cautious judgment");
    assert_eq!(regressed.judgment.category, JudgmentCategoryV1::Unknown);
    assert_eq!(
        regressed.judgment.dimensions.transport,
        TransportDimensionV1::Blind
    );
    assert_eq!(regressed.judgment.evaluated_at_monotonic_ms, 17);
}
